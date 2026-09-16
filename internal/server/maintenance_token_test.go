package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type maintenanceTestGrant struct {
	TokenID      string   `json:"tokenId"`
	TokenHash    string   `json:"tokenHash"`
	Subject      string   `json:"subject"`
	Generation   uint64   `json:"generation"`
	Capabilities []string `json:"capabilities"`
	Revoked      bool     `json:"revoked"`
}

type maintenanceTestStatus struct {
	DeviceID     string   `json:"deviceId"`
	TokenID      string   `json:"tokenId"`
	Subject      string   `json:"subject"`
	Generation   uint64   `json:"generation"`
	Capabilities []string `json:"capabilities"`
	Revoked      bool     `json:"revoked"`
	Persisted    bool     `json:"persisted"`
}

func maintenanceTestRandom(t *testing.T) (string, maintenanceTestGrant) {
	t.Helper()
	var secret [32]byte
	var id [16]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	token := "fdpat_" + base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(token))
	return token, maintenanceTestGrant{
		TokenID:   fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]),
		TokenHash: hex.EncodeToString(hash[:]), Subject: "feidu-user:42", Generation: 1,
		Capabilities: []string{"desktop", "files", "peripherals", "ssh", "terminal"},
	}
}

func maintenanceTestServer(t *testing.T, registryPath string) *Server {
	t.Helper()
	s := NewServer()
	s.ControlToken = "maintenance-test-control"
	if err := s.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	return s
}

func maintenanceTestDevice(t *testing.T, s *Server, name string) string {
	t.Helper()
	return redeemEnrollmentForTest(t, s,
		createEnrollmentForTest(t, s, "feidu-user:42", 600).Code, name).DeviceID
}

func maintenanceTestRequest(t *testing.T, s *Server, method, deviceID string, payload any, control string) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, "/api/control/devices/"+url.PathEscape(deviceID)+"/maintenance-token", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", control)
	response := httptest.NewRecorder()
	s.HandleManagedDeviceLifecycleAPI(response, request)
	return response
}

func maintenanceTestInstall(t *testing.T, s *Server, deviceID string, grant maintenanceTestGrant) maintenanceTestStatus {
	t.Helper()
	response := maintenanceTestRequest(t, s, http.MethodPut, deviceID, grant, s.ControlToken)
	if response.Code != http.StatusOK {
		t.Fatalf("install status = %d, body = %s", response.Code, response.Body.String())
	}
	return maintenanceTestReadStatus(t, response)
}

func maintenanceTestReadStatus(t *testing.T, response *httptest.ResponseRecorder) maintenanceTestStatus {
	t.Helper()
	var status maintenanceTestStatus
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Persisted {
		t.Fatal("success was acknowledged without persisted:true")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"token", "tokenHash", "token_hash", "credential"} {
		if _, exists := fields[key]; exists {
			t.Fatalf("control status disclosed credential field %q", key)
		}
	}
	return status
}

func TestMaintenanceTokenOfflineInstallRestartAndDurableTombstone(t *testing.T) {
	registry := filepath.Join(t.TempDir(), "managed_devices.json")
	s := maintenanceTestServer(t, registry)
	deviceID := maintenanceTestDevice(t, s, "offline-workstation")
	token, grant := maintenanceTestRandom(t)
	status := maintenanceTestInstall(t, s, deviceID, grant)
	if status.DeviceID != deviceID || status.TokenID != grant.TokenID || status.Subject != grant.Subject || status.Generation != 1 || status.Revoked || !reflect.DeepEqual(status.Capabilities, grant.Capabilities) {
		t.Fatalf("incorrect installed status: %+v", status)
	}
	data, err := os.ReadFile(registry)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(token)) {
		t.Fatal("registry persisted the plaintext token")
	}
	restarted := maintenanceTestServer(t, registry)
	// A fixed credential must survive the old 24-hour deadline and a new process.
	restarted.accessTicketNow = func() time.Time { return time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC) }
	client := &ClientConn{ID: deviceID, InstanceID: "after-restart", Password: "changed-device-password"}
	restarted.clients[deviceID] = client
	if !restarted.authorizeDeviceCredential(client, token) {
		t.Fatal("fixed token did not survive server restart and old ticket deadline")
	}
	response := maintenanceTestRequest(t, restarted, http.MethodGet, deviceID, nil, restarted.ControlToken)
	if response.Code != http.StatusOK || maintenanceTestReadStatus(t, response).TokenID != grant.TokenID {
		t.Fatal("GET did not return persisted authorization")
	}
	grant.Generation++
	grant.Revoked = true
	maintenanceTestInstall(t, restarted, deviceID, grant)
	if restarted.authorizeDeviceCredential(client, token) {
		t.Fatal("revoked fixed token remained valid")
	}
	third := maintenanceTestServer(t, registry)
	third.clients[deviceID] = client
	response = maintenanceTestRequest(t, third, http.MethodGet, deviceID, nil, third.ControlToken)
	if response.Code != http.StatusOK {
		t.Fatalf("tombstone GET status = %d", response.Code)
	}
	if status := maintenanceTestReadStatus(t, response); !status.Revoked || status.Generation != 2 {
		t.Fatalf("revocation tombstone was not durable: %+v", status)
	}
	grant.Generation = 1
	grant.Revoked = false
	if response = maintenanceTestRequest(t, third, http.MethodPut, deviceID, grant, third.ControlToken); response.Code != http.StatusConflict {
		t.Fatalf("pre-revocation replay status = %d, want 409", response.Code)
	}
	if third.authorizeDeviceCredential(client, token) {
		t.Fatal("stale replay restored a revoked token")
	}
}

func TestMaintenanceTokenIdempotenceReplayAndDeviceIsolation(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	deviceID := maintenanceTestDevice(t, s, "first")
	otherID := maintenanceTestDevice(t, s, "second")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, deviceID, grant)
	maintenanceTestInstall(t, s, deviceID, grant)
	reordered := grant
	reordered.Capabilities = []string{"ssh", "terminal", "files", "desktop", "peripherals"}
	maintenanceTestInstall(t, s, deviceID, reordered)
	grant.Generation = 3
	maintenanceTestInstall(t, s, deviceID, grant)
	for _, changed := range []maintenanceTestGrant{
		{TokenID: grant.TokenID, TokenHash: grant.TokenHash, Subject: grant.Subject, Generation: 2, Capabilities: grant.Capabilities},
		{TokenID: grant.TokenID, TokenHash: grant.TokenHash, Subject: grant.Subject, Generation: 3, Capabilities: []string{"files"}},
		{TokenID: grant.TokenID, TokenHash: grant.TokenHash, Subject: grant.Subject, Generation: 3, Capabilities: grant.Capabilities, Revoked: true},
	} {
		if response := maintenanceTestRequest(t, s, http.MethodPut, deviceID, changed, s.ControlToken); response.Code != http.StatusConflict {
			t.Fatalf("conflicting generation status = %d, want 409", response.Code)
		}
	}
	if s.authorizeDeviceCredential(&ClientConn{ID: otherID, InstanceID: "other"}, token) {
		t.Fatal("token authenticated another device")
	}
	if response := maintenanceTestRequest(t, s, http.MethodPut, otherID, grant, s.ControlToken); response.Code != http.StatusConflict {
		t.Fatalf("same token bound to another device: status %d, want 409", response.Code)
	}
	wrongOwner := grant
	wrongOwner.Subject = "feidu-user:43"
	wrongOwner.Generation++
	if response := maintenanceTestRequest(t, s, http.MethodPut, deviceID, wrongOwner, s.ControlToken); response.Code < 400 || response.Code >= 500 {
		t.Fatalf("cross-owner update status = %d, want 4xx", response.Code)
	}
	if !s.authorizeDeviceCredential(&ClientConn{ID: deviceID, InstanceID: "original"}, token) {
		t.Fatal("rejected changes invalidated the existing token")
	}
}

func TestMaintenanceTokenControlAuthenticationAndStrictInput(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	deviceID := maintenanceTestDevice(t, s, "validation")
	_, grant := maintenanceTestRandom(t)
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		for _, control := range []string{"", "wrong-control"} {
			if response := maintenanceTestRequest(t, s, method, deviceID, grant, control); response.Code != http.StatusUnauthorized {
				t.Fatalf("unauthorized %s status = %d, want 401", method, response.Code)
			}
		}
	}
	for _, id := range []string{deviceID, "unknown-device"} {
		if response := maintenanceTestRequest(t, s, http.MethodGet, id, nil, s.ControlToken); response.Code != http.StatusNotFound {
			t.Fatalf("unbound GET status = %d, want 404", response.Code)
		}
	}
	data, _ := json.Marshal(grant)
	var valid map[string]any
	if err := json.Unmarshal(data, &valid); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		key   string
		value any
	}{
		{"invalid token ID", "tokenId", "not-a-uuid"},
		{"uppercase digest", "tokenHash", strings.ToUpper(grant.TokenHash)},
		{"short digest", "tokenHash", "abcd"},
		{"invalid subject", "subject", "feidu-browser:42"},
		{"zero generation", "generation", 0},
		{"unknown capability", "capabilities", []string{"can_manage"}},
		{"unknown field", "expiresAt", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := make(map[string]any, len(valid)+1)
			for k, v := range valid {
				body[k] = v
			}
			body[test.key] = test.value
			if response := maintenanceTestRequest(t, s, http.MethodPut, deviceID, body, s.ControlToken); response.Code != http.StatusBadRequest {
				t.Fatalf("invalid PUT status = %d, want 400", response.Code)
			}
		})
	}
	maintenanceTestInstall(t, s, deviceID, grant)
}

func TestMaintenanceTokenRejectsQueryCredentialAndRequiresDesktopScope(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	deviceID := maintenanceTestDevice(t, s, "desktop-transport")
	client := &ClientConn{ID: deviceID, InstanceID: "desktop-instance"}
	token, grant := maintenanceTestRandom(t)
	grant.Capabilities = []string{"desktop"}
	maintenanceTestInstall(t, s, deviceID, grant)
	request := httptest.NewRequest(http.MethodGet, "/gpu-desktop/"+deviceID+"?password="+url.QueryEscape(token), nil)
	if s.authorizeBrowserDeviceRequest(client, request) {
		t.Fatal("permanent token was accepted in a URL query")
	}
	request = httptest.NewRequest(http.MethodGet, "/gpu-desktop/"+deviceID, nil)
	request.Header.Set("X-RDev-Device-Credential", token)
	if !s.authorizeBrowserDeviceRequest(client, request) {
		t.Fatal("desktop-scoped header credential was rejected")
	}
	grant.Generation++
	grant.Capabilities = []string{"ssh"}
	maintenanceTestInstall(t, s, deviceID, grant)
	if s.authorizeBrowserDeviceRequest(client, request) {
		t.Fatal("SSH-only token accessed the desktop endpoint")
	}
}

func TestMaintenanceTokenSSHReconnectCapabilityUpdateAndReset(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	deviceID := maintenanceTestDevice(t, s, "reconnect")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, deviceID, grant)
	first := &ClientConn{ID: deviceID, InstanceID: "first", Password: "first-password"}
	s.clients[deviceID] = first
	sshServer := &SSHServer{srv: s}
	ctx := newSSHAuthTestContext(deviceID)
	if !sshServer.handlePassword(ctx, token) {
		t.Fatal("fixed token SSH authentication failed")
	}
	if _, ok := s.authorizedSSHClient(ctx); !ok {
		t.Fatal("fresh fixed-token SSH context rejected")
	}
	second := &ClientConn{ID: deviceID, InstanceID: "second", Password: "new-password"}
	s.clients[deviceID] = second
	if _, ok := s.authorizedSSHClient(ctx); ok {
		t.Fatal("old connection survived instance replacement")
	}
	ctx = newSSHAuthTestContext(deviceID)
	if !sshServer.handlePassword(ctx, token) {
		t.Fatal("same fixed token failed after device reconnect")
	}
	grant.Generation++
	grant.Capabilities = []string{"files"}
	maintenanceTestInstall(t, s, deviceID, grant)
	if _, ok := s.authorizedSSHClient(ctx); ok {
		t.Fatal("capability removal left established SSH authorization valid")
	}
	if sshServer.handlePassword(newSSHAuthTestContext(deviceID), token) {
		t.Fatal("files-only token authenticated SSH")
	}
	if _, ok := s.authorizeBrowserDeviceCredentialBinding(second, token, browserCapabilityFiles); !ok {
		t.Fatal("capability update removed allowed file access")
	}
	if _, ok := s.authorizeBrowserDeviceCredentialBinding(second, token, browserCapabilityTerminal); ok {
		t.Fatal("files-only token authenticated terminal")
	}
	newToken, reset := maintenanceTestRandom(t)
	reset.Generation = grant.Generation + 1
	maintenanceTestInstall(t, s, deviceID, reset)
	if s.authorizeDeviceCredential(second, token) {
		t.Fatal("old credential survived explicit token reset")
	}
	if !s.authorizeDeviceCredential(second, newToken) {
		t.Fatal("reset token was not usable")
	}
}

func TestMaintenanceTokenPersistenceFailureDoesNotAcknowledgeOrChangeGrant(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "registry")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	s := maintenanceTestServer(t, filepath.Join(parent, "managed.json"))
	deviceID := maintenanceTestDevice(t, s, "durability")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, deviceID, grant)
	if err := os.Rename(parent, parent+"-saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(parent, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	grant.Generation++
	grant.Revoked = true
	response := maintenanceTestRequest(t, s, http.MethodPut, deviceID, grant, s.ControlToken)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("persistence failure status = %d, want 500", response.Code)
	}
	if !s.authorizeDeviceCredential(&ClientConn{ID: deviceID, InstanceID: "live"}, token) {
		t.Fatal("failed durable update still changed in-memory authorization")
	}
	response = maintenanceTestRequest(t, s, http.MethodGet, deviceID, nil, s.ControlToken)
	if response.Code != http.StatusOK {
		t.Fatalf("GET status after failed update = %d", response.Code)
	}
	if status := maintenanceTestReadStatus(t, response); status.Generation != 1 || status.Revoked {
		t.Fatalf("failed update changed acknowledged state: %+v", status)
	}
}
