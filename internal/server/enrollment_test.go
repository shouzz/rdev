package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEnrollmentCreatesOneTimeManagedDeviceCredential(t *testing.T) {
	now := time.Date(2026, 9, 3, 8, 0, 0, 987654321, time.UTC)
	registryPath := filepath.Join(t.TempDir(), "managed_devices.json")
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}

	createBody := []byte(`{"subject":"feidu-user:42","expiresInSeconds":600}`)
	createRequest := httptest.NewRequest(http.MethodPost, "/api/control/enrollments", bytes.NewReader(createBody))
	createRequest.Header.Set("X-RDev-Control-Token", s.ControlToken)
	createResponse := httptest.NewRecorder()
	s.HandleEnrollmentCreateAPI(createResponse, createRequest)
	if createResponse.Code != http.StatusOK {
		t.Fatalf("create status = %d, body = %q", createResponse.Code, createResponse.Body.String())
	}
	var created enrollmentCreateResponse
	if err := json.Unmarshal(createResponse.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !validEnrollmentCode(created.Code) {
		t.Fatal("creation returned an invalid enrollment code")
	}
	if created.JoinURL != "https://rdev.example.com/join#"+created.Code {
		t.Fatalf("join URL = %q", created.JoinURL)
	}
	if created.ExpiresAtMs != now.Add(10*time.Minute).UTC().Truncate(time.Second).UnixMilli() {
		t.Fatalf("expiresAtMs = %d", created.ExpiresAtMs)
	}

	redeemBody, _ := json.Marshal(enrollmentRedeemRequest{Code: created.Code, DeviceID: "workstation-01"})
	redeemRequest := httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(redeemBody))
	redeemResponse := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(redeemResponse, redeemRequest)
	if redeemResponse.Code != http.StatusOK {
		t.Fatalf("redeem status = %d, body = %q", redeemResponse.Code, redeemResponse.Body.String())
	}
	var redeemed enrollmentRedeemResponse
	if err := json.Unmarshal(redeemResponse.Body.Bytes(), &redeemed); err != nil {
		t.Fatal(err)
	}
	if redeemed.DeviceID != "workstation-01" || !strings.HasPrefix(redeemed.DeviceSecret, deviceSecretPrefix) || redeemed.ServerURL != "https://rdev.example.com" {
		t.Fatal("redemption returned invalid managed device fields")
	}
	if allowed, managed := s.authorizeManagedRegistration(redeemed.DeviceID, redeemed.DeviceSecret); !managed || !allowed {
		t.Fatal("managed device secret was not accepted")
	}
	if allowed, managed := s.authorizeManagedRegistration(redeemed.DeviceID, "wrong"); !managed || allowed {
		t.Fatal("wrong managed device secret was accepted")
	}

	replayRequest := httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(redeemBody))
	replayResponse := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", replayResponse.Code)
	}

	registryBytes, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(registryBytes, []byte(redeemed.DeviceSecret)) || bytes.Contains(registryBytes, []byte(created.Code)) {
		t.Fatal("registry persisted a plaintext enrollment or device secret")
	}
	if !bytes.Contains(registryBytes, []byte(`"owner_subject": "feidu-user:42"`)) ||
		!bytes.Contains(registryBytes, []byte(`"secret_hash": "$2`)) {
		t.Fatal("registry does not contain the owner and slow device-secret hash")
	}

	reloaded := NewServer()
	if err = reloaded.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	if allowed, managed := reloaded.authorizeManagedRegistration(redeemed.DeviceID, redeemed.DeviceSecret); !managed || !allowed {
		t.Fatal("reloaded registry rejected the managed device secret")
	}
}

func TestEnrollmentExpiryAndStrictJSON(t *testing.T) {
	now := time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(filepath.Join(t.TempDir(), "managed_devices.json"), "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}

	badRequest := httptest.NewRequest(http.MethodPost, "/api/control/enrollments", strings.NewReader(`{"subject":"operator","expiresInSeconds":600,"extra":true}`))
	badRequest.Header.Set("X-RDev-Control-Token", s.ControlToken)
	badResponse := httptest.NewRecorder()
	s.HandleEnrollmentCreateAPI(badResponse, badRequest)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d, want 400", badResponse.Code)
	}

	created := createEnrollmentForTest(t, s, "operator", 60)
	now = now.Add(time.Minute)
	body, _ := json.Marshal(enrollmentRedeemRequest{Code: created.Code, DeviceID: "expired-device"})
	response := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(response, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired redemption status = %d, want 401", response.Code)
	}
}

func TestEnrollmentCreateRequiresControlCredential(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	if err := s.ConfigureEnrollmentStore(filepath.Join(t.TempDir(), "managed_devices.json"), "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.HandleEnrollmentCreateAPI(response, httptest.NewRequest(http.MethodPost, "/api/control/enrollments", strings.NewReader(`{"subject":"operator","expiresInSeconds":600}`)))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestEnrollmentCreateRejectsDisabledControlCredential(t *testing.T) {
	s := NewServer()
	if err := s.ConfigureEnrollmentStore(filepath.Join(t.TempDir(), "managed_devices.json"), "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.HandleEnrollmentCreateAPI(response, httptest.NewRequest(http.MethodPost, "/api/control/enrollments", strings.NewReader(`{"subject":"operator","expiresInSeconds":600}`)))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
}

func TestEnrollmentLifecycleQueryRevokeAndRestart(t *testing.T) {
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	registryPath := filepath.Join(t.TempDir(), "managed_devices.json")
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	created := createEnrollmentForTest(t, s, "feidu-user:7", 600)

	status := getEnrollmentStatusForTest(t, s, created.EnrollmentID)
	if status.State != "active" || status.Subject != "feidu-user:7" || status.IssuedDeviceID != "" {
		t.Fatalf("active status = %#v", status)
	}
	statusJSON, _ := json.Marshal(status)
	if bytes.Contains(statusJSON, []byte(created.Code)) || bytes.Contains(statusJSON, []byte("codeHash")) {
		t.Fatal("status response exposed enrollment credentials")
	}

	revokeRequest := httptest.NewRequest(http.MethodDelete, "/api/control/enrollments/"+created.EnrollmentID, nil)
	revokeRequest.Header.Set("X-RDev-Control-Token", s.ControlToken)
	revokeResponse := httptest.NewRecorder()
	s.HandleEnrollmentLifecycleAPI(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, body = %q", revokeResponse.Code, revokeResponse.Body.String())
	}
	if got := getEnrollmentStatusForTest(t, s, created.EnrollmentID); got.State != "revoked" || got.RevokedAt == "" {
		t.Fatalf("revoked status = %#v", got)
	}

	redeemBody, _ := json.Marshal(enrollmentRedeemRequest{Code: created.Code, DeviceID: "revoked-invite"})
	redeemResponse := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(redeemResponse, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(redeemBody)))
	if redeemResponse.Code != http.StatusUnauthorized {
		t.Fatalf("revoked invite redemption status = %d, want 401", redeemResponse.Code)
	}

	reloaded := NewServer()
	reloaded.ControlToken = s.ControlToken
	reloaded.enrollmentNow = func() time.Time { return now }
	if err := reloaded.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := getEnrollmentStatusForTest(t, reloaded, created.EnrollmentID); got.State != "revoked" || got.RevokedAt == "" {
		t.Fatalf("reloaded revoked status = %#v", got)
	}
}

func TestEnrollmentConcurrentRedemptionIsSingleUse(t *testing.T) {
	now := time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC)
	registryPath := filepath.Join(t.TempDir(), "managed_devices.json")
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	created := createEnrollmentForTest(t, s, "feidu-user:8", 600)

	const attempts = 8
	statuses := make(chan int, attempts)
	var wait sync.WaitGroup
	for index := 0; index < attempts; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			body, _ := json.Marshal(enrollmentRedeemRequest{Code: created.Code, DeviceID: "parallel-device"})
			response := httptest.NewRecorder()
			s.HandleEnrollmentRedeemAPI(response, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
			statuses <- response.Code
		}(index)
	}
	wait.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		} else if status != http.StatusUnauthorized {
			t.Fatalf("concurrent redemption status = %d", status)
		}
	}
	if successes != 1 {
		t.Fatalf("successful concurrent redemptions = %d, want 1", successes)
	}
	if len(s.managedDevices) != 1 {
		t.Fatalf("managed devices = %d, want 1", len(s.managedDevices))
	}

	reloaded := NewServer()
	reloaded.ControlToken = s.ControlToken
	reloaded.enrollmentNow = func() time.Time { return now }
	if err := reloaded.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.managedDevices) != 1 {
		t.Fatalf("reloaded managed devices = %d, want 1", len(reloaded.managedDevices))
	}
	status := getEnrollmentStatusForTest(t, reloaded, created.EnrollmentID)
	if status.State != "consumed" || status.ConsumedAt == "" || status.IssuedDeviceID == "" {
		t.Fatalf("reloaded consumed status = %#v", status)
	}
}

func TestManagedDeviceRotateRevokeAndRestart(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	registryPath := filepath.Join(t.TempDir(), "managed_devices.json")
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	created := createEnrollmentForTest(t, s, "feidu-user:9", 600)
	redeemed := redeemEnrollmentForTest(t, s, created.Code, "managed-workstation")
	transport := &enrollmentTestTransport{closed: make(chan string, 1)}
	s.mu.Lock()
	s.clients[redeemed.DeviceID] = &ClientConn{
		ID: redeemed.DeviceID, RequestedID: redeemed.DeviceID, InstanceID: "connected-instance", Transport: transport,
	}
	s.mu.Unlock()
	ticketHash := sha256.Sum256([]byte("temporary-access-ticket"))
	s.accessTicketMu.Lock()
	s.accessTickets[ticketHash] = accessTicket{DeviceID: redeemed.DeviceID, InstanceID: "connected-instance", ExpiresAt: now.Add(time.Hour)}
	s.accessTicketMu.Unlock()

	now = now.Add(time.Minute)
	rotateRequest := httptest.NewRequest(http.MethodPost, "/api/control/devices/managed-workstation/rotate-secret", nil)
	rotateRequest.Header.Set("X-RDev-Control-Token", s.ControlToken)
	rotateResponse := httptest.NewRecorder()
	s.HandleManagedDeviceLifecycleAPI(rotateResponse, rotateRequest)
	if rotateResponse.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, body = %q", rotateResponse.Code, rotateResponse.Body.String())
	}
	var rotated deviceSecretRotateResponse
	if err := json.Unmarshal(rotateResponse.Body.Bytes(), &rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.DeviceID != redeemed.DeviceID || rotated.DeviceSecret == "" || rotated.DeviceSecret == redeemed.DeviceSecret {
		t.Fatal("rotation did not return a new device secret")
	}
	if allowed, managed := s.authorizeManagedRegistration(redeemed.DeviceID, redeemed.DeviceSecret); !managed || allowed {
		t.Fatal("old device secret remained valid after rotation")
	}
	if allowed, managed := s.authorizeManagedRegistration(redeemed.DeviceID, rotated.DeviceSecret); !managed || !allowed {
		t.Fatal("rotated device secret was rejected")
	}
	select {
	case reason := <-transport.closed:
		if reason != "device secret rotated" {
			t.Fatalf("device close reason = %q", reason)
		}
	default:
		t.Fatal("rotated device connection was not closed")
	}
	s.accessTicketMu.Lock()
	remainingTickets := len(s.accessTickets)
	s.accessTicketMu.Unlock()
	if remainingTickets != 0 {
		t.Fatalf("access tickets after rotation = %d, want 0", remainingTickets)
	}
	registryBytes, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(registryBytes, []byte(redeemed.DeviceSecret)) || bytes.Contains(registryBytes, []byte(rotated.DeviceSecret)) {
		t.Fatal("registry persisted a plaintext device secret")
	}

	reloaded := NewServer()
	reloaded.ControlToken = s.ControlToken
	reloaded.enrollmentNow = func() time.Time { return now }
	if err = reloaded.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	if allowed, managed := reloaded.authorizeManagedRegistration(redeemed.DeviceID, rotated.DeviceSecret); !managed || !allowed {
		t.Fatal("reloaded registry rejected rotated device secret")
	}

	now = now.Add(time.Minute)
	revokeRequest := httptest.NewRequest(http.MethodDelete, "/api/control/devices/managed-workstation", nil)
	revokeRequest.Header.Set("X-RDev-Control-Token", reloaded.ControlToken)
	revokeResponse := httptest.NewRecorder()
	reloaded.HandleManagedDeviceLifecycleAPI(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("device revoke status = %d, body = %q", revokeResponse.Code, revokeResponse.Body.String())
	}
	if allowed, managed := reloaded.authorizeManagedRegistration(redeemed.DeviceID, rotated.DeviceSecret); !managed || allowed {
		t.Fatal("revoked device secret remained valid")
	}

	restarted := NewServer()
	if err = restarted.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	if allowed, managed := restarted.authorizeManagedRegistration(redeemed.DeviceID, rotated.DeviceSecret); !managed || allowed {
		t.Fatal("restarted registry accepted a revoked device")
	}
}

func TestEnrollmentLifecycleRequiresControlCredential(t *testing.T) {
	s := NewServer()
	if err := s.ConfigureEnrollmentStore(filepath.Join(t.TempDir(), "managed_devices.json"), "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/control/enrollments/00000000000000000000000000000000", nil),
		httptest.NewRequest(http.MethodDelete, "/api/control/devices/device", nil),
		httptest.NewRequest(http.MethodPost, "/api/control/devices/device/rotate-secret", nil),
	}
	for _, request := range requests {
		response := httptest.NewRecorder()
		if strings.HasPrefix(request.URL.Path, "/api/control/enrollments/") {
			s.HandleEnrollmentLifecycleAPI(response, request)
		} else {
			s.HandleManagedDeviceLifecycleAPI(response, request)
		}
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s %s status = %d, want 503", request.Method, request.URL.Path, response.Code)
		}
	}
}

func createEnrollmentForTest(t *testing.T, s *Server, subject string, lifetimeSeconds int64) enrollmentCreateResponse {
	t.Helper()
	body, _ := json.Marshal(enrollmentCreateRequest{Subject: subject, ExpiresInSecond: lifetimeSeconds})
	request := httptest.NewRequest(http.MethodPost, "/api/control/enrollments", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleEnrollmentCreateAPI(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("create enrollment status = %d, body = %q", response.Code, response.Body.String())
	}
	var result enrollmentCreateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func getEnrollmentStatusForTest(t *testing.T, s *Server, enrollmentID string) enrollmentStatusResponse {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/control/enrollments/"+enrollmentID, nil)
	request.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleEnrollmentLifecycleAPI(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("get enrollment status = %d, body = %q", response.Code, response.Body.String())
	}
	var result enrollmentStatusResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func redeemEnrollmentForTest(t *testing.T, s *Server, code, deviceID string) enrollmentRedeemResponse {
	t.Helper()
	body, _ := json.Marshal(enrollmentRedeemRequest{Code: code, DeviceID: deviceID})
	response := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(response, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("redeem enrollment status = %d, body = %q", response.Code, response.Body.String())
	}
	var result enrollmentRedeemResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

type enrollmentTestTransport struct {
	closed chan string
}

func (t *enrollmentTestTransport) WriteJSON([]byte) error   { return nil }
func (t *enrollmentTestTransport) WriteBinary([]byte) error { return nil }
func (t *enrollmentTestTransport) WritePing([]byte) error   { return nil }
func (t *enrollmentTestTransport) RemoteAddr() string       { return "test" }
func (t *enrollmentTestTransport) Close(reason string) error {
	select {
	case t.closed <- reason:
	default:
	}
	return nil
}
