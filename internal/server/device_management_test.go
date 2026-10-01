package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"rdev/internal/protocol"
)

func managementRequest(s *Server, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/control/devices/"+path, strings.NewReader(body))
	r.Header.Set("X-RDev-Control-Token", s.ControlToken)
	w := httptest.NewRecorder()
	s.HandleManagedDeviceLifecycleAPI(w, r)
	return w
}

func TestDisplayNameDurabilityIdentityAndRollback(t *testing.T) {
	s := NewServer()
	s.ControlToken = "test-control"
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := s.ConfigureEnrollmentStore(path, "https://example.test"); err != nil {
		t.Fatal(err)
	}
	invite := createEnrollmentForTest(t, s, "owner", 0)
	device := redeemEnrollmentForTest(t, s, invite.Code, "exact-device")
	before := s.managedDevices[device.DeviceID]
	w := managementRequest(s, "PATCH", "exact-device/name", `{"subject":"owner","displayName":"机房控制器"}`)
	if w.Code != 200 {
		t.Fatalf("rename: %d %s", w.Code, w.Body)
	}
	after := s.managedDevices[device.DeviceID]
	after.DisplayName, after.UpdatedAt = before.DisplayName, before.UpdatedAt
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rename changed identity or authorization")
	}
	reloaded := NewServer()
	if err := reloaded.ConfigureEnrollmentStore(path, "https://example.test"); err != nil {
		t.Fatal(err)
	}
	if reloaded.displayName(device.DeviceID) != "机房控制器" {
		t.Fatal("display name lost on restart")
	}
	if allowed, _ := reloaded.authorizeManagedRegistration(device.DeviceID, device.DeviceSecret); !allowed {
		t.Fatal("rename changed credential")
	}
	client := &ClientConn{ID: device.DeviceID, InstanceID: "new-process"}
	if reloaded.deviceInfo(client).DisplayName != "机房控制器" {
		t.Fatal("new connection did not expose persisted name")
	}
	s.enrollmentRegistryPath = filepath.Join(path, "not-a-directory")
	w = managementRequest(s, "PATCH", "exact-device/name", `{"subject":"owner","displayName":"replacement"}`)
	if w.Code != 500 || s.displayName(device.DeviceID) != "机房控制器" {
		t.Fatal("failed persistence changed name")
	}
	s.enrollmentRegistryPath = path
	w = managementRequest(s, "PATCH", "exact-device/name", `{"subject":"owner","displayName":""}`)
	if w.Code != 200 || s.displayName(device.DeviceID) != "" {
		t.Fatal("clear name failed")
	}
}

func TestDeviceManagementAuthorizationAndValidation(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		want                     int
	}{
		{"wrong subject", "PATCH", "exact/name", `{"subject":"intruder","displayName":"x"}`, 403},
		{"name is not ID", "PATCH", "alias/name", `{"subject":"owner","displayName":"x"}`, 403},
		{"case sensitive", "PATCH", "Exact/name", `{"subject":"owner","displayName":"x"}`, 403},
		{"space in ID", "PATCH", "%20exact/name", `{"subject":"owner","displayName":"x"}`, 404},
		{"missing name", "PATCH", "exact/name", `{"subject":"owner"}`, 400},
		{"control name", "PATCH", "exact/name", `{"subject":"owner","displayName":"x\n"}`, 400},
		{"unknown field", "PATCH", "exact/name", `{"subject":"owner","displayName":"x","id":"other"}`, 400},
		{"trailing JSON", "PATCH", "exact/name", `{"subject":"owner","displayName":"x"}{}`, 400},
		{"unconfirmed uninstall", "POST", "exact/actions", `{"subject":"owner","instanceId":"one","requestId":"00000000000000000000000000000001","action":"uninstall"}`, 400},
		{"delete on stop", "POST", "exact/actions", `{"subject":"owner","instanceId":"one","requestId":"00000000000000000000000000000001","action":"stop","deleteIdentity":true}`, 400},
		{"wrong instance", "POST", "exact/actions", `{"subject":"owner","instanceId":"old","requestId":"00000000000000000000000000000001","action":"stop"}`, 409},
		{"unknown action", "POST", "exact/actions", `{"subject":"owner","instanceId":"one","requestId":"00000000000000000000000000000001","action":"exec"}`, 400},
		{"wrong method", "DELETE", "exact/actions", `{}`, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewServer()
			s.ControlToken = "test-control"
			s.managedDevices["exact"] = managedDevice{ID: "exact", OwnerSubject: "owner", DisplayName: "alias"}
			w := managementRequest(s, tc.method, tc.path, tc.body)
			if w.Code != tc.want {
				t.Fatalf("status %d want %d: %s", w.Code, tc.want, w.Body)
			}
		})
	}
	for _, path := range []string{"exact/name", "exact/actions"} {
		s := NewServer()
		w := managementRequest(s, "GET", path, "")
		if w.Code != 503 {
			t.Fatalf("disabled control status: %d", w.Code)
		}
		s.ControlToken = "test-control"
		r := httptest.NewRequest("GET", "/api/control/devices/"+path, nil)
		w = httptest.NewRecorder()
		s.HandleManagedDeviceLifecycleAPI(w, r)
		if w.Code != 401 {
			t.Fatalf("unauthenticated status: %d", w.Code)
		}
	}
	if validDisplayName(strings.Repeat("中", 86)) {
		t.Fatal("oversized UTF-8 name allowed")
	}
}

func TestDeviceActionExactDispatchReplayAndResultBinding(t *testing.T) {
	s := NewServer()
	s.ControlToken = "test-control"
	s.managedDevices["exact"] = managedDevice{ID: "exact", OwnerSubject: "owner"}
	transport := &cloudTransferCaptureTransport{}
	c := &ClientConn{ID: "exact", InstanceID: "one", Managed: true, DeviceManagementV1: true, Transport: transport}
	s.clients[c.ID] = c
	writes := 0
	transport.onWrite = func([]byte) { writes++ }
	const body = `{"subject":"owner","instanceId":"one","requestId":"00000000000000000000000000000001","action":"upgrade"}`
	w := managementRequest(s, "POST", "exact/actions", body)
	if w.Code != 202 || writes != 1 {
		t.Fatalf("dispatch %d, writes %d", w.Code, writes)
	}
	msg, err := protocol.Decode(transport.message)
	if err != nil || msg.ClientID != "exact" || msg.InstanceID != "one" || msg.Action != "upgrade" {
		t.Fatal("incorrect protocol binding")
	}
	w = managementRequest(s, "POST", "exact/actions", body)
	if w.Code != 200 || writes != 1 {
		t.Fatal("duplicate request re-executed")
	}
	w = managementRequest(s, "POST", "exact/actions", strings.Replace(body, "upgrade", "stop", 1))
	if w.Code != 409 {
		t.Fatal("conflicting request accepted")
	}
	msg.Type, msg.ActionState = protocol.MsgDeviceActionResult, "up_to_date"
	wrongConnection := &ClientConn{ID: c.ID, InstanceID: c.InstanceID}
	s.handleDeviceActionResult(wrongConnection, msg)
	w = managementRequest(s, "GET", "exact/actions?subject=owner&requestId="+msg.RequestID, "")
	var op deviceAction
	_ = json.Unmarshal(w.Body.Bytes(), &op)
	if op.State != "dispatched" {
		t.Fatal("another connection spoofed result")
	}
	s.handleDeviceActionResult(c, msg)
	w = managementRequest(s, "GET", "exact/actions?subject=owner&requestId="+msg.RequestID, "")
	_ = json.Unmarshal(w.Body.Bytes(), &op)
	if w.Code != 200 || op.State != "up_to_date" {
		t.Fatalf("missing result: %s", w.Body)
	}
	// Revocation denies both result polling and new commands.
	d := s.managedDevices["exact"]
	d.RevokedAt = time.Now()
	s.managedDevices["exact"] = d
	w = managementRequest(s, "POST", "exact/actions", body)
	if w.Code != 403 || writes != 1 {
		t.Fatal("revoked device received a command")
	}
}

func TestDeviceActionMissingCapabilityAndTimeout(t *testing.T) {
	s := NewServer()
	s.ControlToken = "test-control"
	s.managedDevices["exact"] = managedDevice{ID: "exact", OwnerSubject: "owner"}
	s.clients["exact"] = &ClientConn{ID: "exact", InstanceID: "one", Managed: true}
	body := `{"subject":"owner","instanceId":"one","requestId":"00000000000000000000000000000001","action":"stop"}`
	if w := managementRequest(s, "POST", "exact/actions", body); w.Code != 409 {
		t.Fatal("old client accepted")
	}
	s.management.actions = map[string]*deviceAction{
		"00000000000000000000000000000001": {
			RequestID: "00000000000000000000000000000001", DeviceID: "exact", subject: "owner",
			State: "dispatched", created: time.Now().Add(-16 * time.Minute),
		},
	}
	w := managementRequest(s, "GET", "exact/actions?subject=owner&requestId=00000000000000000000000000000001", "")
	if !strings.Contains(w.Body.String(), `"state":"unknown"`) {
		t.Fatal("unacknowledged operation claimed success")
	}
}

func TestDisplayNameRegistryDoesNotContainPlaintextSecret(t *testing.T) {
	// Real enrollment persistence, also exercising schema v6 with a permanent invite.
	s := NewServer()
	s.ControlToken = "test"
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := s.ConfigureEnrollmentStore(path, "https://example.test"); err != nil {
		t.Fatal(err)
	}
	invite := createEnrollmentForTest(t, s, "owner", 0)
	d := redeemEnrollmentForTest(t, s, invite.Code, "exact")
	w := managementRequest(s, http.MethodPatch, "exact/name", `{"subject":"owner","displayName":"name"}`)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), d.DeviceSecret) || strings.Contains(string(data), invite.Code) {
		t.Fatal("plaintext credential in registry")
	}
}
