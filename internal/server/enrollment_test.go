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

func TestPersistentReEnrollmentReplacesSameOwnerDevice(t *testing.T) {
	now := time.Date(2026, 9, 4, 9, 0, 0, 0, time.UTC)
	registryPath := filepath.Join(t.TempDir(), "managed_devices.json")
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	ticketNow := now
	s.accessTicketNow = func() time.Time { return ticketNow }
	if err := s.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}

	firstInvite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	first := redeemEnrollmentForTest(t, s, firstInvite.Code, "workstation-01")
	createdAt := s.managedDevices[first.DeviceID].CreatedAt
	transport := &enrollmentTestTransport{closed: make(chan string, 1)}
	s.mu.Lock()
	s.clients[first.DeviceID] = &ClientConn{
		ID: first.DeviceID, RequestedID: first.DeviceID, InstanceID: "old-instance", Transport: transport, PeripheralV1: true,
	}
	s.mu.Unlock()
	ticketValue := "rdvat_replacement-test-ticket"
	ticketHash := sha256.Sum256([]byte(ticketValue))
	s.accessTicketMu.Lock()
	s.accessTickets[ticketHash] = accessTicket{
		ID: "11111111111111111111111111111111", DeviceID: first.DeviceID,
		InstanceID: "old-instance", Subject: "feidu-user:42", ExpiresAt: now.Add(time.Hour),
	}
	s.accessTicketMu.Unlock()
	browserTicket := "rdvat_reenrollment-browser-ticket"
	browserTicketHash := sha256.Sum256([]byte(browserTicket))
	s.accessTicketMu.Lock()
	s.accessTickets[browserTicketHash] = accessTicket{
		ID: "33333333333333333333333333333333", DeviceID: first.DeviceID,
		DeviceCredentialVersion: s.managedDevices[first.DeviceID].CredentialVersion,
		InstanceID:              "old-instance", PasswordFingerprint: passwordFingerprint(""),
		Subject: "feidu-browser:42", Capabilities: []string{browserCapabilityPeripherals}, ExpiresAt: now.Add(10 * time.Minute),
	}
	s.accessTicketMu.Unlock()
	_, browserCapture := connectTrackedPeripheralBrowserForTest(t, s, first.DeviceID, browserTicket)

	now = now.Add(time.Minute)
	secondInvite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	body, err := json.Marshal(enrollmentRedeemRequest{
		Code: secondInvite.Code, DeviceID: first.DeviceID, ReplaceExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(response, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("replace status = %d, body = %q", response.Code, response.Body.String())
	}
	var replaced enrollmentRedeemResponse
	if err = json.Unmarshal(response.Body.Bytes(), &replaced); err != nil {
		t.Fatal(err)
	}
	if replaced.DeviceID != first.DeviceID || replaced.DeviceSecret == first.DeviceSecret {
		t.Fatalf("replacement identity = %#v", replaced)
	}
	if len(s.managedDevices) != 1 {
		t.Fatalf("managed devices = %d, want 1", len(s.managedDevices))
	}
	record := s.managedDevices[first.DeviceID]
	if !record.CreatedAt.Equal(createdAt) || !record.UpdatedAt.Equal(now.UTC().Truncate(time.Second)) {
		t.Fatalf("replacement timestamps = created %s updated %s", record.CreatedAt, record.UpdatedAt)
	}
	if allowed, managed := s.authorizeManagedRegistration(first.DeviceID, first.DeviceSecret); !managed || allowed {
		t.Fatal("old managed-device secret remained valid")
	}
	if allowed, managed := s.authorizeManagedRegistration(replaced.DeviceID, replaced.DeviceSecret); !managed || !allowed {
		t.Fatal("replacement managed-device secret was rejected")
	}
	staleLegacy := &ClientConn{ID: replaced.DeviceID, RequestedID: replaced.DeviceID}
	if _, _, _, registered, err := s.registerClientIfAuthorizationCurrent(staleLegacy, ""); err != nil || registered {
		t.Fatal("stale unmanaged authorization registered over a managed device")
	}
	s.mu.RLock()
	registeredAfterReplacement := s.clients[replaced.DeviceID]
	s.mu.RUnlock()
	if registeredAfterReplacement != nil {
		t.Fatal("replacement retained the old client in the online registry")
	}
	oldClient := &ClientConn{ID: first.DeviceID, InstanceID: "old-instance"}
	if s.accessTicketValid(oldClient, ticketValue) {
		t.Fatal("replacement left the old access ticket usable")
	}
	select {
	case reason := <-transport.closed:
		if reason != "managed device replaced" {
			t.Fatalf("device close reason = %q", reason)
		}
	default:
		t.Fatal("old managed-device connection was not closed")
	}
	select {
	case <-browserCapture.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("re-enrollment did not close the active browser WebSocket")
	}

	reloaded := NewServer()
	if err = reloaded.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	if allowed, managed := reloaded.authorizeManagedRegistration(replaced.DeviceID, replaced.DeviceSecret); !managed || !allowed {
		t.Fatal("reloaded registry rejected replacement secret")
	}
}

func TestManagedDeviceRegistryV2LoadsWithInitialCredentialVersion(t *testing.T) {
	now := time.Date(2026, 9, 4, 9, 30, 0, 0, time.UTC)
	registryPath := filepath.Join(t.TempDir(), "managed_devices.json")
	original := NewServer()
	original.ControlToken = "control-secret"
	original.enrollmentNow = func() time.Time { return now }
	if err := original.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	invite := createEnrollmentForTest(t, original, "feidu-user:42", 600)
	redeemed := redeemEnrollmentForTest(t, original, invite.Code, "legacy-registry-device")
	device := original.managedDevices[redeemed.DeviceID]
	legacy := managedDeviceRegistry{
		Schema: managedDeviceRegistryV2,
		Devices: []managedDeviceRegistryRecord{{
			ID: device.ID, OwnerSubject: device.OwnerSubject, SecretHash: device.SecretHash,
			CreatedAt: device.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: device.UpdatedAt.UTC().Format(time.RFC3339),
		}},
	}
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err = os.WriteFile(registryPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	reloaded := NewServer()
	if err = reloaded.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	loaded := reloaded.managedDevices[redeemed.DeviceID]
	if loaded.CredentialVersion != 1 {
		t.Fatalf("legacy device credential version = %d, want 1", loaded.CredentialVersion)
	}
	if allowed, managed := reloaded.authorizeManagedRegistration(redeemed.DeviceID, redeemed.DeviceSecret); !managed || !allowed {
		t.Fatal("legacy registry device secret was rejected")
	}
}

func TestPersistentReEnrollmentRejectsAnotherOwner(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(filepath.Join(t.TempDir(), "managed_devices.json"), "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	firstInvite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	first := redeemEnrollmentForTest(t, s, firstInvite.Code, "shared-name")
	secondInvite := createEnrollmentForTest(t, s, "feidu-user:43", 600)
	body, err := json.Marshal(enrollmentRedeemRequest{
		Code: secondInvite.Code, DeviceID: first.DeviceID, ReplaceExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(response, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
	if response.Code != http.StatusConflict {
		t.Fatalf("cross-owner replacement status = %d, want 409", response.Code)
	}
	if allowed, managed := s.authorizeManagedRegistration(first.DeviceID, first.DeviceSecret); !managed || !allowed {
		t.Fatal("rejected replacement changed the existing device secret")
	}
	if status := getEnrollmentStatusForTest(t, s, secondInvite.EnrollmentID); status.State != "active" {
		t.Fatalf("rejected replacement consumed the invitation: %#v", status)
	}
}

func TestPersistentReEnrollmentInvalidatesTicketsWithoutTicketStoreMutation(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 15, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(filepath.Join(t.TempDir(), "managed_devices.json"), "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	firstInvite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	first := redeemEnrollmentForTest(t, s, firstInvite.Code, "ticket-persist-failure")
	transport := &enrollmentTestTransport{closed: make(chan string, 1)}
	s.mu.Lock()
	s.clients[first.DeviceID] = &ClientConn{
		ID: first.DeviceID, RequestedID: first.DeviceID, InstanceID: "old-instance", Transport: transport,
	}
	s.mu.Unlock()
	ticketValue := "rdvat_ticket-that-must-be-invalidated"
	ticketHash := sha256.Sum256([]byte(ticketValue))
	s.accessTicketMu.Lock()
	s.accessTickets[ticketHash] = accessTicket{
		ID: "22222222222222222222222222222222", DeviceID: first.DeviceID,
		InstanceID: "old-instance", Subject: "feidu-user:42", ExpiresAt: now.Add(time.Hour),
	}
	ticketStoreDirectory := filepath.Join(t.TempDir(), "existing-directory")
	if err := os.Mkdir(ticketStoreDirectory, 0700); err != nil {
		s.accessTicketMu.Unlock()
		t.Fatal(err)
	}
	s.accessTicketStorePath = ticketStoreDirectory
	s.accessTicketMu.Unlock()

	secondInvite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	body, err := json.Marshal(enrollmentRedeemRequest{
		Code: secondInvite.Code, DeviceID: first.DeviceID, ReplaceExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(response, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("replacement status = %d, want 200; body = %q", response.Code, response.Body.String())
	}
	if allowed, managed := s.authorizeManagedRegistration(first.DeviceID, first.DeviceSecret); !managed || allowed {
		t.Fatal("replacement left the old device secret usable")
	}
	s.accessTicketMu.Lock()
	_, ticketExists := s.accessTickets[ticketHash]
	s.accessTicketMu.Unlock()
	if !ticketExists {
		t.Fatal("replacement unexpectedly required a ticket-store rewrite")
	}
	oldClient := &ClientConn{ID: first.DeviceID, InstanceID: "old-instance"}
	if s.accessTicketValid(oldClient, ticketValue) {
		t.Fatal("retained old access ticket remained usable after replacement")
	}
	if status := getEnrollmentStatusForTest(t, s, secondInvite.EnrollmentID); status.State != "consumed" {
		t.Fatalf("replacement invitation status = %#v", status)
	}
	select {
	case reason := <-transport.closed:
		if reason != "managed device replaced" {
			t.Fatalf("replacement close reason = %q", reason)
		}
	default:
		t.Fatal("replacement did not disconnect the old device")
	}
}

func TestFinalManagedRegistrationRejectsSecretReplacedAfterInitialAuthorization(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 20, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(filepath.Join(t.TempDir(), "managed_devices.json"), "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	firstInvite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	first := redeemEnrollmentForTest(t, s, firstInvite.Code, "registration-race")
	if allowed, managed := s.authorizeManagedRegistration(first.DeviceID, first.DeviceSecret); !managed || !allowed {
		t.Fatal("initial managed-device authorization failed")
	}
	now = now.Add(time.Minute)
	secondInvite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	body, err := json.Marshal(enrollmentRedeemRequest{
		Code: secondInvite.Code, DeviceID: first.DeviceID, ReplaceExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(response, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("replacement status = %d, body = %q", response.Code, response.Body.String())
	}
	stale := &ClientConn{ID: first.DeviceID, RequestedID: first.DeviceID, Managed: true}
	if _, _, _, registered, err := s.registerClientIfAuthorizationCurrent(stale, first.DeviceSecret); err != nil || registered {
		t.Fatal("old device secret completed registration after replacement")
	}
	if client := s.clientByID(first.DeviceID); client != nil {
		t.Fatal("old device secret created an online client")
	}
}

func TestFinalUnmanagedRegistrationRejectsDeviceCreatedAndRevokedAfterInitialAuthorization(t *testing.T) {
	s := NewServer()
	deviceID := "registration-revocation-race"
	if allowed, managed := s.authorizeManagedRegistration(deviceID, ""); allowed || managed {
		t.Fatal("device unexpectedly existed during initial authorization")
	}

	s.enrollmentMu.Lock()
	s.managedDevices[deviceID] = managedDevice{
		ID: deviceID, OwnerSubject: "feidu-user:42", SecretHash: "unused",
		CredentialVersion: 2, RevokedAt: time.Now(),
	}
	s.enrollmentMu.Unlock()
	stale := &ClientConn{ID: deviceID, RequestedID: deviceID}
	if _, _, _, registered, err := s.registerClientIfAuthorizationCurrent(stale, ""); err != nil || registered {
		t.Fatal("stale unmanaged authorization registered over a revoked managed device")
	}
	if client := s.clientByID(deviceID); client != nil {
		t.Fatal("stale unmanaged authorization created an online client")
	}
}

func TestPersistentReEnrollmentRejectsRevokedManagedDevice(t *testing.T) {
	now := time.Date(2026, 9, 4, 10, 30, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(filepath.Join(t.TempDir(), "managed_devices.json"), "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	firstInvite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	first := redeemEnrollmentForTest(t, s, firstInvite.Code, "revoked-device")
	if err := s.revokeManagedDevice(first.DeviceID); err != nil {
		t.Fatal(err)
	}
	secondInvite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	body, err := json.Marshal(enrollmentRedeemRequest{
		Code: secondInvite.Code, DeviceID: first.DeviceID, ReplaceExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(response, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
	if response.Code != http.StatusConflict {
		t.Fatalf("revoked replacement status = %d, want 409", response.Code)
	}
	if allowed, managed := s.authorizeManagedRegistration(first.DeviceID, first.DeviceSecret); !managed || allowed {
		t.Fatal("revoked device became authorized")
	}
	if status := getEnrollmentStatusForTest(t, s, secondInvite.EnrollmentID); status.State != "active" {
		t.Fatalf("revoked replacement consumed the invitation: %#v", status)
	}
}

func TestPersistentReEnrollmentRejectsUnmanagedOnlineDevice(t *testing.T) {
	now := time.Date(2026, 9, 4, 11, 0, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(filepath.Join(t.TempDir(), "managed_devices.json"), "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	transport := &enrollmentTestTransport{closed: make(chan string, 1)}
	s.mu.Lock()
	s.clients["legacy-online"] = &ClientConn{
		ID: "legacy-online", RequestedID: "legacy-online", InstanceID: "legacy-instance", Transport: transport,
	}
	s.mu.Unlock()
	invite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	body, err := json.Marshal(enrollmentRedeemRequest{
		Code: invite.Code, DeviceID: "legacy-online", ReplaceExisting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.HandleEnrollmentRedeemAPI(response, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
	if response.Code != http.StatusConflict {
		t.Fatalf("unmanaged online replacement status = %d, want 409", response.Code)
	}
	if _, managed := s.authorizeManagedRegistration("legacy-online", "unused"); managed {
		t.Fatal("unmanaged online device became managed")
	}
	if status := getEnrollmentStatusForTest(t, s, invite.EnrollmentID); status.State != "active" {
		t.Fatalf("unmanaged replacement consumed the invitation: %#v", status)
	}
	select {
	case reason := <-transport.closed:
		t.Fatalf("unmanaged online device was disconnected: %q", reason)
	default:
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
	ticketNow := now
	s.accessTicketNow = func() time.Time { return ticketNow }
	if err := s.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	created := createEnrollmentForTest(t, s, "feidu-user:9", 600)
	redeemed := redeemEnrollmentForTest(t, s, created.Code, "managed-workstation")
	transport := &enrollmentTestTransport{closed: make(chan string, 1)}
	s.mu.Lock()
	s.clients[redeemed.DeviceID] = &ClientConn{
		ID: redeemed.DeviceID, RequestedID: redeemed.DeviceID, InstanceID: "connected-instance", Transport: transport,
		OwnerSubject: "feidu-user:9", PeripheralV1: true, Sessions: make(map[string]*ProxySession), Forwards: make(map[string]*ProxyForward),
	}
	s.mu.Unlock()
	_, _, beforeRotateSequence := s.deviceEventsAfter(0)
	ticketValue := "rdvat_temporary-access-ticket"
	ticketHash := sha256.Sum256([]byte(ticketValue))
	s.accessTicketMu.Lock()
	s.accessTickets[ticketHash] = accessTicket{DeviceID: redeemed.DeviceID, InstanceID: "connected-instance", ExpiresAt: now.Add(time.Hour)}
	s.accessTicketMu.Unlock()
	browserTicket := "rdvat_rotation-browser-ticket"
	browserTicketHash := sha256.Sum256([]byte(browserTicket))
	s.accessTicketMu.Lock()
	s.accessTickets[browserTicketHash] = accessTicket{
		ID: "44444444444444444444444444444444", DeviceID: redeemed.DeviceID,
		DeviceCredentialVersion: s.managedDevices[redeemed.DeviceID].CredentialVersion,
		InstanceID:              "connected-instance", PasswordFingerprint: passwordFingerprint(""),
		Subject: "feidu-browser:9", Capabilities: []string{browserCapabilityPeripherals}, ExpiresAt: now.Add(10 * time.Minute),
	}
	s.accessTicketMu.Unlock()
	_, browserCapture := connectTrackedPeripheralBrowserForTest(t, s, redeemed.DeviceID, browserTicket)

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
	if _, connected := s.GetClient(redeemed.DeviceID); connected {
		t.Fatal("rotated device remained in the online registry")
	}
	select {
	case <-browserCapture.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("device secret rotation did not close the active browser WebSocket")
	}
	rotateEvents, reset, _ := s.deviceEventsAfter(beforeRotateSequence)
	if reset || len(rotateEvents) != 1 || rotateEvents[0].Type != "device.offline" || rotateEvents[0].DeviceID != redeemed.DeviceID || rotateEvents[0].OwnerSubject != "feidu-user:9" {
		t.Fatalf("rotation device events = %#v, reset = %v", rotateEvents, reset)
	}
	oldClient := &ClientConn{ID: redeemed.DeviceID, InstanceID: "connected-instance"}
	if s.accessTicketValid(oldClient, ticketValue) {
		t.Fatal("access ticket remained usable after secret rotation")
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
	reloaded.mu.Lock()
	reloaded.clients[redeemed.DeviceID] = &ClientConn{
		ID: redeemed.DeviceID, RequestedID: redeemed.DeviceID, InstanceID: "reconnected-instance",
		OwnerSubject: "feidu-user:9", Sessions: make(map[string]*ProxySession), Forwards: make(map[string]*ProxyForward),
	}
	reloaded.mu.Unlock()

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
	revokeEvents, reset, _ := reloaded.deviceEventsAfter(0)
	if reset || len(revokeEvents) != 1 || revokeEvents[0].Type != "device.offline" || revokeEvents[0].DeviceID != redeemed.DeviceID || revokeEvents[0].OwnerSubject != "feidu-user:9" {
		t.Fatalf("revocation device events = %#v, reset = %v", revokeEvents, reset)
	}

	restarted := NewServer()
	if err = restarted.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	if allowed, managed := restarted.authorizeManagedRegistration(redeemed.DeviceID, rotated.DeviceSecret); !managed || allowed {
		t.Fatal("restarted registry accepted a revoked device")
	}
}

func TestManagedDeviceRotationInvalidatesPersistedAccessTicketAcrossRestart(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 30, 0, 0, time.UTC)
	dataDir := t.TempDir()
	registryPath := filepath.Join(dataDir, "managed_devices.json")
	ticketPath := filepath.Join(dataDir, "access_tickets.json")
	s := NewServer()
	s.ControlToken = "control-secret"
	s.enrollmentNow = func() time.Time { return now }
	s.accessTicketNow = func() time.Time { return now }
	if err := s.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.ConfigureAccessTicketStore(ticketPath); err != nil {
		t.Fatal(err)
	}
	invite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	redeemed := redeemEnrollmentForTest(t, s, invite.Code, "persisted-ticket-device")
	client := &ClientConn{
		ID: redeemed.DeviceID, RequestedID: redeemed.DeviceID, InstanceID: "instance-one",
		Password: "device-password", Managed: true,
	}
	s.clients[client.ID] = client
	ticketValue := issueAccessTicketWithSubject(t, s, client.ID, "feidu-user:42", 600)

	rotateRequest := httptest.NewRequest(http.MethodPost, "/api/control/devices/"+client.ID+"/rotate-secret", nil)
	rotateRequest.Header.Set("X-RDev-Control-Token", s.ControlToken)
	rotateResponse := httptest.NewRecorder()
	s.HandleManagedDeviceLifecycleAPI(rotateResponse, rotateRequest)
	if rotateResponse.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, body = %q", rotateResponse.Code, rotateResponse.Body.String())
	}
	if s.accessTicketValid(client, ticketValue) {
		t.Fatal("rotated device accepted its previous access ticket")
	}

	reloaded := NewServer()
	reloaded.enrollmentNow = func() time.Time { return now }
	reloaded.accessTicketNow = func() time.Time { return now }
	if err := reloaded.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := reloaded.ConfigureAccessTicketStore(ticketPath); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.accessTickets) != 1 {
		t.Fatalf("persisted stale ticket count = %d, want 1", len(reloaded.accessTickets))
	}
	if reloaded.accessTicketValid(client, ticketValue) {
		t.Fatal("server restart restored an access ticket from an older device credential version")
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
