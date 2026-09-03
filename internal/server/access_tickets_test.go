package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestControlAuthUsesOnlyControlTokenHeader(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"

	tests := []struct {
		name       string
		configure  func(*http.Request)
		wantStatus int
	}{
		{name: "missing", configure: func(*http.Request) {}, wantStatus: http.StatusUnauthorized},
		{name: "wrong header", configure: func(r *http.Request) { r.Header.Set("X-RDev-Control-Token", "wrong") }, wantStatus: http.StatusUnauthorized},
		{name: "legacy query", configure: func(r *http.Request) { r.URL.RawQuery = "token=control-secret" }, wantStatus: http.StatusUnauthorized},
		{name: "bearer", configure: func(r *http.Request) { r.Header.Set("Authorization", "Bearer control-secret") }, wantStatus: http.StatusUnauthorized},
		{name: "legacy header", configure: func(r *http.Request) { r.Header.Set("X-RDev-Token", "control-secret") }, wantStatus: http.StatusUnauthorized},
		{name: "control header", configure: func(r *http.Request) { r.Header.Set("X-RDev-Control-Token", "control-secret") }, wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/clients", nil)
			test.configure(req)
			response := httptest.NewRecorder()
			s.HandleAPI(response, req)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestControlAuthOpenModeCompatibility(t *testing.T) {
	s := NewServer()
	response := httptest.NewRecorder()
	s.HandleAPI(response, httptest.NewRequest(http.MethodGet, "/api/clients", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestWhitespaceControlTokenDoesNotEnableOpenMode(t *testing.T) {
	s := NewServer()
	s.ControlToken = "                                "
	response := httptest.NewRecorder()
	s.HandleAPI(response, httptest.NewRequest(http.MethodGet, "/api/clients", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestAccessTicketDeviceBindingAndExpiry(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.accessTicketNow = func() time.Time { return now }
	client := &ClientConn{ID: "device-a", InstanceID: "instance-a", Password: "device-secret"}
	s.clients[client.ID] = client
	s.clients["device-b"] = &ClientConn{ID: "device-b", InstanceID: "instance-b", Password: "device-secret"}

	ticket := issueAccessTicket(t, s, client.ID, 60)
	if !s.authorizeDeviceCredential(client, ticket) {
		t.Fatal("fresh ticket was rejected")
	}
	if s.authorizeDeviceCredential(s.clients["device-b"], ticket) {
		t.Fatal("ticket authenticated a different device")
	}

	client.InstanceID = "instance-a-reconnected"
	if s.authorizeDeviceCredential(client, ticket) {
		t.Fatal("ticket survived an instance change")
	}
	client.InstanceID = "instance-a"
	client.Password = "new-device-secret"
	if s.authorizeDeviceCredential(client, ticket) {
		t.Fatal("ticket survived a password change")
	}
	client.Password = "device-secret"
	now = now.Add(60 * time.Second)
	if s.authorizeDeviceCredential(client, ticket) {
		t.Fatal("ticket remained valid at its expiry instant")
	}
}

func TestAccessTicketCreationRejectsTrailingJSON(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	s.clients["device"] = &ClientConn{ID: "device", InstanceID: "one"}
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/control/access-tickets",
		strings.NewReader(`{"deviceId":"device","subject":"operator","expiresInSeconds":60}{}`),
	)
	req.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(response, req)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestSecureModeDeviceCredentialRules(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	protected := &ClientConn{ID: "protected", InstanceID: "one", Password: "device-secret"}
	open := &ClientConn{ID: "open", InstanceID: "two"}
	s.clients[protected.ID] = protected
	s.clients[open.ID] = open

	if !s.authorizeDeviceCredential(protected, "device-secret") {
		t.Fatal("legacy device password was rejected")
	}
	if s.authorizeDeviceCredential(protected, "wrong") {
		t.Fatal("wrong device password was accepted")
	}
	if s.authorizeDeviceCredential(open, "") {
		t.Fatal("passwordless device was accepted without a ticket in secure mode")
	}
	if ticket := issueAccessTicket(t, s, open.ID, 60); !s.authorizeDeviceCredential(open, ticket) {
		t.Fatal("ticket for passwordless device was rejected")
	}
}

func TestDeviceAuthorizationCacheTracksConnectionIdentity(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "one", Password: "secret"}
	authorization := deviceAuthorizationFor(client)
	files := &fileSocket{authorized: map[string]deviceAuthorization{client.ID: authorization}}
	batch := &batchSocket{authorized: map[string]deviceAuthorization{client.ID: authorization}}

	if !(&filesWSHandler{srv: s}).isAuthorized(files, client) {
		t.Fatal("files authorization cache rejected its original client")
	}
	if !(&batchWSHandler{srv: s}).isDeviceAuthorized(batch, client) {
		t.Fatal("batch authorization cache rejected its original client")
	}

	client.InstanceID = "two"
	if (&filesWSHandler{srv: s}).isAuthorized(files, client) {
		t.Fatal("files authorization cache survived an instance change")
	}
	if (&batchWSHandler{srv: s}).isDeviceAuthorized(batch, client) {
		t.Fatal("batch authorization cache survived an instance change")
	}
	client.InstanceID = "one"
	client.Password = "changed"
	if (&filesWSHandler{srv: s}).isAuthorized(files, client) {
		t.Fatal("files authorization cache survived a password change")
	}
	if (&batchWSHandler{srv: s}).isDeviceAuthorized(batch, client) {
		t.Fatal("batch authorization cache survived a password change")
	}
}

func TestGPUDesktopBrowserCredentialTransport(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "one", Password: "device-secret"}
	s.clients[client.ID] = client
	ticket := issueAccessTicket(t, s, client.ID, 60)

	tests := []struct {
		name       string
		url        string
		credential string
		wantStatus int
	}{
		{name: "legacy password query", url: "/gpu-desktop/device?password=device-secret", wantStatus: http.StatusFound},
		{name: "ticket header", url: "/gpu-desktop/device", credential: ticket, wantStatus: http.StatusFound},
		{name: "ticket query rejected", url: "/gpu-desktop/device?password=" + ticket, wantStatus: http.StatusUnauthorized},
		{name: "missing credential", url: "/gpu-desktop/device", wantStatus: http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.url, nil)
			req.Header.Set("X-RDev-Control-Token", s.ControlToken)
			if test.credential != "" {
				req.Header.Set("X-RDev-Device-Credential", test.credential)
			}
			response := httptest.NewRecorder()
			s.HandleGPUDesktopProxy(response, req)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestAccessTicketIsAbsentFromOtherAPIResponses(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "one", Password: "device-secret"}
	s.clients[client.ID] = client
	ticket := issueAccessTicket(t, s, client.ID, 60)

	req := httptest.NewRequest(http.MethodGet, "/api/clients", nil)
	req.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleAPI(response, req)
	if strings.Contains(response.Body.String(), ticket) {
		t.Fatal("access ticket leaked into a non-creation API response")
	}
}

func issueAccessTicket(t *testing.T, s *Server, deviceID string, lifetimeSeconds int64) string {
	t.Helper()
	body, err := json.Marshal(accessTicketCreateRequest{
		DeviceID:        deviceID,
		Subject:         "test operator",
		ExpiresInSecond: lifetimeSeconds,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/access-tickets", bytes.NewReader(body))
	req.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("ticket creation status = %d, body = %q", response.Code, response.Body.String())
	}
	var output accessTicketCreateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.Ticket, accessTicketPrefix) {
		t.Fatalf("ticket = %q, expected prefix %q", output.Ticket, accessTicketPrefix)
	}
	return output.Ticket
}
