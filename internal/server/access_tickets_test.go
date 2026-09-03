package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lxzan/gws"
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

func TestBrowserSocketAuthAcceptsOnlyScopedFeiduTicket(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	s.clients["device-a"] = &ClientConn{ID: "device-a", InstanceID: "one", Password: "secret"}
	browserTicket := issueAccessTicketWithSubject(t, s, "device-a", "feidu-browser:42", 60)
	agentTicket := issueAccessTicketWithSubject(t, s, "device-a", "feidu-agent:42", 60)

	tests := []struct {
		name       string
		path       string
		method     string
		upgrade    bool
		protocol   string
		wantStatus int
	}{
		{name: "terminal", path: "/terminal?device=device-a", method: http.MethodGet, upgrade: true, protocol: browserTicketProtocol + browserTicket, wantStatus: http.StatusOK},
		{name: "files", path: "/files", method: http.MethodGet, upgrade: true, protocol: "rdev-browser-v1, " + browserTicketProtocol + browserTicket, wantStatus: http.StatusOK},
		{name: "wrong device", path: "/desktop?device=device-b", method: http.MethodGet, upgrade: true, protocol: browserTicketProtocol + browserTicket, wantStatus: http.StatusUnauthorized},
		{name: "agent ticket", path: "/terminal?device=device-a", method: http.MethodGet, upgrade: true, protocol: browserTicketProtocol + agentTicket, wantStatus: http.StatusUnauthorized},
		{name: "control api", path: "/api/clients", method: http.MethodGet, upgrade: true, protocol: browserTicketProtocol + browserTicket, wantStatus: http.StatusUnauthorized},
		{name: "not websocket", path: "/terminal?device=device-a", method: http.MethodGet, protocol: browserTicketProtocol + browserTicket, wantStatus: http.StatusUnauthorized},
		{name: "wrong method", path: "/files", method: http.MethodPost, upgrade: true, protocol: browserTicketProtocol + browserTicket, wantStatus: http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, nil)
			if test.upgrade {
				req.Header.Set("Connection", "keep-alive, Upgrade")
				req.Header.Set("Upgrade", "websocket")
			}
			req.Header.Set("Sec-WebSocket-Protocol", test.protocol)
			response := httptest.NewRecorder()
			if s.requireAuth(response, req) != (test.wantStatus == http.StatusOK) {
				t.Fatalf("authorization mismatch, response status = %d", response.Code)
			}
			if test.wantStatus != http.StatusOK && response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestBrowserWebSocketHandlersNegotiateProtocol(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		handler func(*Server, http.ResponseWriter, *http.Request)
	}{
		{name: "terminal", path: "/terminal?device=device", handler: func(s *Server, w http.ResponseWriter, r *http.Request) { s.HandleTerminalWS(w, r) }},
		{name: "files", path: "/files", handler: func(s *Server, w http.ResponseWriter, r *http.Request) { s.HandleFilesWS(w, r) }},
		{name: "desktop", path: "/desktop?device=device", handler: func(s *Server, w http.ResponseWriter, r *http.Request) { s.HandleDesktopWS(w, r) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := NewServer()
			s.ControlToken = "control-secret"
			s.clients["device"] = &ClientConn{ID: "device", InstanceID: "one"}
			ticket := issueAccessTicketWithSubject(t, s, "device", "feidu-browser:42", 60)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				test.handler(s, w, r)
			}))
			t.Cleanup(server.Close)

			header := make(http.Header)
			header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+ticket)
			socket, response, err := gws.NewClient(&gws.BuiltinEventHandler{}, &gws.ClientOption{
				Addr:          "ws" + strings.TrimPrefix(server.URL, "http") + test.path,
				RequestHeader: header,
			})
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			t.Cleanup(func() { _ = socket.WriteClose(1000, nil) })
			if got := response.Header.Get("Sec-WebSocket-Protocol"); got != browserSocketProtocol {
				t.Fatalf("response protocol = %q, want %q", got, browserSocketProtocol)
			}
			if got := socket.SubProtocol(); got != browserSocketProtocol {
				t.Fatalf("socket protocol = %q, want %q", got, browserSocketProtocol)
			}
		})
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

func TestAccessTicketResponseUsesOneExactSecondPrecision(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 987654321, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.accessTicketNow = func() time.Time { return now }
	s.clients["device"] = &ClientConn{ID: "device", InstanceID: "one"}
	req := httptest.NewRequest(
		http.MethodPost,
		"/api/control/access-tickets",
		strings.NewReader("{\"deviceId\":\"device\",\"subject\":\"feidu-browser:42\",\"expiresInSeconds\":600}"),
	)
	req.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()

	s.HandleAccessTicketsAPI(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var access accessTicketCreateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &access); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	wantExpiresAt := now.Add(10 * time.Minute).UTC().Truncate(time.Second)
	if access.ExpiresAt != wantExpiresAt.Format(time.RFC3339) {
		t.Fatalf("expiresAt = %q, want %q", access.ExpiresAt, wantExpiresAt.Format(time.RFC3339))
	}
	if access.ExpiresAtMs != wantExpiresAt.UnixMilli() {
		t.Fatalf("expiresAtMs = %d, want %d", access.ExpiresAtMs, wantExpiresAt.UnixMilli())
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
	return issueAccessTicketWithSubject(t, s, deviceID, "test operator", lifetimeSeconds)
}

func issueAccessTicketWithSubject(t *testing.T, s *Server, deviceID, subject string, lifetimeSeconds int64) string {
	t.Helper()
	body, err := json.Marshal(accessTicketCreateRequest{
		DeviceID:        deviceID,
		Subject:         subject,
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
