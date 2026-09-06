package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lxzan/gws"
	"golang.org/x/crypto/bcrypt"
)

type browserCloseCapture struct {
	gws.BuiltinEventHandler
	closed chan struct{}
	once   sync.Once
}

func connectTrackedPeripheralBrowserForTest(t *testing.T, s *Server, deviceID, ticket string) (*gws.Conn, *browserCloseCapture) {
	t.Helper()
	httpServer := httptest.NewServer(http.HandlerFunc(s.HandlePeripheralsWS))
	t.Cleanup(httpServer.Close)
	capture := &browserCloseCapture{closed: make(chan struct{})}
	header := make(http.Header)
	header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+ticket)
	socket, _, err := gws.NewClient(capture, &gws.ClientOption{
		Addr: "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/peripherals?device=" + deviceID, RequestHeader: header,
	})
	if err != nil {
		t.Fatalf("connect browser: %v", err)
	}
	t.Cleanup(func() { _ = socket.WriteClose(1000, nil) })
	go socket.ReadLoop()
	ticketHash := sha256.Sum256([]byte(ticket))
	s.accessTicketMu.Lock()
	ticketID := s.accessTickets[ticketHash].ID
	s.accessTicketMu.Unlock()
	deadline := time.After(2 * time.Second)
	for {
		s.browserTicketMu.Lock()
		tracked := len(s.browserTicketConnections[ticketID]) > 0
		s.browserTicketMu.Unlock()
		if tracked {
			return socket, capture
		}
		select {
		case <-deadline:
			t.Fatal("browser ticket connection was not tracked")
		case <-time.After(time.Millisecond):
		}
	}
}

func (capture *browserCloseCapture) OnClose(*gws.Conn, error) {
	capture.once.Do(func() { close(capture.closed) })
}

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
	browserTicket := issueScopedAccessTicketWithSubject(t, s, "device-a", "feidu-browser:42", 60, []string{
		browserCapabilityDesktop, browserCapabilityFiles, browserCapabilityPeripherals, browserCapabilityTerminal,
	})
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
		{name: "peripherals", path: "/peripherals?device=device-a", method: http.MethodGet, upgrade: true, protocol: browserTicketProtocol + browserTicket, wantStatus: http.StatusOK},
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

func TestBrowserSocketAuthRequiresExactCapability(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	s.clients["device-a"] = &ClientConn{ID: "device-a", InstanceID: "one", Password: "secret"}
	peripheralTicket := issueScopedAccessTicketWithSubject(
		t, s, "device-a", "feidu-browser:42", 60, []string{browserCapabilityPeripherals},
	)
	legacyTicket := issueAccessTicketWithSubject(t, s, "device-a", "feidu-browser:42", 60)

	for _, test := range []struct {
		name   string
		path   string
		ticket string
		want   bool
	}{
		{name: "scoped peripheral", path: "/peripherals?device=device-a", ticket: peripheralTicket, want: true},
		{name: "scoped terminal rejected", path: "/terminal?device=device-a", ticket: peripheralTicket, want: false},
		{name: "legacy terminal", path: "/terminal?device=device-a", ticket: legacyTicket, want: true},
		{name: "legacy peripheral rejected", path: "/peripherals?device=device-a", ticket: legacyTicket, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.path, nil)
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+test.ticket)
			if got := s.browserSocketAuthOK(req); got != test.want {
				t.Fatalf("browser socket authorization = %t, want %t", got, test.want)
			}
		})
	}
}

func TestBrowserTicketCannotAuthenticateSSHCredentialPath(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device-a", InstanceID: "one", Password: "secret"}
	s.clients[client.ID] = client
	ticket := issueScopedAccessTicketWithSubject(
		t, s, client.ID, "feidu-browser:42", 60, []string{browserCapabilityTerminal},
	)
	if s.authorizeDeviceCredential(client, ticket) {
		t.Fatal("browser-only ticket authenticated the generic device credential path")
	}
	if _, ok := s.authorizeBrowserDeviceCredentialBinding(client, ticket, browserCapabilityTerminal); !ok {
		t.Fatal("terminal browser ticket was rejected by the terminal credential path")
	}
	if _, ok := s.authorizeBrowserDeviceCredentialBinding(client, ticket, browserCapabilityFiles); ok {
		t.Fatal("terminal browser ticket authenticated the files credential path")
	}
}

func TestBrowserAccessTicketRejectsChangedOrRevokedManagedDeviceCredential(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	s.clients["device-a"] = &ClientConn{ID: "device-a", InstanceID: "one", Password: "secret"}
	ticket := issueAccessTicketWithSubject(t, s, "device-a", "feidu-browser:42", 60)
	if !s.browserAccessTicketValid(ticket, "device-a", browserCapabilityTerminal) {
		t.Fatal("fresh browser access ticket was rejected")
	}

	device := s.managedDevices["device-a"]
	device.CredentialVersion++
	s.managedDevices["device-a"] = device
	if s.browserAccessTicketValid(ticket, "device-a", browserCapabilityTerminal) {
		t.Fatal("browser access ticket survived a device credential version change")
	}

	device.CredentialVersion--
	device.RevokedAt = time.Now()
	s.managedDevices["device-a"] = device
	if s.browserAccessTicketValid(ticket, "device-a", browserCapabilityTerminal) {
		t.Fatal("browser access ticket remained valid for a revoked managed device")
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
		{name: "peripherals", path: "/peripherals?device=device", handler: func(s *Server, w http.ResponseWriter, r *http.Request) { s.HandlePeripheralsWS(w, r) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := NewServer()
			s.ControlToken = "control-secret"
			s.clients["device"] = &ClientConn{ID: "device", InstanceID: "one"}
			ticket := issueScopedAccessTicketWithSubject(t, s, "device", "feidu-browser:42", 60, []string{
				browserCapabilityDesktop, browserCapabilityFiles, browserCapabilityPeripherals, browserCapabilityTerminal,
			})
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

func TestBrowserTicketExpiryClosesEstablishedWebSocket(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "one", PeripheralV1: true}
	s.clients[client.ID] = client
	ticket := issueScopedAccessTicketWithSubject(
		t, s, client.ID, "feidu-browser:42", 60, []string{browserCapabilityPeripherals},
	)
	s.accessTicketMu.Lock()
	for hash, stored := range s.accessTickets {
		stored.ExpiresAt = time.Now().Add(500 * time.Millisecond)
		s.accessTickets[hash] = stored
	}
	s.accessTicketMu.Unlock()

	httpServer := httptest.NewServer(http.HandlerFunc(s.HandlePeripheralsWS))
	t.Cleanup(httpServer.Close)
	capture := &browserCloseCapture{closed: make(chan struct{})}
	header := make(http.Header)
	header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+ticket)
	socket, _, err := gws.NewClient(capture, &gws.ClientOption{
		Addr: "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/peripherals?device=device", RequestHeader: header,
	})
	if err != nil {
		t.Fatalf("connect browser: %v", err)
	}
	go socket.ReadLoop()
	select {
	case <-capture.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("established browser WebSocket remained open after ticket expiry")
	}
}

func TestBrowserTicketRevocationClosesEstablishedWebSocket(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "one", PeripheralV1: true}
	s.clients[client.ID] = client
	ticket := issueScopedAccessTicketWithSubject(
		t, s, client.ID, "feidu-browser:42", 60, []string{browserCapabilityPeripherals},
	)
	var ticketID string
	s.accessTicketMu.Lock()
	for _, stored := range s.accessTickets {
		ticketID = stored.ID
	}
	s.accessTicketMu.Unlock()

	httpServer := httptest.NewServer(http.HandlerFunc(s.HandlePeripheralsWS))
	t.Cleanup(httpServer.Close)
	capture := &browserCloseCapture{closed: make(chan struct{})}
	header := make(http.Header)
	header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+ticket)
	socket, _, err := gws.NewClient(capture, &gws.ClientOption{
		Addr: "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/peripherals?device=device", RequestHeader: header,
	})
	if err != nil {
		t.Fatalf("connect browser: %v", err)
	}
	go socket.ReadLoop()

	body, err := json.Marshal(accessTicketRevokeRequest{TicketID: ticketID})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodDelete, "/api/control/access-tickets", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d", response.Code)
	}
	select {
	case <-capture.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("established browser WebSocket remained open after ticket revocation")
	}
}

func TestBrowserTicketRevokedAfterUpgradeAuthorizationIsNotTracked(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "one", PeripheralV1: true}
	s.clients[client.ID] = client
	ticket := issueScopedAccessTicketWithSubject(
		t, s, client.ID, "feidu-browser:42", 60, []string{browserCapabilityPeripherals},
	)
	ticketHash := sha256.Sum256([]byte(ticket))
	s.accessTicketMu.Lock()
	ticketID := s.accessTickets[ticketHash].ID
	s.accessTicketMu.Unlock()

	authorized := make(chan struct{})
	releaseUpgrade := make(chan struct{})
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := gws.NewUpgrader(&gws.BuiltinEventHandler{}, &gws.ServerOption{
			SubProtocols: []string{browserSocketProtocol},
			Authorize: func(r *http.Request, session gws.SessionStorage) bool {
				session.Store("deviceID", client.ID)
				if !s.authorizeBrowserUpgrade(r, session, client.ID) {
					return false
				}
				close(authorized)
				<-releaseUpgrade
				return true
			},
		})
		socket, err := upgrader.Upgrade(w, r)
		if err != nil {
			return
		}
		if _, ok := s.trackBrowserTicketConnection(socket); !ok {
			_ = socket.WriteClose(4003, []byte("browser access expired"))
			return
		}
		defer s.untrackBrowserTicketConnection(socket)
		socket.ReadLoop()
	}))
	t.Cleanup(httpServer.Close)

	type connectionResult struct {
		socket  *gws.Conn
		capture *browserCloseCapture
		err     error
	}
	connected := make(chan connectionResult, 1)
	go func() {
		capture := &browserCloseCapture{closed: make(chan struct{})}
		header := make(http.Header)
		header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+ticket)
		socket, _, err := gws.NewClient(capture, &gws.ClientOption{
			Addr: "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/peripherals?device=device", RequestHeader: header,
		})
		connected <- connectionResult{socket: socket, capture: capture, err: err}
	}()
	select {
	case <-authorized:
	case <-time.After(2 * time.Second):
		t.Fatal("browser upgrade authorization did not run")
	}
	body, err := json.Marshal(accessTicketRevokeRequest{TicketID: ticketID})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodDelete, "/api/control/access-tickets", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d", response.Code)
	}
	close(releaseUpgrade)
	result := <-connected
	if result.err != nil {
		t.Fatalf("connect after authorized upgrade: %v", result.err)
	}
	go result.socket.ReadLoop()
	select {
	case <-result.capture.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked ticket connection entered the browser read loop")
	}
	s.browserTicketMu.Lock()
	tracked := len(s.browserTicketConnections[ticketID])
	s.browserTicketMu.Unlock()
	if tracked != 0 {
		t.Fatalf("revoked ticket retained %d tracked browser connections", tracked)
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

func TestManagedDeviceAccessTicketRequiresExactOwnerSubject(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	s.managedDevices["managed-device"] = managedDevice{
		ID: "managed-device", OwnerSubject: "feidu-user:42", SecretHash: "$2a$10$abcdefghijklmnopqrstuv012345678901234567890123456789012", CredentialVersion: 1,
	}
	s.clients["managed-device"] = &ClientConn{ID: "managed-device", InstanceID: "online"}
	body := []byte(`{"deviceId":"managed-device","subject":"feidu-user:7","expiresInSeconds":600}`)
	request := httptest.NewRequest(http.MethodPost, "/api/control/access-tickets", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestUnmanagedDeviceAccessTicketIsRejected(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	s.clients["legacy-device"] = &ClientConn{ID: "legacy-device", InstanceID: "online"}
	body := []byte(`{"deviceId":"legacy-device","subject":"feidu-user:42","expiresInSeconds":600}`)
	request := httptest.NewRequest(http.MethodPost, "/api/control/access-tickets", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()

	s.HandleAccessTicketsAPI(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestManagedDeviceBrowserTicketMapsToExactAccountOwner(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	s.managedDevices["managed-device"] = managedDevice{
		ID: "managed-device", OwnerSubject: "feidu-user:42", SecretHash: "$2a$10$abcdefghijklmnopqrstuv012345678901234567890123456789012", CredentialVersion: 1,
	}
	s.clients["managed-device"] = &ClientConn{ID: "managed-device", InstanceID: "online"}

	for _, test := range []struct {
		subject string
		want    int
	}{
		{subject: "feidu-user:42", want: http.StatusOK},
		{subject: "feidu-browser:42", want: http.StatusOK},
		{subject: "feidu-browser:7", want: http.StatusForbidden},
		{subject: "feidu-agent-handoff:42", want: http.StatusForbidden},
	} {
		body, err := json.Marshal(accessTicketCreateRequest{
			DeviceID: "managed-device", Subject: test.subject, ExpiresInSecond: 600,
		})
		if err != nil {
			t.Fatalf("encode request: %v", err)
		}
		request := httptest.NewRequest(http.MethodPost, "/api/control/access-tickets", bytes.NewReader(body))
		request.Header.Set("X-RDev-Control-Token", s.ControlToken)
		response := httptest.NewRecorder()
		s.HandleAccessTicketsAPI(response, request)
		if response.Code != test.want {
			t.Fatalf("subject %q status = %d, want %d", test.subject, response.Code, test.want)
		}
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
	s.managedDevices["device"] = managedDevice{ID: "device", OwnerSubject: "feidu-user:42", CredentialVersion: 1}
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

func TestAccessTicketCanBeRevokedByControlAPI(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "one", Password: "device-secret"}
	s.clients[client.ID] = client
	s.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}

	create := httptest.NewRequest(
		http.MethodPost,
		"/api/control/access-tickets",
		strings.NewReader("{\"deviceId\":\"device\",\"subject\":\"feidu-user:42\",\"expiresInSeconds\":600}"),
	)
	create.Header.Set("X-RDev-Control-Token", s.ControlToken)
	created := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(created, create)
	if created.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d", created.Code, http.StatusOK)
	}
	var access accessTicketCreateResponse
	if err := json.Unmarshal(created.Body.Bytes(), &access); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if !s.authorizeDeviceCredential(client, access.Ticket) {
		t.Fatal("fresh ticket was rejected")
	}

	body, err := json.Marshal(accessTicketRevokeRequest{TicketID: access.TicketID})
	if err != nil {
		t.Fatalf("encode revoke request: %v", err)
	}
	revoke := httptest.NewRequest(http.MethodDelete, "/api/control/access-tickets", bytes.NewReader(body))
	revoke.Header.Set("X-RDev-Control-Token", s.ControlToken)
	revoked := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(revoked, revoke)
	if revoked.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d", revoked.Code, http.StatusNoContent)
	}
	if s.authorizeDeviceCredential(client, access.Ticket) {
		t.Fatal("revoked ticket remained valid")
	}

	missing := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(missing, httptest.NewRequest(http.MethodDelete, "/api/control/access-tickets", bytes.NewReader(body)))
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated revoke status = %d, want %d", missing.Code, http.StatusUnauthorized)
	}

	repeated := httptest.NewRequest(http.MethodDelete, "/api/control/access-tickets", bytes.NewReader(body))
	repeated.Header.Set("X-RDev-Control-Token", s.ControlToken)
	repeatedResponse := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(repeatedResponse, repeated)
	if repeatedResponse.Code != http.StatusNoContent {
		t.Fatalf("repeated revoke status = %d, want %d", repeatedResponse.Code, http.StatusNoContent)
	}
}

func TestAccessTicketCanBeRenewedWithoutChangingCredential(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.accessTicketNow = func() time.Time { return now }
	client := &ClientConn{ID: "device", InstanceID: "one", Password: "device-secret"}
	s.clients[client.ID] = client
	s.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}

	ticket := issueAccessTicket(t, s, client.ID, 60)
	var ticketID string
	s.accessTicketMu.Lock()
	for _, stored := range s.accessTickets {
		ticketID = stored.ID
	}
	s.accessTicketMu.Unlock()
	if ticketID == "" {
		t.Fatal("issued ticket id was not stored")
	}

	now = now.Add(30 * time.Second)
	wantExpiry := now.Add(10 * time.Minute)
	body, err := json.Marshal(accessTicketRenewRequest{TicketID: ticketID, ExpiresAtMs: wantExpiry.UnixMilli()})
	if err != nil {
		t.Fatalf("encode renew request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPatch, "/api/control/access-tickets", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("renew status = %d, want %d", response.Code, http.StatusOK)
	}
	var renewed accessTicketRenewResponse
	if err = json.Unmarshal(response.Body.Bytes(), &renewed); err != nil {
		t.Fatalf("decode renew response: %v", err)
	}
	if renewed.TicketID != ticketID || renewed.DeviceID != client.ID || renewed.ExpiresAtMs != wantExpiry.UnixMilli() {
		t.Fatalf("renew response = %#v", renewed)
	}
	shorterExpiry := wantExpiry.Add(-time.Minute)
	shorterBody, err := json.Marshal(accessTicketRenewRequest{TicketID: ticketID, ExpiresAtMs: shorterExpiry.UnixMilli()})
	if err != nil {
		t.Fatalf("encode shorter renew request: %v", err)
	}
	shorterRequest := httptest.NewRequest(http.MethodPatch, "/api/control/access-tickets", bytes.NewReader(shorterBody))
	shorterRequest.Header.Set("X-RDev-Control-Token", s.ControlToken)
	shorterResponse := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(shorterResponse, shorterRequest)
	if shorterResponse.Code != http.StatusOK {
		t.Fatalf("shorter renew status = %d, want %d", shorterResponse.Code, http.StatusOK)
	}
	var notShortened accessTicketRenewResponse
	if err = json.Unmarshal(shorterResponse.Body.Bytes(), &notShortened); err != nil {
		t.Fatalf("decode shorter renew response: %v", err)
	}
	if notShortened.ExpiresAtMs != wantExpiry.UnixMilli() {
		t.Fatalf("shorter renew changed expiry to %d, want %d", notShortened.ExpiresAtMs, wantExpiry.UnixMilli())
	}
	now = now.Add(31 * time.Second)
	if !s.authorizeDeviceCredential(client, ticket) {
		t.Fatal("renewed ticket credential was not valid after its original expiry")
	}
}

func TestAccessTicketSurvivesServerRestartRenewalAndRevocation(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	storePath := t.TempDir() + string(os.PathSeparator) + "access_tickets.json"
	original := NewServer()
	original.ControlToken = "control-secret"
	original.accessTicketNow = func() time.Time { return now }
	if err := original.ConfigureAccessTicketStore(storePath); err != nil {
		t.Fatalf("configure original store: %v", err)
	}
	client := &ClientConn{ID: "device", InstanceID: "instance-one", Password: "device-secret"}
	original.clients[client.ID] = client
	original.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}
	ticketValue := issueAccessTicketWithSubject(t, original, client.ID, "feidu-user:42", 600)
	storedBytes, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read access ticket store: %v", err)
	}
	if bytes.Contains(storedBytes, []byte(ticketValue)) {
		t.Fatal("access ticket store contains the plaintext ticket credential")
	}
	var ticketID string
	for _, ticket := range original.accessTickets {
		ticketID = ticket.ID
	}

	restarted := NewServer()
	restarted.ControlToken = original.ControlToken
	restarted.accessTicketNow = func() time.Time { return now }
	if err := restarted.ConfigureAccessTicketStore(storePath); err != nil {
		t.Fatalf("configure restarted store: %v", err)
	}
	restarted.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}
	restarted.clients[client.ID] = &ClientConn{ID: client.ID, InstanceID: client.InstanceID, Password: client.Password}
	if !restarted.authorizeDeviceCredential(restarted.clients[client.ID], ticketValue) {
		t.Fatal("restarted server rejected the original ticket credential")
	}

	expiresAt := now.Add(time.Hour)
	renewBody, err := json.Marshal(accessTicketRenewRequest{TicketID: ticketID, ExpiresAtMs: expiresAt.UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	renewRequest := httptest.NewRequest(http.MethodPatch, "/api/control/access-tickets", bytes.NewReader(renewBody))
	renewRequest.Header.Set("X-RDev-Control-Token", restarted.ControlToken)
	renewResponse := httptest.NewRecorder()
	restarted.HandleAccessTicketsAPI(renewResponse, renewRequest)
	if renewResponse.Code != http.StatusOK {
		t.Fatalf("renew after restart status = %d, body = %q", renewResponse.Code, renewResponse.Body.String())
	}
	now = now.Add(11 * time.Minute)
	afterRenewRestart := NewServer()
	afterRenewRestart.ControlToken = original.ControlToken
	afterRenewRestart.accessTicketNow = func() time.Time { return now }
	if err = afterRenewRestart.ConfigureAccessTicketStore(storePath); err != nil {
		t.Fatalf("configure post-renew restart store: %v", err)
	}
	afterRenewRestart.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}
	afterRenewRestart.clients[client.ID] = &ClientConn{ID: client.ID, InstanceID: client.InstanceID, Password: client.Password}
	if !afterRenewRestart.authorizeDeviceCredential(afterRenewRestart.clients[client.ID], ticketValue) {
		t.Fatal("persisted renewal did not keep the original ticket valid beyond its first expiry")
	}

	revokeBody, err := json.Marshal(accessTicketRevokeRequest{TicketID: ticketID})
	if err != nil {
		t.Fatal(err)
	}
	revokeRequest := httptest.NewRequest(http.MethodDelete, "/api/control/access-tickets", bytes.NewReader(revokeBody))
	revokeRequest.Header.Set("X-RDev-Control-Token", afterRenewRestart.ControlToken)
	revokeResponse := httptest.NewRecorder()
	afterRenewRestart.HandleAccessTicketsAPI(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusNoContent {
		t.Fatalf("revoke after restart status = %d, body = %q", revokeResponse.Code, revokeResponse.Body.String())
	}

	verified := NewServer()
	verified.accessTicketNow = func() time.Time { return now }
	if err = verified.ConfigureAccessTicketStore(storePath); err != nil {
		t.Fatalf("configure verification store: %v", err)
	}
	verified.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}
	verified.clients[client.ID] = &ClientConn{ID: client.ID, InstanceID: client.InstanceID, Password: client.Password}
	if verified.authorizeDeviceCredential(verified.clients[client.ID], ticketValue) {
		t.Fatal("revoked ticket returned after another server restart")
	}
}

func TestAccessTicketRegistryBrowserCapabilityMigrationAndIsolation(t *testing.T) {
	now := time.Date(2026, 9, 6, 8, 0, 0, 0, time.UTC)
	client := &ClientConn{ID: "browser-registry-device", InstanceID: "instance", Password: "password"}
	ticketValue := "rdvat_browser-registry-ticket"
	ticketHash := sha256.Sum256([]byte(ticketValue))
	baseRecord := accessTicketRegistryRecord{
		TicketHash: fmt.Sprintf("%x", ticketHash[:]), ID: "11111111111111111111111111111111",
		DeviceID: client.ID, DeviceCredentialVersion: 1, InstanceID: client.InstanceID,
		PasswordFingerprint: passwordFingerprint(client.Password), Subject: "feidu-browser:42",
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	writeRegistry := func(t *testing.T, path string, registry accessTicketRegistry) {
		t.Helper()
		data, err := json.MarshalIndent(registry, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, '\n')
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("v2 browser ticket restores only legacy capabilities and writes v3", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "access_tickets.json")
		writeRegistry(t, storePath, accessTicketRegistry{Schema: accessTicketRegistryV2, Tickets: []accessTicketRegistryRecord{baseRecord}})
		s := NewServer()
		s.accessTicketNow = func() time.Time { return now }
		s.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}
		if err := s.ConfigureAccessTicketStore(storePath); err != nil {
			t.Fatal(err)
		}
		for _, capability := range []string{browserCapabilityDesktop, browserCapabilityFiles, browserCapabilityTerminal} {
			if !s.browserAccessTicketValid(ticketValue, client.ID, capability) {
				t.Fatalf("v2 browser ticket did not restore %q capability", capability)
			}
		}
		if s.browserAccessTicketValid(ticketValue, client.ID, browserCapabilityPeripherals) {
			t.Fatal("v2 browser ticket gained the peripherals capability")
		}
		s.accessTicketMu.Lock()
		err := s.persistAccessTicketsLocked()
		s.accessTicketMu.Unlock()
		if err != nil {
			t.Fatalf("persist migrated registry: %v", err)
		}
		stored, err := os.ReadFile(storePath)
		if err != nil {
			t.Fatal(err)
		}
		var rewritten accessTicketRegistry
		if err = json.Unmarshal(stored, &rewritten); err != nil {
			t.Fatal(err)
		}
		if rewritten.Schema != accessTicketRegistryV3 || len(rewritten.Tickets) != 1 {
			t.Fatalf("rewritten registry = %#v", rewritten)
		}
		capabilities := rewritten.Tickets[0].Capabilities
		if len(capabilities) != 3 || capabilities[0] != browserCapabilityDesktop ||
			capabilities[1] != browserCapabilityFiles || capabilities[2] != browserCapabilityTerminal {
			t.Fatalf("rewritten legacy capabilities = %v", capabilities)
		}
	})

	t.Run("v3 single capability remains isolated after restart", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "access_tickets.json")
		record := baseRecord
		record.Capabilities = []string{browserCapabilityPeripherals}
		writeRegistry(t, storePath, accessTicketRegistry{Schema: accessTicketRegistryV3, Tickets: []accessTicketRegistryRecord{record}})
		s := NewServer()
		s.accessTicketNow = func() time.Time { return now }
		s.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}
		if err := s.ConfigureAccessTicketStore(storePath); err != nil {
			t.Fatal(err)
		}
		if !s.browserAccessTicketValid(ticketValue, client.ID, browserCapabilityPeripherals) {
			t.Fatal("v3 peripheral capability was not restored")
		}
		for _, capability := range []string{browserCapabilityDesktop, browserCapabilityFiles, browserCapabilityTerminal} {
			if s.browserAccessTicketValid(ticketValue, client.ID, capability) {
				t.Fatalf("v3 peripheral ticket gained %q capability", capability)
			}
		}
	})

	t.Run("v3 browser ticket requires capabilities", func(t *testing.T) {
		storePath := filepath.Join(t.TempDir(), "access_tickets.json")
		writeRegistry(t, storePath, accessTicketRegistry{Schema: accessTicketRegistryV3, Tickets: []accessTicketRegistryRecord{baseRecord}})
		s := NewServer()
		s.accessTicketNow = func() time.Time { return now }
		if err := s.ConfigureAccessTicketStore(storePath); err == nil || err.Error() != "access ticket store browser capabilities are missing" {
			t.Fatalf("missing v3 capabilities error = %v", err)
		}
	})
}

func TestAccessTicketPersistenceFailureRollsBackMemory(t *testing.T) {
	now := time.Date(2026, 9, 6, 9, 0, 0, 0, time.UTC)
	newServer := func(t *testing.T) (*Server, *ClientConn) {
		t.Helper()
		s := NewServer()
		s.ControlToken = "control-secret"
		s.accessTicketNow = func() time.Time { return now }
		client := &ClientConn{ID: "device", InstanceID: "instance", Password: "password"}
		s.clients[client.ID] = client
		s.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}
		return s, client
	}
	setFailingStore := func(t *testing.T, s *Server) {
		t.Helper()
		storeDirectory := filepath.Join(t.TempDir(), "access-ticket-store-directory")
		if err := os.Mkdir(storeDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		s.accessTicketStorePath = storeDirectory
	}

	t.Run("create", func(t *testing.T) {
		s, client := newServer(t)
		setFailingStore(t, s)
		request := httptest.NewRequest(http.MethodPost, "/api/control/access-tickets", strings.NewReader(
			`{"deviceId":"`+client.ID+`","subject":"feidu-user:42","expiresInSeconds":600}`,
		))
		request.Header.Set("X-RDev-Control-Token", s.ControlToken)
		response := httptest.NewRecorder()
		s.HandleAccessTicketsAPI(response, request)
		if response.Code != http.StatusInternalServerError || len(s.accessTickets) != 0 {
			t.Fatalf("create failure status=%d tickets=%d", response.Code, len(s.accessTickets))
		}
	})

	t.Run("renew", func(t *testing.T) {
		s, client := newServer(t)
		ticketValue := issueAccessTicketWithSubject(t, s, client.ID, "feidu-user:42", 600)
		ticketHash := sha256.Sum256([]byte(ticketValue))
		originalExpiry := s.accessTickets[ticketHash].ExpiresAt
		expiredHash := sha256.Sum256([]byte("rdvat_expired-rollback-ticket"))
		s.accessTickets[expiredHash] = accessTicket{
			ID: "22222222222222222222222222222222", DeviceID: client.ID,
			DeviceCredentialVersion: 1, InstanceID: client.InstanceID,
			PasswordFingerprint: passwordFingerprint(client.Password), Subject: "feidu-user:42", ExpiresAt: now.Add(-time.Minute),
		}
		setFailingStore(t, s)
		body, err := json.Marshal(accessTicketRenewRequest{
			TicketID: s.accessTickets[ticketHash].ID, ExpiresAtMs: now.Add(time.Hour).UnixMilli(),
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPatch, "/api/control/access-tickets", bytes.NewReader(body))
		request.Header.Set("X-RDev-Control-Token", s.ControlToken)
		response := httptest.NewRecorder()
		s.HandleAccessTicketsAPI(response, request)
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("renew failure status = %d", response.Code)
		}
		if got := s.accessTickets[ticketHash].ExpiresAt; !got.Equal(originalExpiry) {
			t.Fatalf("renew failure retained expiry %s, want %s", got, originalExpiry)
		}
		if _, exists := s.accessTickets[expiredHash]; !exists {
			t.Fatal("renew failure did not restore the pruned expired ticket")
		}
	})

	t.Run("revoke", func(t *testing.T) {
		s, client := newServer(t)
		ticketValue := issueAccessTicketWithSubject(t, s, client.ID, "feidu-user:42", 600)
		ticketHash := sha256.Sum256([]byte(ticketValue))
		setFailingStore(t, s)
		body, err := json.Marshal(accessTicketRevokeRequest{TicketID: s.accessTickets[ticketHash].ID})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodDelete, "/api/control/access-tickets", bytes.NewReader(body))
		request.Header.Set("X-RDev-Control-Token", s.ControlToken)
		response := httptest.NewRecorder()
		s.HandleAccessTicketsAPI(response, request)
		if response.Code != http.StatusInternalServerError || !s.authorizeDeviceCredential(client, ticketValue) {
			t.Fatalf("revoke failure status=%d ticket_valid=%t", response.Code, s.authorizeDeviceCredential(client, ticketValue))
		}
	})
}

func TestAccessTicketRegistryV1IsCompatibleOnlyWithInitialDeviceCredentialVersion(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 15, 0, 0, time.UTC)
	storePath := t.TempDir() + string(os.PathSeparator) + "access_tickets.json"
	ticketValue := "rdvat_legacy-registry-ticket"
	ticketHash := sha256.Sum256([]byte(ticketValue))
	client := &ClientConn{ID: "legacy-ticket-device", InstanceID: "legacy-instance", Password: "legacy-password"}
	legacy := accessTicketRegistry{
		Schema: accessTicketRegistryV1,
		Tickets: []accessTicketRegistryRecord{{
			TicketHash: fmt.Sprintf("%x", ticketHash[:]), ID: "11111111111111111111111111111111",
			DeviceID: client.ID, InstanceID: client.InstanceID, PasswordFingerprint: passwordFingerprint(client.Password),
			Subject: "feidu-user:42", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		}},
	}
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err = os.WriteFile(storePath, data, 0600); err != nil {
		t.Fatal(err)
	}

	s := NewServer()
	s.accessTicketNow = func() time.Time { return now }
	s.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}
	if err = s.ConfigureAccessTicketStore(storePath); err != nil {
		t.Fatal(err)
	}
	if !s.accessTicketValid(client, ticketValue) {
		t.Fatal("initial device credential version rejected a legacy ticket")
	}
	device := s.managedDevices[client.ID]
	device.CredentialVersion = 2
	s.managedDevices[client.ID] = device
	if s.accessTicketValid(client, ticketValue) {
		t.Fatal("new device credential version accepted a legacy ticket")
	}
}

func TestManagedReconnectRebindsTicketOnlyWhenPreviousInstanceIsOffline(t *testing.T) {
	s := NewServer()
	client := &ClientConn{ID: "device", InstanceID: "instance-one", Password: "device-secret"}
	s.clients[client.ID] = client
	ticketValue := issueAccessTicket(t, s, client.ID, 600)

	if err := s.rebindManagedAccessTickets(client.ID, "instance-two", passwordFingerprint(client.Password)); err != nil {
		t.Fatalf("rebind while connected: %v", err)
	}
	replacement := &ClientConn{ID: client.ID, InstanceID: "instance-two", Password: client.Password}
	if s.authorizeDeviceCredential(replacement, ticketValue) {
		t.Fatal("ticket moved while its original instance was still connected")
	}

	delete(s.clients, client.ID)
	if err := s.rebindManagedAccessTickets(client.ID, replacement.InstanceID, passwordFingerprint(replacement.Password)); err != nil {
		t.Fatalf("rebind after disconnect: %v", err)
	}
	if !s.authorizeDeviceCredential(replacement, ticketValue) {
		t.Fatal("ticket did not follow an authenticated managed-device reconnect")
	}
}

func TestAuthenticatedManagedRegistrationRebindsTicketWhilePreviousInstanceIsOnline(t *testing.T) {
	s := NewServer()
	secretHash, err := bcrypt.GenerateFromPassword([]byte("device-secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	s.managedDevices["device"] = managedDevice{
		ID: "device", OwnerSubject: "feidu-user:42", SecretHash: string(secretHash), CredentialVersion: 1,
	}
	oldClient := &ClientConn{ID: "device", RequestedID: "device", InstanceID: "instance-one", Managed: true}
	s.clients[oldClient.ID] = oldClient
	ticketValue := issueAccessTicket(t, s, oldClient.ID, 600)

	newClient := &ClientConn{ID: "device", RequestedID: "device", InstanceID: "instance-two", Managed: true}
	old, assignedID, duplicate, authorizationCurrent, registerErr := s.registerClientIfAuthorizationCurrent(newClient, "device-secret")
	if registerErr != nil {
		t.Fatalf("managed registration: %v", registerErr)
	}
	if !authorizationCurrent || old != oldClient || assignedID != "device" || duplicate {
		t.Fatalf("managed registration = (%#v, %q, %v, %v), want old client, device, false, true", old, assignedID, duplicate, authorizationCurrent)
	}
	if !s.accessTicketValid(newClient, ticketValue) {
		t.Fatal("ticket did not follow an authenticated managed-device replacement")
	}
	if s.accessTicketValid(oldClient, ticketValue) {
		t.Fatal("ticket remained bound to the replaced managed-device instance")
	}
}

func TestAccessTicketRenewRejectsMissingTicket(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	expiresAt := time.Now().UTC().Truncate(time.Second).Add(10 * time.Minute)
	body, err := json.Marshal(accessTicketRenewRequest{TicketID: strings.Repeat("0", 32), ExpiresAtMs: expiresAt.UnixMilli()})
	if err != nil {
		t.Fatalf("encode renew request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPatch, "/api/control/access-tickets", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", s.ControlToken)
	response := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("renew missing status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestAccessTicketRenewRejectsInvalidRequests(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.accessTicketNow = func() time.Time { return now }
	s.clients["device"] = &ClientConn{ID: "device", InstanceID: "one"}
	issueAccessTicket(t, s, "device", 600)
	var ticketID string
	s.accessTicketMu.Lock()
	for _, stored := range s.accessTickets {
		ticketID = stored.ID
	}
	s.accessTicketMu.Unlock()
	validExpiry := now.Add(10 * time.Minute).UnixMilli()
	tests := []struct {
		name string
		body string
	}{
		{name: "unknown field", body: fmt.Sprintf(`{"ticketId":%q,"expiresAtMs":%d,"extra":true}`, ticketID, validExpiry)},
		{name: "trailing JSON", body: fmt.Sprintf(`{"ticketId":%q,"expiresAtMs":%d}{}`, ticketID, validExpiry)},
		{name: "uppercase ticket id", body: fmt.Sprintf(`{"ticketId":%q,"expiresAtMs":%d}`, strings.Repeat("A", 32), validExpiry)},
		{name: "non-second expiry", body: fmt.Sprintf(`{"ticketId":%q,"expiresAtMs":%d}`, ticketID, now.Add(10*time.Minute+time.Millisecond).UnixMilli())},
		{name: "short lifetime", body: fmt.Sprintf(`{"ticketId":%q,"expiresAtMs":%d}`, ticketID, now.Add(59*time.Second).UnixMilli())},
		{name: "long lifetime", body: fmt.Sprintf(`{"ticketId":%q,"expiresAtMs":%d}`, ticketID, now.Add(8*time.Hour+time.Second).UnixMilli())},
		{name: "past expiry", body: fmt.Sprintf(`{"ticketId":%q,"expiresAtMs":%d}`, ticketID, now.Add(-time.Second).UnixMilli())},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPatch, "/api/control/access-tickets", strings.NewReader(test.body))
			request.Header.Set("X-RDev-Control-Token", s.ControlToken)
			response := httptest.NewRecorder()
			s.HandleAccessTicketsAPI(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestAccessTicketRenewAndRevokeRaceEndsRevoked(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	s := NewServer()
	s.ControlToken = "control-secret"
	s.accessTicketNow = func() time.Time { return now }
	client := &ClientConn{ID: "device", InstanceID: "one"}
	s.clients[client.ID] = client
	ticketValue := issueAccessTicket(t, s, client.ID, 600)
	var ticketID string
	s.accessTicketMu.Lock()
	for _, stored := range s.accessTickets {
		ticketID = stored.ID
	}
	s.accessTicketMu.Unlock()
	renewBody, err := json.Marshal(accessTicketRenewRequest{TicketID: ticketID, ExpiresAtMs: now.Add(time.Hour).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	revokeBody, err := json.Marshal(accessTicketRevokeRequest{TicketID: ticketID})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	statuses := make(chan int, 2)
	var workers sync.WaitGroup
	for _, operation := range []struct {
		method string
		body   []byte
	}{
		{method: http.MethodPatch, body: renewBody},
		{method: http.MethodDelete, body: revokeBody},
	} {
		workers.Add(1)
		go func(operation struct {
			method string
			body   []byte
		}) {
			defer workers.Done()
			<-start
			request := httptest.NewRequest(operation.method, "/api/control/access-tickets", bytes.NewReader(operation.body))
			request.Header.Set("X-RDev-Control-Token", s.ControlToken)
			response := httptest.NewRecorder()
			s.HandleAccessTicketsAPI(response, request)
			statuses <- response.Code
		}(operation)
	}
	close(start)
	workers.Wait()
	close(statuses)
	seenRevoke := false
	for status := range statuses {
		if status == http.StatusNoContent {
			seenRevoke = true
			continue
		}
		if status != http.StatusOK && status != http.StatusNotFound {
			t.Fatalf("unexpected concurrent status %d", status)
		}
	}
	if !seenRevoke || s.authorizeDeviceCredential(client, ticketValue) {
		t.Fatal("concurrent revoke did not leave the ticket revoked")
	}
}

func TestAccessTicketRenewRejectsExpiredAndRevokedTickets(t *testing.T) {
	for _, test := range []struct {
		name   string
		revoke bool
	}{
		{name: "expired"},
		{name: "revoked", revoke: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
			s := NewServer()
			s.ControlToken = "control-secret"
			s.accessTicketNow = func() time.Time { return now }
			s.clients["device"] = &ClientConn{ID: "device", InstanceID: "one"}
			issueAccessTicket(t, s, "device", 60)
			var ticketID string
			s.accessTicketMu.Lock()
			for _, stored := range s.accessTickets {
				ticketID = stored.ID
			}
			s.accessTicketMu.Unlock()
			if test.revoke {
				body, err := json.Marshal(accessTicketRevokeRequest{TicketID: ticketID})
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodDelete, "/api/control/access-tickets", bytes.NewReader(body))
				request.Header.Set("X-RDev-Control-Token", s.ControlToken)
				response := httptest.NewRecorder()
				s.HandleAccessTicketsAPI(response, request)
				if response.Code != http.StatusNoContent {
					t.Fatalf("revoke status = %d", response.Code)
				}
			} else {
				now = now.Add(61 * time.Second)
			}
			body, err := json.Marshal(accessTicketRenewRequest{TicketID: ticketID, ExpiresAtMs: now.Add(10 * time.Minute).UnixMilli()})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPatch, "/api/control/access-tickets", bytes.NewReader(body))
			request.Header.Set("X-RDev-Control-Token", s.ControlToken)
			response := httptest.NewRecorder()
			s.HandleAccessTicketsAPI(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("renew status = %d, want %d", response.Code, http.StatusNotFound)
			}
		})
	}
}

func TestAccessTicketRevokeHookRunsOnlyForExistingTicket(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "one", Password: "device-secret"}
	s.clients[client.ID] = client
	s.managedDevices[client.ID] = managedDevice{ID: client.ID, OwnerSubject: "feidu-user:42", CredentialVersion: 1}
	revokedTicketIDs := make([]string, 0, 1)
	s.accessTicketRevoked = func(ticketID string) {
		revokedTicketIDs = append(revokedTicketIDs, ticketID)
	}

	create := httptest.NewRequest(
		http.MethodPost,
		"/api/control/access-tickets",
		strings.NewReader("{\"deviceId\":\"device\",\"subject\":\"feidu-browser:42\",\"expiresInSeconds\":600}"),
	)
	create.Header.Set("X-RDev-Control-Token", s.ControlToken)
	created := httptest.NewRecorder()
	s.HandleAccessTicketsAPI(created, create)
	if created.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d", created.Code, http.StatusOK)
	}
	var access accessTicketCreateResponse
	if err := json.Unmarshal(created.Body.Bytes(), &access); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	body, err := json.Marshal(accessTicketRevokeRequest{TicketID: access.TicketID})
	if err != nil {
		t.Fatalf("encode revoke request: %v", err)
	}
	for range 2 {
		request := httptest.NewRequest(http.MethodDelete, "/api/control/access-tickets", bytes.NewReader(body))
		request.Header.Set("X-RDev-Control-Token", s.ControlToken)
		response := httptest.NewRecorder()
		s.HandleAccessTicketsAPI(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("revoke status = %d, want %d", response.Code, http.StatusNoContent)
		}
	}
	if len(revokedTicketIDs) != 1 || revokedTicketIDs[0] != access.TicketID {
		t.Fatalf("revoke hook ticket ids = %v, want [%s]", revokedTicketIDs, access.TicketID)
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
	return issueScopedAccessTicketWithSubject(t, s, deviceID, subject, lifetimeSeconds, nil)
}

func issueScopedAccessTicketWithSubject(t *testing.T, s *Server, deviceID, subject string, lifetimeSeconds int64, capabilities []string) string {
	t.Helper()
	device := s.managedDevices[deviceID]
	device.ID = deviceID
	device.OwnerSubject = subject
	if device.CredentialVersion == 0 {
		device.CredentialVersion = 1
	}
	s.managedDevices[deviceID] = device
	body, err := json.Marshal(accessTicketCreateRequest{
		DeviceID:        deviceID,
		Subject:         subject,
		ExpiresInSecond: lifetimeSeconds,
		Capabilities:    capabilities,
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
