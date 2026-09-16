package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lxzan/gws"
	gossh "golang.org/x/crypto/ssh"
	"rdev/internal/protocol"
)

type maintenanceBrowserCapture struct {
	gws.BuiltinEventHandler
	text   chan json.RawMessage
	binary chan []byte
	closed chan struct{}
	once   sync.Once
}

func (c *maintenanceBrowserCapture) OnMessage(_ *gws.Conn, m *gws.Message) {
	defer m.Close()
	data := append([]byte(nil), m.Bytes()...)
	if m.Opcode == gws.OpcodeText {
		c.text <- data
	} else if m.Opcode == gws.OpcodeBinary {
		c.binary <- data
	}
}

func (c *maintenanceBrowserCapture) OnClose(*gws.Conn, error) { c.once.Do(func() { close(c.closed) }) }

func maintenanceBrowserConnect(t *testing.T, endpoint, token string) (*gws.Conn, *maintenanceBrowserCapture) {
	t.Helper()
	capture := &maintenanceBrowserCapture{text: make(chan json.RawMessage, 16), binary: make(chan []byte, 16), closed: make(chan struct{})}
	header := make(http.Header)
	header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+token)
	socket, response, err := gws.NewClient(capture, &gws.ClientOption{Addr: endpoint, RequestHeader: header})
	if err != nil {
		t.Fatalf("connect fixed-token browser: %v", err)
	}
	if got := response.Header.Get("Sec-WebSocket-Protocol"); got != browserSocketProtocol {
		t.Fatalf("selected browser protocol = %q", got)
	}
	go socket.ReadLoop()
	t.Cleanup(func() { _ = socket.WriteClose(1000, nil) })
	return socket, capture
}

func maintenanceBrowserWrite(t *testing.T, socket *gws.Conn, body any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err = socket.WriteMessage(gws.OpcodeText, data); err != nil {
		t.Fatal(err)
	}
}

func maintenanceBrowserWait(t *testing.T, capture *maintenanceBrowserCapture, wantOp string) json.RawMessage {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case data := <-capture.text:
			var msg struct {
				Op string `json:"op"`
			}
			if err := json.Unmarshal(data, &msg); err != nil {
				t.Fatal(err)
			}
			if msg.Op == wantOp {
				return data
			}
			if msg.Op == "error" || msg.Op == "auth_fail" {
				t.Fatalf("browser received %s while waiting for %s", msg.Op, wantOp)
			}
		case <-capture.closed:
			t.Fatalf("browser closed while waiting for %s", wantOp)
		case <-deadline:
			t.Fatalf("timed out waiting for browser %s", wantOp)
		}
	}
}

func maintenanceOnlineClient(t *testing.T, s *Server, name string) (*ClientConn, *peripheralServerCaptureTransport) {
	t.Helper()
	deviceID := maintenanceTestDevice(t, s, name)
	transport := newPeripheralServerCaptureTransport()
	client := &ClientConn{ID: deviceID, InstanceID: "instance-" + deviceID, Transport: transport, PeripheralV1: true, Sessions: make(map[string]*ProxySession), Forwards: make(map[string]*ProxyForward)}
	s.clients[deviceID] = client
	return client, transport
}

func TestMaintenanceTokenBrowserHandshakeAllCapabilities(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	client, _ := maintenanceOnlineClient(t, s, "browser")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, client.ID, grant)
	for _, test := range []struct {
		path    string
		handler http.HandlerFunc
	}{
		{"/terminal", s.HandleTerminalWS}, {"/files", s.HandleFilesWS},
		{"/desktop", s.HandleDesktopWS}, {"/peripherals", s.HandlePeripheralsWS},
	} {
		t.Run(test.path, func(t *testing.T) {
			httpServer := httptest.NewServer(test.handler)
			defer httpServer.Close()
			endpoint := "ws" + strings.TrimPrefix(httpServer.URL, "http") + test.path + "?device=" + url.QueryEscape(client.ID)
			socket, _ := maintenanceBrowserConnect(t, endpoint, token)
			_ = socket.WriteClose(1000, nil)
		})
	}
	grant.Generation++
	grant.Capabilities = []string{"ssh"}
	maintenanceTestInstall(t, s, client.ID, grant)
	for _, path := range []string{"/terminal", "/files", "/desktop", "/peripherals"} {
		request := httptest.NewRequest(http.MethodGet, path+"?device="+url.QueryEscape(client.ID), nil)
		request.Header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+token)
		if s.browserSocketAuthOK(request) {
			t.Fatalf("SSH-only token authorized browser %s", path)
		}
		if _, ok := s.authorizeBrowserDeviceCredentialBinding(client, token, strings.TrimPrefix(path, "/")); ok {
			t.Fatalf("SSH-only token authorized browser message for %s", path)
		}
	}
}

func TestMaintenanceTokenTerminalAndFilesRoundTripThenRevocation(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	client, device := maintenanceOnlineClient(t, s, "roundtrip")
	other, _ := maintenanceOnlineClient(t, s, "other-device")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, client.ID, grant)
	mux := http.NewServeMux()
	mux.HandleFunc("/terminal", s.HandleTerminalWS)
	mux.HandleFunc("/files", s.HandleFilesWS)
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	base := "ws" + strings.TrimPrefix(httpServer.URL, "http")
	terminal, terminalCapture := maintenanceBrowserConnect(t, base+"/terminal?device="+url.QueryEscape(client.ID), token)
	maintenanceBrowserWait(t, terminalCapture, "auth")
	maintenanceBrowserWrite(t, terminal, terminalMsg{Op: "auth", Password: token})
	maintenanceBrowserWait(t, terminalCapture, "auth_ok")
	newSession := waitPeripheralDeviceMessage(t, device, protocol.MsgNewSession)
	if !newSession.Pty {
		t.Fatal("terminal session did not request PTY")
	}
	// Retrying an acknowledged control update must not interrupt ongoing work.
	maintenanceTestInstall(t, s, client.ID, grant)
	if err := terminal.WriteMessage(gws.OpcodeBinary, []byte("terminal-input")); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-device.binaryCh:
		typ, sessionID, payload, err := protocol.DecodeBinFrame(frame)
		if err != nil || typ != protocol.BinData || sessionID != newSession.SessionID || string(payload) != "terminal-input" {
			t.Fatal("terminal input was not routed to authorized device session")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("terminal input did not reach device")
	}
	s.handleClientBinary(client, protocol.EncodeBinFrame(protocol.BinData, newSession.SessionID, []byte("terminal-output")))
	select {
	case output := <-terminalCapture.binary:
		if string(output) != "terminal-output" {
			t.Fatal("terminal output changed in transit")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("terminal output did not reach browser")
	}
	files, fileCapture := maintenanceBrowserConnect(t, base+"/files?device="+url.QueryEscape(client.ID), token)
	maintenanceBrowserWrite(t, files, fileMsg{Op: "auth", DeviceID: other.ID, Password: token})
	maintenanceBrowserWait(t, fileCapture, "auth_fail")
	maintenanceBrowserWrite(t, files, fileMsg{Op: "auth", DeviceID: client.ID, Password: token})
	maintenanceBrowserWait(t, fileCapture, "auth_ok")
	maintenanceBrowserWrite(t, files, fileMsg{Op: "list", DeviceID: client.ID, RequestID: "maintenance-list", Path: "/fixture"})
	list := waitPeripheralDeviceMessage(t, device, protocol.MsgFileListRequest)
	if list.Path != "/fixture" {
		t.Fatalf("list path = %q", list.Path)
	}
	s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgFileListResult, RequestID: list.RequestID, Success: true, Path: list.Path, FileEntries: []protocol.FileEntry{{Name: "evidence.txt", Size: 17}}})
	var listed fileMsg
	if err := json.Unmarshal(maintenanceBrowserWait(t, fileCapture, "list_result"), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Entries) != 1 || listed.Entries[0].Name != "evidence.txt" {
		t.Fatal("file listing did not complete through the authorized browser channel")
	}
	grant.Generation++
	grant.Revoked = true
	maintenanceTestInstall(t, s, client.ID, grant)
	for name, capture := range map[string]*maintenanceBrowserCapture{"terminal": terminalCapture, "files": fileCapture} {
		select {
		case <-capture.closed:
		case <-time.After(3 * time.Second):
			t.Fatalf("revocation left active %s channel open", name)
		}
	}
}

func TestMaintenanceTokenSSHCapabilityDoesNotBypassBrowserMessageScope(t *testing.T) {
	for _, capability := range []string{"terminal", "files"} {
		t.Run(capability, func(t *testing.T) {
			s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
			client, _ := maintenanceOnlineClient(t, s, "scope")
			token, grant := maintenanceTestRandom(t)
			grant.Capabilities = []string{"ssh"}
			maintenanceTestInstall(t, s, client.ID, grant)
			// Enter via the compatible legacy browser handshake, then attempt the
			// message authentication with a fixed token lacking this capability.
			body, err := json.Marshal(accessTicketCreateRequest{DeviceID: client.ID, Subject: "feidu-browser:42", ExpiresInSecond: 60, Capabilities: []string{capability}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/control/access-tickets", bytes.NewReader(body))
			request.Header.Set("X-RDev-Control-Token", s.ControlToken)
			response := httptest.NewRecorder()
			s.HandleAccessTicketsAPI(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("legacy browser setup status = %d", response.Code)
			}
			var ticket accessTicketCreateResponse
			if err = json.Unmarshal(response.Body.Bytes(), &ticket); err != nil {
				t.Fatal(err)
			}
			handler := s.HandleTerminalWS
			if capability == "files" {
				handler = s.HandleFilesWS
			}
			httpServer := httptest.NewServer(http.HandlerFunc(handler))
			defer httpServer.Close()
			browser, capture := maintenanceBrowserConnect(t, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/"+capability+"?device="+url.QueryEscape(client.ID), ticket.Ticket)
			if capability == "terminal" {
				maintenanceBrowserWait(t, capture, "auth")
			}
			maintenanceBrowserWrite(t, browser, fileMsg{Op: "auth", DeviceID: client.ID, Password: token})
			maintenanceBrowserWait(t, capture, "auth_fail")
		})
	}
}

func TestMaintenanceTokenRealSSHExecAndSFTPChannelThenRevocation(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	client, device := maintenanceOnlineClient(t, s, "ssh")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, client.ID, grant)
	sshServer, err := NewSSHServer(s, "127.0.0.1:0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = sshServer.server.Serve(listener) }()
	t.Cleanup(func() { _ = sshServer.server.Close(); _ = listener.Close() })
	connection, err := gossh.Dial("tcp", listener.Addr().String(), &gossh.ClientConfig{User: client.ID, Auth: []gossh.AuthMethod{gossh.Password(token)}, HostKeyCallback: gossh.FixedHostKey(sshServer.hostKey.PublicKey()), Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("fixed-token SSH handshake: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	exec, err := connection.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer exec.Close()
	var output bytes.Buffer
	exec.Stdout = &output
	if err = exec.Start("fixture-command"); err != nil {
		t.Fatal(err)
	}
	request := waitPeripheralDeviceMessage(t, device, protocol.MsgNewSession)
	if request.Command != "fixture-command" || request.Subsystem != "" {
		t.Fatal("SSH exec was not routed intact")
	}
	s.handleClientBinary(client, protocol.EncodeBinFrame(protocol.BinData, request.SessionID, []byte("exec-result")))
	s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgExitCode, SessionID: request.SessionID, ExitCode: 0})
	s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgClose, SessionID: request.SessionID})
	completed := make(chan error, 1)
	go func() { completed <- exec.Wait() }()
	select {
	case err = <-completed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SSH exec did not complete")
	}
	if output.String() != "exec-result" {
		t.Fatal("SSH exec output changed in transit")
	}
	// Check the actual SSH subsystem and binary channel used by SFTP. The fixture
	// supplies the device side; a separate end-to-end deployment must verify disk I/O.
	sftp, err := connection.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sftp.Close()
	stdin, err := sftp.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := sftp.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = sftp.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	request = waitPeripheralDeviceMessage(t, device, protocol.MsgNewSession)
	if request.Subsystem != "sftp" || request.Pty {
		t.Fatal("SFTP subsystem was not routed intact")
	}
	initPacket := []byte{0, 0, 0, 5, 1, 0, 0, 0, 3}
	if _, err = stdin.Write(initPacket); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-device.binaryCh:
		typ, id, packet, decodeErr := protocol.DecodeBinFrame(frame)
		if decodeErr != nil || typ != protocol.BinData || id != request.SessionID || !bytes.Equal(packet, initPacket) {
			t.Fatal("SFTP initialization was not routed intact")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SFTP request did not reach device")
	}
	versionPacket := []byte{0, 0, 0, 5, 2, 0, 0, 0, 3}
	s.handleClientBinary(client, protocol.EncodeBinFrame(protocol.BinData, request.SessionID, versionPacket))
	readResult := make(chan error, 1)
	got := make([]byte, len(versionPacket))
	go func() { _, readErr := io.ReadFull(stdout, got); readResult <- readErr }()
	select {
	case err = <-readResult:
		if err != nil || !bytes.Equal(got, versionPacket) {
			t.Fatal("SFTP response did not reach SSH client")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SFTP response stalled")
	}
	closed := make(chan error, 1)
	go func() { closed <- connection.Wait() }()
	grant.Generation++
	grant.Revoked = true
	maintenanceTestInstall(t, s, client.ID, grant)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("revocation left active SSH/SFTP connection open")
	}
}
