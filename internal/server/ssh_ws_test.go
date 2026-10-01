package server

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lxzan/gws"
	gossh "golang.org/x/crypto/ssh"
	"rdev/internal/protocol"
)

func sshWSTestServer(t *testing.T) (*Server, *SSHServer, *ClientConn, *peripheralServerCaptureTransport, string, maintenanceTestGrant) {
	t.Helper()
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	client, device := maintenanceOnlineClient(t, s, "ssh-ws")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, client.ID, grant)
	server, err := NewSSHServer(s, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return s, server, client, device, token, grant
}

func sshWSHeader(token string) http.Header {
	h := make(http.Header)
	h.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+token)
	h.Set("Connection", "Upgrade")
	h.Set("Upgrade", "websocket")
	return h
}

func TestSSHWSAuthorization(t *testing.T) {
	s, server, client, _, token, grant := sshWSTestServer(t)
	for _, tc := range []struct {
		name, query, credential string
		allowed                 bool
	}{
		{"valid", "device=" + url.QueryEscape(client.ID), token, true},
		{"wrong device", "device=other", token, false},
		{"missing", "", token, false},
		{"duplicate", "device=a&device=b", token, false},
		{"url credential", "device=" + url.QueryEscape(client.ID) + "&token=secret", token, false},
		{"malformed", "device=%xx", token, false},
		{"wrong credential", "device=" + url.QueryEscape(client.ID), "invalid", false},
		{"device password", "device=" + url.QueryEscape(client.ID), client.Password, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/ssh-ws?"+tc.query, nil)
			r.Header = sshWSHeader(tc.credential)
			_, ok := server.webSocketAuthorization(r)
			if ok != tc.allowed {
				t.Fatalf("authorized=%v", ok)
			}
		})
	}
	r := httptest.NewRequest("GET", "/ssh-ws?device="+url.QueryEscape(client.ID), nil)
	r.Header = sshWSHeader(token)
	r.Header.Add("Sec-WebSocket-Protocol", browserTicketProtocol+token)
	if _, ok := server.webSocketAuthorization(r); ok {
		t.Fatal("duplicate credential accepted")
	}
	r.Header.Set("Sec-WebSocket-Protocol", browserTicketProtocol+token)
	if _, ok := server.webSocketAuthorization(r); ok {
		t.Fatal("missing protocol accepted")
	}
	grant.Generation++
	grant.Capabilities = []string{"terminal", "files"}
	maintenanceTestInstall(t, s, client.ID, grant)
	r.Header = sshWSHeader(token)
	if _, ok := server.webSocketAuthorization(r); ok {
		t.Fatal("terminal capability accepted as ssh")
	}
	recorder := httptest.NewRecorder()
	server.HandleWebSocket(recorder, r)
	if recorder.Code != 401 {
		t.Fatalf("status=%d", recorder.Code)
	}
}

// Exercise binary framing with an actual SSH handshake, not a JSON terminal.
func sshWSDial(t *testing.T, endpoint, token string) net.Conn {
	t.Helper()
	bridge, sshConn := net.Pipe()
	handler := &sshWSBridge{pipe: bridge, idle: time.Second * 5, write: time.Second}
	ws, response, err := gws.NewClient(handler, &gws.ClientOption{Addr: endpoint, RequestHeader: sshWSHeader(token)})
	if err != nil {
		t.Fatal("websocket connection failed")
	}
	if response.Header.Get("Sec-WebSocket-Protocol") != browserSocketProtocol {
		t.Fatal("secret protocol reflected")
	}
	go handler.pump(ws)
	go ws.ReadLoop()
	t.Cleanup(func() { _ = sshConn.Close(); _ = bridge.Close(); _ = ws.NetConn().Close() })
	return sshConn
}

func TestSSHWSExecBinaryStdinEOFForwardingAndRevocation(t *testing.T) {
	s, server, client, device, token, grant := sshWSTestServer(t)
	httpServer := httptest.NewServer(http.HandlerFunc(server.HandleWebSocket))
	defer httpServer.Close()
	endpoint := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ssh-ws?device=" + url.QueryEscape(client.ID)
	raw := sshWSDial(t, endpoint, token)
	conn, channels, requests, err := gossh.NewClientConn(raw, "test", &gossh.ClientConfig{
		User: client.ID, HostKeyCallback: gossh.FixedHostKey(server.hostKey.PublicKey()),
		Timeout: time.Second * 3, // No SSH password: WSS authenticates the connection.
	})
	if err != nil {
		t.Fatal(err)
	}
	sshClient := gossh.NewClient(conn, channels, requests)
	defer sshClient.Close()
	if forwarded, err := sshClient.Dial("tcp", "127.0.0.1:22"); err == nil {
		forwarded.Close()
		t.Fatal("local forwarding accepted")
	}
	if listener, err := sshClient.Listen("tcp", "127.0.0.1:0"); err == nil {
		listener.Close()
		t.Fatal("remote forwarding accepted")
	}
	exec, err := sshClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer exec.Close()
	stdin, _ := exec.StdinPipe()
	var output bytes.Buffer
	exec.Stdout = &output
	if err = exec.Start("unique-fixture-command"); err != nil {
		t.Fatal(err)
	}
	request := waitPeripheralDeviceMessage(t, device, protocol.MsgNewSession)
	if request.Command != "unique-fixture-command" {
		t.Fatal("wrong command")
	}
	payload := []byte{0, 1, 2, 255, 13, 10, 0}
	if _, err = stdin.Write(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-device.binaryCh:
		_, id, data, err := protocol.DecodeBinFrame(frame)
		if err != nil || id != request.SessionID || !bytes.Equal(data, payload) {
			t.Fatal("input bytes changed")
		}
	case <-time.After(time.Second * 3):
		t.Fatal("input stalled")
	}
	_ = stdin.Close()
	waitPeripheralDeviceMessage(t, device, protocol.MsgStdinClose)
	// The SSH channel's write EOF must not prevent later output or exit status.
	s.handleClientBinary(client, protocol.EncodeBinFrame(protocol.BinData, request.SessionID, payload))
	s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgExitCode, SessionID: request.SessionID, ExitCode: 23})
	s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgClose, SessionID: request.SessionID})
	err = exec.Wait()
	if exit, ok := err.(*gossh.ExitError); !ok || exit.ExitStatus() != 23 {
		t.Fatalf("exit: %v", err)
	}
	if !bytes.Equal(output.Bytes(), payload) {
		t.Fatal("output bytes changed")
	}
	subsystem, err := sshClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer subsystem.Close()
	if err = subsystem.RequestSubsystem("sftp"); err != nil {
		t.Fatal(err)
	}
	request = waitPeripheralDeviceMessage(t, device, protocol.MsgNewSession)
	if request.Subsystem != "sftp" || request.Pty {
		t.Fatal("invalid subsystem")
	}
	grant.Generation++
	grant.Revoked = true
	maintenanceTestInstall(t, s, client.ID, grant)
	closed := make(chan error, 1)
	go func() { closed <- sshClient.Wait() }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("revocation did not close WSS")
	}
}

func TestSSHWSWrongSSHUsername(t *testing.T) {
	_, server, client, _, token, _ := sshWSTestServer(t)
	httpServer := httptest.NewServer(http.HandlerFunc(server.HandleWebSocket))
	defer httpServer.Close()
	raw := sshWSDial(t, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/ssh-ws?device="+url.QueryEscape(client.ID), token)
	conn, _, _, err := gossh.NewClientConn(raw, "test", &gossh.ClientConfig{User: "other", HostKeyCallback: gossh.FixedHostKey(server.hostKey.PublicKey())})
	if err == nil {
		conn.Close()
		t.Fatal("changed username accepted")
	}
}

func TestSSHWSTicketExpiryAndBrowserScope(t *testing.T) {
	s, server, client, _, _, _ := sshWSTestServer(t)
	ticket := issueAccessTicketWithSubject(t, s, client.ID, "feidu-user:42", 60)
	r := httptest.NewRequest("GET", "/ssh-ws?device="+url.QueryEscape(client.ID), nil)
	r.Header = sshWSHeader(ticket)
	auth, ok := server.webSocketAuthorization(r)
	if !ok || auth.TicketID == "" {
		t.Fatal("delegated ticket rejected")
	}
	s.accessTicketNow = func() time.Time { return time.Now().Add(61 * time.Second) }
	if _, ok = server.webSocketAuthorization(r); ok {
		t.Fatal("expired ticket accepted")
	}
	s.accessTicketNow = nil
	browser := issueScopedAccessTicketWithSubject(t, s, client.ID, "feidu-browser:42", 60, []string{"terminal"})
	r.Header = sshWSHeader(browser)
	if _, ok = server.webSocketAuthorization(r); ok {
		t.Fatal("browser ticket accepted")
	}
}

func TestSSHWSHandshakeTimeout(t *testing.T) {
	_, server, client, _, token, _ := sshWSTestServer(t)
	httpServer := httptest.NewServer(http.HandlerFunc(server.HandleWebSocket))
	defer httpServer.Close()
	capture := &browserCloseCapture{closed: make(chan struct{})}
	socket, _, err := gws.NewClient(capture, &gws.ClientOption{
		Addr:          "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ssh-ws?device=" + url.QueryEscape(client.ID),
		RequestHeader: sshWSHeader(token),
	})
	if err != nil {
		t.Fatal("websocket connect failed")
	}
	defer socket.NetConn().Close()
	go socket.ReadLoop()
	select {
	case <-capture.closed:
	case <-time.After(sshWSHandshake + 3*time.Second):
		t.Fatal("incomplete SSH handshake leaked")
	}
}

func TestSSHWSLimitsAndClose(t *testing.T) {
	_, server, client, _, token, _ := sshWSTestServer(t)
	for i := 0; i < sshWSMaxDevice; i++ {
		if !server.acquireWebSocket(client.ID) {
			t.Fatal("premature limit")
		}
	}
	r := httptest.NewRequest("GET", "/ssh-ws?device="+url.QueryEscape(client.ID), nil)
	r.Header = sshWSHeader(token)
	w := httptest.NewRecorder()
	server.HandleWebSocket(w, r)
	if w.Code != 429 {
		t.Fatalf("device limit status=%d", w.Code)
	}
	for i := 0; i < sshWSMaxDevice; i++ {
		server.releaseWebSocket(client.ID)
	}
	server.wsTotal = sshWSMaxTotal
	if server.acquireWebSocket("other") {
		t.Fatal("global limit ignored")
	}
	server.wsTotal = 0

	for _, test := range []string{"text", "oversize", "idle", "close", "backpressure"} {
		t.Run(test, func(t *testing.T) {
			peerClosed := make(chan struct{})
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, peer := net.Pipe()
				defer p.Close()
				defer peer.Close()
				defer close(peerClosed)
				h := &sshWSBridge{pipe: p, idle: 50 * time.Millisecond, write: 50 * time.Millisecond}
				ws, err := gws.NewUpgrader(h, &gws.ServerOption{ReadMaxPayloadSize: sshWSMaxMessage}).Upgrade(w, r)
				if err != nil {
					return
				}
				defer ws.NetConn().Close()
				_ = ws.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				ws.ReadLoop()
			}))
			defer httpServer.Close()
			ws, _, err := gws.NewClient(&gws.BuiltinEventHandler{}, &gws.ClientOption{Addr: "ws" + strings.TrimPrefix(httpServer.URL, "http")})
			if err != nil {
				t.Fatal(err)
			}
			defer ws.NetConn().Close()
			go ws.ReadLoop()
			switch test {
			case "text":
				_ = ws.WriteMessage(gws.OpcodeText, []byte("not SSH"))
			case "oversize":
				_ = ws.WriteMessage(gws.OpcodeBinary, make([]byte, sshWSMaxMessage+1))
			case "close":
				_ = ws.WriteClose(1000, nil)
			case "backpressure":
				_ = ws.WriteMessage(gws.OpcodeBinary, []byte{1})
			}
			select {
			case <-peerClosed:
			case <-time.After(time.Second):
				t.Fatal("connection leaked")
			}
		})
	}
}

func TestSSHWSDuplexHalfCloseDrainsReverseData(t *testing.T) {
	a, b := sshWSPipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(time.Second))
	_ = b.SetDeadline(time.Now().Add(time.Second))
	_ = a.CloseWrite()
	if _, err := b.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("want EOF: %v", err)
	}
	go func() { _, _ = b.Write([]byte("tail")); _ = b.CloseWrite() }()
	output, err := io.ReadAll(a)
	if err != nil || string(output) != "tail" {
		t.Fatalf("tail lost: %q %v", output, err)
	}
}
