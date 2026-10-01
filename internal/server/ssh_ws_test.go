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

type sshWSTestStream struct {
	gws.BuiltinEventHandler
	net.Conn
	input  net.Conn
	socket *gws.Conn
}

func (c *sshWSTestStream) OnMessage(_ *gws.Conn, m *gws.Message) {
	defer m.Close()
	if m.Opcode == gws.OpcodeBinary {
		_, _ = c.input.Write(m.Bytes())
	}
}
func (c *sshWSTestStream) OnClose(_ *gws.Conn, _ error) { _ = c.input.Close() }
func (c *sshWSTestStream) Write(p []byte) (int, error) {
	err := c.socket.WriteMessage(gws.OpcodeBinary, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *sshWSTestStream) Close() error {
	_ = c.Conn.Close()
	_ = c.input.Close()
	return c.socket.NetConn().Close()
}

func sshWSTestConnect(t *testing.T, endpoint, credential string) *sshWSTestStream {
	t.Helper()
	a, b := net.Pipe()
	c := &sshWSTestStream{Conn: a, input: b}
	header := http.Header{}
	header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+credential)
	socket, _, err := gws.NewClient(c, &gws.ClientOption{Addr: endpoint, RequestHeader: header})
	if err != nil {
		t.Fatal("WebSocket handshake failed")
	}
	c.socket = socket
	t.Cleanup(func() { _ = c.Close() })
	go socket.ReadLoop()
	return c
}

func TestSSHWSAuthorizationAndLimits(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	client, _ := maintenanceOnlineClient(t, s, "wss-auth")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, client.ID, grant)
	server := &SSHServer{srv: s}
	for _, tc := range []struct {
		query, credential string
		want              bool
	}{
		{"device=" + url.QueryEscape(client.ID), token, true},
		{"device=wrong", token, false},
		{"device=" + url.QueryEscape(client.ID) + "&token=bad", token, false},
		{"device=" + url.QueryEscape(client.ID) + "&device=wrong", token, false},
		{"device=" + url.QueryEscape(client.ID), "wrong", false},
		{"device=" + url.QueryEscape(client.ID), "", false},
	} {
		r := httptest.NewRequest("GET", "/ssh-ws?"+tc.query, nil)
		r.Header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+tc.credential)
		if _, ok := server.webSocketAuthorization(r); ok != tc.want {
			t.Fatal("unexpected authorization result")
		}
	}
	grant.Generation++
	grant.Capabilities = []string{"terminal"}
	maintenanceTestInstall(t, s, client.ID, grant)
	r := httptest.NewRequest("GET", "/ssh-ws?device="+url.QueryEscape(client.ID), nil)
	r.Header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+token)
	if _, ok := server.webSocketAuthorization(r); ok {
		t.Fatal("terminal-only token accepted")
	}
	for i := 0; i < sshWSMaxDevice; i++ {
		if !server.acquireWebSocket("device") {
			t.Fatal("early limit")
		}
	}
	if server.acquireWebSocket("device") {
		t.Fatal("device limit ignored")
	}
	server.releaseWebSocket("device")
	if !server.acquireWebSocket("device") {
		t.Fatal("slot not released")
	}
	server.wsTotal = sshWSMaxTotal
	if server.acquireWebSocket("other") {
		t.Fatal("global limit ignored")
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

func TestSSHWSRealHandshakeExecIdentityAndForwardBoundary(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	client, device := maintenanceOnlineClient(t, s, "wss-exec")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, client.ID, grant)
	server, err := NewSSHServer(s, "127.0.0.1:0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(http.HandlerFunc(server.HandleWebSocket))
	defer httpServer.Close()
	endpoint := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ssh-ws?device=" + url.QueryEscape(client.ID)
	config := &gossh.ClientConfig{User: client.ID, HostKeyCallback: gossh.FixedHostKey(server.hostKey.PublicKey()), Timeout: 3 * time.Second}
	stream := sshWSTestConnect(t, endpoint, token)
	conn, channels, requests, err := gossh.NewClientConn(stream, "fixture", config)
	if err != nil {
		t.Fatal(err)
	}
	sshClient := gossh.NewClient(conn, channels, requests)
	defer sshClient.Close()
	if _, err = sshClient.Dial("tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("WSS forwarding allowed")
	}
	session, err := sshClient.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var output bytes.Buffer
	session.Stdout = &output
	if err = session.Start("unique-wss-command"); err != nil {
		t.Fatal(err)
	}
	request := waitPeripheralDeviceMessage(t, device, protocol.MsgNewSession)
	if request.Command != "unique-wss-command" {
		t.Fatal("command changed")
	}
	s.handleClientBinary(client, protocol.EncodeBinFrame(protocol.BinData, request.SessionID, []byte("unique-wss-output")))
	s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgExitCode, SessionID: request.SessionID, ExitCode: 23})
	s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgClose, SessionID: request.SessionID})
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case err = <-done:
		exit, ok := err.(*gossh.ExitError)
		if !ok || exit.ExitStatus() != 23 || output.String() != "unique-wss-output" {
			t.Fatal("exit status or output lost")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("command stalled")
	}
	wrong := sshWSTestConnect(t, endpoint, token)
	config.User = "wrong-device"
	if unexpected, _, _, err := gossh.NewClientConn(wrong, "fixture", config); err == nil {
		_ = unexpected.Close()
		t.Fatal("inner device mismatch accepted")
	}
	closed := make(chan error, 1)
	go func() { closed <- sshClient.Wait() }()
	grant.Generation++
	grant.Revoked = true
	maintenanceTestInstall(t, s, client.ID, grant)
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("revoked WSS remained connected")
	}
}

func TestSSHWSRejectsOversizeAndText(t *testing.T) {
	for _, opcode := range []gws.Opcode{gws.OpcodeText, gws.OpcodeBinary} {
		t.Run(string(rune(opcode+'0')), func(t *testing.T) {
			a, b := sshWSPipe()
			defer a.Close()
			defer b.Close()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				u := gws.NewUpgrader(&sshWSBridge{pipe: a, idle: time.Second, write: time.Second}, &gws.ServerOption{ReadMaxPayloadSize: sshWSMaxMessage})
				c, e := u.Upgrade(w, r)
				if e != nil {
					return
				}
				c.ReadLoop()
			}))
			defer srv.Close()
			capture := &browserCloseCapture{closed: make(chan struct{})}
			c, _, err := gws.NewClient(capture, &gws.ClientOption{Addr: "ws" + strings.TrimPrefix(srv.URL, "http")})
			if err != nil {
				t.Fatal(err)
			}
			defer c.NetConn().Close()
			go c.ReadLoop()
			payload := []byte("not SSH binary")
			if opcode == gws.OpcodeBinary {
				payload = make([]byte, sshWSMaxMessage+1)
			}
			_ = c.WriteMessage(opcode, payload)
			select {
			case <-capture.closed:
			case <-time.After(3 * time.Second):
				t.Fatal("invalid frame not closed")
			}
		})
	}
}
