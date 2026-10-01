package server

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/lxzan/gws"
	gossh "golang.org/x/crypto/ssh"
)

const (
	sshWSMaxMessage = 64 * 1024
	sshWSMaxDevice  = 8
	sshWSMaxTotal   = 128
	sshWSHandshake  = 15 * time.Second
	sshWSIdle       = 90 * time.Second
	sshWSWrite      = 15 * time.Second
)

// Authentication is performed before upgrade, independently of control-plane
// access and browser terminal permissions. Never forward a credential to SSH.
func (s *SSHServer) webSocketAuthorization(r *http.Request) (deviceAuthorization, bool) {
	// ParseQuery also rejects malformed escapes instead of silently dropping them.
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["device"]) != 1 || query.Get("device") == "" {
		return deviceAuthorization{}, false
	}
	client, ok := s.srv.GetClient(query.Get("device"))
	if !ok {
		return deviceAuthorization{}, false
	}
	protocol, credential, count := false, "", 0
	for _, header := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, value := range strings.Split(header, ",") {
			value = strings.TrimSpace(value)
			if value == browserSocketProtocol {
				protocol = true
			} else if strings.HasPrefix(value, browserTicketProtocol) {
				credential = strings.TrimPrefix(value, browserTicketProtocol)
				count++
			}
		}
	}
	if !protocol || count != 1 {
		return deviceAuthorization{}, false
	}
	if strings.HasPrefix(credential, maintenanceTokenPrefix) {
		return s.srv.maintenanceAuthorization(client, credential, "ssh")
	}
	// Only delegated device tickets, never browser-only tickets or device passwords.
	if ticket, valid := s.srv.accessTicketForCredential(client, credential); valid {
		auth := deviceAuthorizationFor(client)
		auth.TicketID, auth.TicketExpiresAt = ticket.ID, ticket.ExpiresAt
		auth.DeviceCredentialVersion = ticket.DeviceCredentialVersion
		return auth, true
	}
	return deviceAuthorization{}, false
}

func (s *SSHServer) acquireWebSocket(device string) bool {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	if s.wsTotal >= sshWSMaxTotal || s.wsConnections[device] >= sshWSMaxDevice {
		return false
	}
	if s.wsConnections == nil {
		s.wsConnections = make(map[string]int)
	}
	s.wsConnections[device]++
	s.wsTotal++
	return true
}

func (s *SSHServer) releaseWebSocket(device string) {
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	s.wsConnections[device]--
	if s.wsConnections[device] == 0 {
		delete(s.wsConnections, device)
	}
	s.wsTotal--
}

// HandleWebSocket presents the existing SSH host key and session implementation
// over a private in-process connection. No unauthenticated TCP listener is added.
func (s *SSHServer) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet || !headerContainsToken(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	auth, ok := s.webSocketAuthorization(r)
	if !ok {
		http.Error(w, "device authorization denied", http.StatusUnauthorized)
		return
	}
	if !s.acquireWebSocket(auth.DeviceID) {
		http.Error(w, "connection limit reached", http.StatusTooManyRequests)
		return
	}
	defer s.releaseWebSocket(auth.DeviceID)

	bridge, backend := net.Pipe()
	defer bridge.Close()
	defer backend.Close()
	handler := &sshWSBridge{pipe: bridge, idle: sshWSIdle, write: sshWSWrite}
	upgrader := gws.NewUpgrader(handler, &gws.ServerOption{
		ReadMaxPayloadSize: sshWSMaxMessage, WriteMaxPayloadSize: sshWSMaxMessage,
		SubProtocols:      []string{browserSocketProtocol},
		PermessageDeflate: gws.PermessageDeflate{Enabled: false},
		// Sequential reads and a synchronous pipe provide bounded backpressure.
		ParallelEnabled: false,
	})
	socket, err := upgrader.Upgrade(w, r)
	if err != nil {
		return // Upgrade errors may contain request headers; do not log them.
	}
	defer socket.NetConn().Close()
	done := make(chan struct{})
	defer close(done)
	go s.watchWebSocketAuthorization(auth, socket, done)
	go handler.pump(socket)
	go s.serveWebSocketSSH(backend, auth)
	_ = socket.SetReadDeadline(time.Now().Add(sshWSIdle))
	socket.ReadLoop()
}

func (s *SSHServer) watchWebSocketAuthorization(auth deviceAuthorization, socket *gws.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		client, ok := s.srv.GetClient(auth.DeviceID)
		if !ok || !s.srv.deviceAuthorizationValid(auth, client) {
			_ = socket.SetWriteDeadline(time.Now().Add(sshWSWrite))
			_ = socket.WriteClose(1008, []byte("device authorization ended"))
			return
		}
		select {
		case <-done:
			return
		case <-ticker.C:
		}
	}
}

func (s *SSHServer) serveWebSocketSSH(conn net.Conn, auth deviceAuthorization) {
	handshake := time.AfterFunc(sshWSHandshake, func() { _ = conn.Close() })
	defer handshake.Stop()
	server := &ssh.Server{
		HostSigners:       []ssh.Signer{s.hostKey},
		Handler:           s.handleSession,
		SubsystemHandlers: map[string]ssh.SubsystemHandler{"sftp": s.handleSession},
		ChannelHandlers:   map[string]ssh.ChannelHandler{"session": ssh.DefaultSessionHandler},
		RequestHandlers:   map[string]ssh.RequestHandler{},
		IdleTimeout:       sshWSIdle,
		ServerConfigCallback: func(ctx ssh.Context) *gossh.ServerConfig {
			bindSSHDeviceAuthorization(ctx, auth)
			return &gossh.ServerConfig{
				NoClientAuth: true,
				NoClientAuthCallback: func(meta gossh.ConnMetadata) (*gossh.Permissions, error) {
					client, ok := s.srv.GetClient(auth.DeviceID)
					if meta.User() != auth.DeviceID || !ok || !s.srv.deviceAuthorizationValid(auth, client) {
						return nil, errors.New("device authorization denied")
					}
					handshake.Stop()
					return nil, nil
				},
			}
		},
	}
	server.HandleConn(conn)
}

type sshWSBridge struct {
	gws.BuiltinEventHandler
	pipe  net.Conn
	idle  time.Duration
	write time.Duration
}

func (h *sshWSBridge) OnClose(_ *gws.Conn, _ error) { _ = h.pipe.Close() }

func (h *sshWSBridge) OnMessage(socket *gws.Conn, message *gws.Message) {
	defer message.Close()
	if message.Opcode != gws.OpcodeBinary {
		_ = socket.SetWriteDeadline(time.Now().Add(h.write))
		_ = socket.WriteClose(1003, []byte("binary SSH data required"))
		_ = h.pipe.Close()
		return
	}
	_ = socket.SetReadDeadline(time.Now().Add(h.idle))
	_ = h.pipe.SetWriteDeadline(time.Now().Add(h.write))
	if _, err := h.pipe.Write(message.Bytes()); err != nil {
		_ = socket.NetConn().Close()
	}
}

func (h *sshWSBridge) pump(socket *gws.Conn) {
	defer h.pipe.Close()
	buffer := make([]byte, 32*1024)
	for {
		n, err := h.pipe.Read(buffer)
		if n > 0 {
			_ = socket.SetWriteDeadline(time.Now().Add(h.write))
			if socket.WriteMessage(gws.OpcodeBinary, buffer[:n]) != nil {
				_ = socket.NetConn().Close()
				return
			}
		}
		if err != nil {
			code := uint16(1011)
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				code = 1000
			}
			_ = socket.SetWriteDeadline(time.Now().Add(h.write))
			_ = socket.WriteClose(code, nil)
			return
		}
	}
}
