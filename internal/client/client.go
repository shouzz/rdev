package client

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lxzan/gws"
	"github.com/pkg/sftp"
	kcp "github.com/xtaci/kcp-go/v5"
	gossh "golang.org/x/crypto/ssh"
	"rdev/internal/protocol"
	"rdev/internal/ptyutil"
	tframe "rdev/internal/transport"
	"rdev/internal/wincompat"
)

const (
	defaultReconnectMin = 1 * time.Second
	defaultReconnectMax = 30 * time.Second
	defaultRegisterWait = 8 * time.Second
	clientWriteWait     = 10 * time.Second
	clientReadWait      = 75 * time.Second
	clientPingPeriod    = 25 * time.Second
)

// convertModes converts protocol modes (map[uint8]uint32) to ssh.TerminalModes.
// Returns nil if the map is empty.
func convertModes(m map[uint8]uint32) gossh.TerminalModes {
	if len(m) == 0 {
		return nil
	}
	modes := make(gossh.TerminalModes, len(m))
	for k, v := range m {
		modes[k] = v
	}
	return modes
}

// --- Write adapters ---

// coalescingWriter batches small writes into larger WebSocket frames.
// Sends immediately for >= 4KB, otherwise buffers up to 5ms.
type coalescingWriter struct {
	client    *Client
	sessionID string
	typ       byte // BinData or BinStderr
	buf       bytes.Buffer
	timer     *time.Timer
	interval  time.Duration
	mu        sync.Mutex
}

func newCoalescingWriter(client *Client, sessionID string, typ byte) *coalescingWriter {
	return newCoalescingWriterWithInterval(client, sessionID, typ, 5*time.Millisecond)
}

func newCoalescingWriterWithInterval(client *Client, sessionID string, typ byte, interval time.Duration) *coalescingWriter {
	return &coalescingWriter{
		client:    client,
		sessionID: sessionID,
		typ:       typ,
		buf:       *bytes.NewBuffer(make([]byte, 0, 8192)),
		interval:  interval,
	}
}

func (w *coalescingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(p) >= 4096 {
		// Keep the pending prefix and the large frame in the same ordering
		// critical section. A timer flush must not send the prefix afterward.
		w.flushLocked()
		w.client.sendBinary(w.typ, w.sessionID, p)
		return len(p), nil
	}

	w.buf.Write(p)
	if w.buf.Len() >= 4096 {
		if w.timer != nil {
			w.timer.Stop()
			w.timer = nil
		}
		w.flushLocked()
	} else if w.timer == nil {
		w.timer = time.AfterFunc(w.interval, w.flush)
	}
	return len(p), nil
}

func (w *coalescingWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flushLocked()
}

func (w *coalescingWriter) flushLocked() {
	if w.buf.Len() == 0 {
		w.timer = nil
		return
	}
	data := make([]byte, w.buf.Len())
	copy(data, w.buf.Bytes())
	w.buf.Reset()
	w.timer = nil
	w.client.sendBinary(w.typ, w.sessionID, data)
}

// sftpRWC bridges SFTP server over WebSocket
type sftpRWC struct {
	reader io.Reader
	writer io.Writer
	closer io.Closer
}

func (s *sftpRWC) Read(p []byte) (int, error)  { return s.reader.Read(p) }
func (s *sftpRWC) Write(p []byte) (int, error) { return s.writer.Write(p) }
func (s *sftpRWC) Close() error {
	s.closer.Close()
	return nil
}

// clientSession represents a proxied session on the client device
type clientSession struct {
	id        string
	subsystem string // "", "sftp"
	command   string
	pty       bool

	// PTY mode
	ptyProc *ptyutil.Process

	// Non-PTY exec mode
	stdinMu   sync.Mutex
	stdinPipe io.WriteCloser
	cmdWaitFn func() (int, error)

	// SFTP mode
	sftpInput  *io.PipeWriter
	sftpOutput *io.PipeReader

	done chan struct{}
	once sync.Once
}

func (s *clientSession) close() {
	s.once.Do(func() {
		if s.ptyProc != nil {
			s.ptyProc.Close()
		}
		s.closeStdin()
		if s.sftpInput != nil {
			s.sftpInput.Close()
		}
		close(s.done)
	})
}

func (s *clientSession) writeStdin(data []byte) bool {
	s.stdinMu.Lock()
	defer s.stdinMu.Unlock()
	if s.stdinPipe == nil {
		return false
	}
	_, _ = s.stdinPipe.Write(data)
	return true
}

func (s *clientSession) closeStdin() {
	s.stdinMu.Lock()
	defer s.stdinMu.Unlock()
	if s.stdinPipe == nil {
		return
	}
	_ = s.stdinPipe.Close()
	s.stdinPipe = nil
}

type fileStream struct {
	path string
	file *os.File
	mode os.FileMode
}

type managedUpload struct {
	path      string
	partPath  string
	file      *os.File
	size      int64
	offset    int64
	startedAt time.Time
}

// Client is the rdev client that connects to the server
type Client struct {
	serverURL       string
	clientID        string
	requestedID     string
	instanceID      string
	password        string
	deviceSecret    string
	shell           string
	version         string
	conn            *gws.Conn
	transport       clientTransport
	writeMu         sync.Mutex
	sessions        map[string]*clientSession
	forwards        map[string]net.Conn
	forwardOpen     map[string]chan struct{}
	listeners       map[string]net.Listener
	fileStreams     map[string]*fileStream
	uploads         map[string]*managedUpload
	downloads       map[string]chan struct{}
	desktopSessions map[string]*desktopSession
	cloudTransfers  map[string]*cloudTransferRun
	mu              sync.Mutex
	done            chan struct{}
	reconnectReset  chan struct{}
	reconnectMin    time.Duration
	reconnectMax    time.Duration
	registerWait    time.Duration
	registration    *registrationAttempt
	registered      bool
	activeEndpoint  string

	// Server info (received on register response)
	sshPort  string
	httpHost string

	// OnConnect is called after successfully connecting and registering.
	OnConnect    func(c *Client)
	logCollector *clientLogCollector
}

type clientTransport interface {
	WriteJSON([]byte) error
	WriteBinary([]byte) error
	WritePing([]byte) error
	Close(string) error
}

type registrationAttempt struct {
	transport clientTransport
	endpoint  string
	result    chan error
	once      sync.Once
}

func (a *registrationAttempt) complete(err error) {
	a.once.Do(func() { a.result <- err })
}

type wsClientTransport struct{ conn *gws.Conn }

func (t *wsClientTransport) WriteJSON(data []byte) error {
	_ = t.conn.SetWriteDeadline(time.Now().Add(clientWriteWait))
	defer t.conn.SetWriteDeadline(time.Time{})
	return t.conn.WriteMessage(gws.OpcodeText, data)
}
func (t *wsClientTransport) WriteBinary(data []byte) error {
	_ = t.conn.SetWriteDeadline(time.Now().Add(clientWriteWait))
	defer t.conn.SetWriteDeadline(time.Time{})
	return t.conn.WriteMessage(gws.OpcodeBinary, data)
}
func (t *wsClientTransport) WritePing(payload []byte) error {
	_ = t.conn.SetWriteDeadline(time.Now().Add(clientWriteWait))
	defer t.conn.SetWriteDeadline(time.Time{})
	return t.conn.WritePing(payload)
}
func (t *wsClientTransport) Close(reason string) error {
	return t.conn.WriteClose(1000, []byte(reason))
}

type streamClientTransport struct {
	conn net.Conn
	mu   sync.Mutex
}

func (t *streamClientTransport) write(kind byte, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	_ = t.conn.SetWriteDeadline(time.Now().Add(clientWriteWait))
	defer t.conn.SetWriteDeadline(time.Time{})
	return tframe.WriteFrame(t.conn, kind, payload)
}
func (t *streamClientTransport) WriteJSON(data []byte) error { return t.write(tframe.KindJSON, data) }
func (t *streamClientTransport) WriteBinary(data []byte) error {
	return t.write(tframe.KindBinary, data)
}
func (t *streamClientTransport) WritePing(payload []byte) error {
	return t.write(tframe.KindPing, payload)
}
func (t *streamClientTransport) Close(reason string) error {
	_ = t.write(tframe.KindClose, []byte(reason))
	return t.conn.Close()
}

// NewClient creates a new client
func NewClient(serverURL, clientID, password, shell string) *Client {
	lc := newClientLogCollector()
	c := &Client{
		serverURL:       serverURL,
		clientID:        clientID,
		requestedID:     clientID,
		instanceID:      newClientInstanceID(),
		password:        password,
		shell:           shell,
		sessions:        make(map[string]*clientSession),
		forwards:        make(map[string]net.Conn),
		forwardOpen:     make(map[string]chan struct{}),
		listeners:       make(map[string]net.Listener),
		fileStreams:     make(map[string]*fileStream),
		uploads:         make(map[string]*managedUpload),
		downloads:       make(map[string]chan struct{}),
		desktopSessions: make(map[string]*desktopSession),
		cloudTransfers:  make(map[string]*cloudTransferRun),
		done:            make(chan struct{}, 1),
		reconnectReset:  make(chan struct{}, 1),
		reconnectMin:    defaultReconnectMin,
		reconnectMax:    defaultReconnectMax,
		registerWait:    defaultRegisterWait,
		logCollector:    lc,
	}
	lc.install(c)
	return c
}

// SetDeviceSecret configures the credential used only for managed-device registration.
func (c *Client) SetDeviceSecret(secret string) {
	c.deviceSecret = secret
}

// SetReconnectDelays configures the reconnect backoff bounds.
func (c *Client) SetReconnectDelays(minDelay, maxDelay time.Duration) {
	if minDelay <= 0 {
		minDelay = defaultReconnectMin
	}
	if maxDelay < minDelay {
		maxDelay = minDelay
	}
	c.reconnectMin = minDelay
	c.reconnectMax = maxDelay
}

// SetVersion sets the version string reported during registration.
func (c *Client) SetVersion(version string) {
	c.version = version
}

func newClientInstanceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

type reconnectBackoff struct {
	min     time.Duration
	max     time.Duration
	current time.Duration
}

func newReconnectBackoff(minDelay, maxDelay time.Duration) *reconnectBackoff {
	if minDelay <= 0 {
		minDelay = defaultReconnectMin
	}
	if maxDelay < minDelay {
		maxDelay = minDelay
	}
	return &reconnectBackoff{min: minDelay, max: maxDelay, current: minDelay}
}

func (b *reconnectBackoff) Reset() {
	b.current = b.min
}

func (b *reconnectBackoff) Next() time.Duration {
	base := b.current
	b.current *= 2
	if b.current > b.max || b.current < 0 {
		b.current = b.max
	}
	if base <= 0 {
		return b.min
	}
	jitter := base / 5
	if jitter <= 0 {
		return base
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(jitter*2)+1))
	if err != nil {
		return base
	}
	return base - jitter + time.Duration(n.Int64())
}

// wsEventHandler implements gws.Event for the client
type wsEventHandler struct {
	gws.BuiltinEventHandler
	client   *Client
	endpoint string
	opened   chan *registrationAttempt
}

func (h *wsEventHandler) OnOpen(socket *gws.Conn) {
	_ = socket.SetDeadline(time.Now().Add(clientReadWait))
	transport := &wsClientTransport{conn: socket}
	attempt := h.client.activateTransport(transport, socket, h.endpoint)
	h.opened <- attempt
	if err := h.client.send(h.client.registrationMessage()); err != nil {
		attempt.complete(fmt.Errorf("send registration: %w", err))
		_ = transport.Close("registration send failed")
		return
	}
}

func (h *wsEventHandler) OnClose(socket *gws.Conn, err error) {
	log.Printf("connection closed: %v", err)
	h.client.mu.Lock()
	if h.client.conn != socket {
		h.client.mu.Unlock()
		return
	}
	attempt := h.client.registration
	wasRegistered := h.client.registered
	for sid, sess := range h.client.sessions {
		sess.close()
		delete(h.client.sessions, sid)
	}
	for fid, tcpConn := range h.client.forwards {
		tcpConn.Close()
		delete(h.client.forwards, fid)
	}
	for tid, upload := range h.client.uploads {
		upload.file.Close()
		delete(h.client.uploads, tid)
	}
	for tid, cancel := range h.client.downloads {
		close(cancel)
		delete(h.client.downloads, tid)
	}
	for sid, session := range h.client.desktopSessions {
		close(session.stop)
		delete(h.client.desktopSessions, sid)
	}
	h.client.conn = nil
	h.client.transport = nil
	h.client.registration = nil
	h.client.registered = false
	h.client.activeEndpoint = ""
	h.client.mu.Unlock()
	if attempt != nil {
		attempt.complete(fmt.Errorf("connection closed before registration: %v", err))
	}
	if wasRegistered {
		select {
		case h.client.done <- struct{}{}:
		default:
		}
	}
}

func (h *wsEventHandler) OnPing(socket *gws.Conn, payload []byte) {
	_ = socket.SetDeadline(time.Now().Add(clientReadWait))
	h.client.writeMu.Lock()
	_ = socket.WritePong(payload)
	h.client.writeMu.Unlock()
}

func (h *wsEventHandler) OnPong(socket *gws.Conn, payload []byte) {
	_ = socket.SetDeadline(time.Now().Add(clientReadWait))
}

func (h *wsEventHandler) OnMessage(socket *gws.Conn, message *gws.Message) {
	defer message.Close()
	if !h.client.isCurrentConn(socket) {
		return
	}
	_ = socket.SetDeadline(time.Now().Add(clientReadWait))

	if message.Opcode == gws.OpcodeBinary {
		h.handleBinaryMessage(message.Bytes())
		return
	}

	// Text frame = JSON control message
	msg, err := protocol.Decode(message.Bytes())
	if err != nil {
		return
	}
	h.client.handleMessage(msg)
}

func (c *Client) isCurrentConn(socket *gws.Conn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn == socket
}

func (h *wsEventHandler) handleBinaryMessage(raw []byte) {
	typ, id, payload, err := protocol.DecodeBinFrame(raw)
	if err != nil {
		return
	}

	switch typ {
	case protocol.BinData:
		h.client.handleBinData(id, payload)
	case protocol.BinStderr:
		// stderr not expected from server in current design
	case protocol.BinTCPData:
		h.client.handleBinTCPData(id, payload)
	case protocol.BinFilePut:
		h.client.handleBinFilePut(id, payload)
	case protocol.BinFileStart:
		h.client.handleBinFileStart(id, payload)
	case protocol.BinFileChunk:
		h.client.handleBinFileChunk(id, payload)
	case protocol.BinFileEnd:
		h.client.handleBinFileEnd(id)
	case protocol.BinFileUploadChunk:
		_, taskID, offset, data, err := protocol.DecodeBinFrameOffset(raw)
		if err == nil {
			h.client.handleManagedUploadChunk(taskID, offset, data)
		}
	case protocol.BinFileTransferCancel:
		h.client.handleManagedTransferCancel(id)
	}
}

// Run starts the client with auto-reconnect
func (c *Client) Run() error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	backoff := newReconnectBackoff(c.reconnectMin, c.reconnectMax)

	for {
		if c.drainReconnectSignals() {
			backoff.Reset()
		}
		err := c.connect()
		if err != nil {
			delay := backoff.Next()
			log.Printf("connection error: %v, reconnecting in %s...", err, delay.Round(time.Millisecond))
			select {
			case <-time.After(delay):
				continue
			case <-sigCh:
				return nil
			}
		}

		for connected := true; connected; {
			select {
			case <-c.reconnectReset:
				backoff.Reset()
			case <-c.done:
				if c.drainReconnectSignals() {
					backoff.Reset()
				}
				delay := backoff.Next()
				log.Printf("disconnected, reconnecting in %s...", delay.Round(time.Millisecond))
				select {
				case <-time.After(delay):
					connected = false
				case <-sigCh:
					return nil
				}
			case <-sigCh:
				c.cleanup()
				return nil
			}
		}
	}
}

func (c *Client) drainReconnectSignals() bool {
	reset := false
	for {
		select {
		case <-c.done:
		case <-c.reconnectReset:
			reset = true
		default:
			return reset
		}
	}
}

func resolveWebSocketURL(wsURL string, maxRedirects int) (string, error) {
	current := strings.TrimSpace(wsURL)
	if current == "" {
		return "", fmt.Errorf("empty websocket url")
	}
	for i := 0; i <= maxRedirects; i++ {
		normalized, err := normalizeWebSocketURL(current)
		if err != nil {
			return "", err
		}
		current = normalized
		probe := current
		if strings.HasPrefix(probe, "wss://") {
			probe = "https://" + strings.TrimPrefix(probe, "wss://")
		} else if strings.HasPrefix(probe, "ws://") {
			probe = "http://" + strings.TrimPrefix(probe, "ws://")
		}
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
		req, err := http.NewRequest(http.MethodGet, probe, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "rdev-client")
		resp, err := client.Do(req)
		if err != nil {
			return current, nil
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			loc := strings.TrimSpace(resp.Header.Get("Location"))
			if loc == "" {
				return "", fmt.Errorf("redirect without location")
			}
			base, err := url.Parse(current)
			if err != nil {
				return "", err
			}
			rel, err := url.Parse(loc)
			if err != nil {
				return "", err
			}
			next := base.ResolveReference(rel)
			current = next.String()
			if strings.HasPrefix(current, "http://") {
				current = "ws://" + strings.TrimPrefix(current, "http://")
			} else if strings.HasPrefix(current, "https://") {
				current = "wss://" + strings.TrimPrefix(current, "https://")
			}
			continue
		default:
			return current, nil
		}
	}
	return current, nil
}

func normalizeWebSocketURL(value string) (string, error) {
	urlValue := strings.TrimSpace(value)
	if urlValue == "" {
		return "", fmt.Errorf("empty websocket url")
	}
	if strings.HasPrefix(urlValue, "wss:///") {
		urlValue = "wss://" + strings.TrimLeft(urlValue[len("wss://"):], "/")
	} else if strings.HasPrefix(urlValue, "ws:///") {
		urlValue = "ws://" + strings.TrimLeft(urlValue[len("ws://"):], "/")
	} else if strings.HasPrefix(urlValue, "https:///") {
		urlValue = "https://" + strings.TrimLeft(urlValue[len("https://"):], "/")
	} else if strings.HasPrefix(urlValue, "http:///") {
		urlValue = "http://" + strings.TrimLeft(urlValue[len("http://"):], "/")
	}
	if strings.HasPrefix(urlValue, "https://") {
		urlValue = "wss://" + strings.TrimPrefix(urlValue, "https://")
	} else if strings.HasPrefix(urlValue, "http://") {
		urlValue = "ws://" + strings.TrimPrefix(urlValue, "http://")
	} else if !strings.HasPrefix(urlValue, "ws://") && !strings.HasPrefix(urlValue, "wss://") {
		urlValue = "ws://" + urlValue
	}
	parsed, err := url.Parse(urlValue)
	if err != nil {
		return "", err
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/ws"
	} else if !strings.HasSuffix(parsed.Path, "/ws") {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/ws"
	}
	return parsed.String(), nil
}

func splitServerEndpoints(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeServerEndpoint(value string) (kind, endpoint string, err error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return "", "", fmt.Errorf("empty server endpoint")
	}
	fixTriple := func(prefix string) {
		if strings.HasPrefix(v, prefix+":///") {
			v = prefix + "://" + strings.TrimLeft(v[len(prefix+"://"):], "/")
		}
	}
	for _, p := range []string{"tcp", "kcp", "udp", "ws", "wss", "http", "https"} {
		fixTriple(p)
	}
	switch {
	case strings.HasPrefix(v, "tcp://"):
		return "tcp", v, nil
	case strings.HasPrefix(v, "kcp://"), strings.HasPrefix(v, "udp://"):
		return "kcp", v, nil
	case strings.HasPrefix(v, "ws://"), strings.HasPrefix(v, "wss://"), strings.HasPrefix(v, "http://"), strings.HasPrefix(v, "https://"):
		return "ws", v, nil
	default:
		return "tcp", "tcp://" + v, nil
	}
}

func (c *Client) connect() error {
	var lastErr error
	for _, endpoint := range splitServerEndpoints(c.serverURL) {
		kind, normalized, err := normalizeServerEndpoint(endpoint)
		if err != nil {
			lastErr = err
			continue
		}
		log.Printf("trying endpoint %s", normalized)
		if kind == "ws" {
			if err := c.connectWebSocket(normalized); err != nil {
				log.Printf("endpoint %s failed: %v", normalized, err)
				lastErr = err
				continue
			}
			return nil
		}
		if err := c.connectStream(kind, normalized); err != nil {
			log.Printf("endpoint %s failed: %v", normalized, err)
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("no server endpoints")
}

func (c *Client) connectWebSocket(serverURL string) error {
	wsURL, err := resolveWebSocketURL(serverURL, 5)
	if err != nil {
		return err
	}
	handler := &wsEventHandler{
		client:   c,
		endpoint: wsURL,
		opened:   make(chan *registrationAttempt, 1),
	}
	socket, _, err := gws.NewClient(handler, &gws.ClientOption{
		Addr:               wsURL,
		HandshakeTimeout:   10 * time.Second,
		ReadMaxPayloadSize: 16 * 1024 * 1024,
		NewDialer:          websocketDialerFor(wsURL),
		PermessageDeflate: gws.PermessageDeflate{
			Enabled:               true,
			ServerContextTakeover: true,
			ClientContextTakeover: true,
			Threshold:             256,
		},
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}

	go socket.ReadLoop()
	var attempt *registrationAttempt
	select {
	case attempt = <-handler.opened:
	case <-time.After(c.registerWait):
		_ = socket.WriteClose(1001, []byte("open timeout"))
		return fmt.Errorf("websocket open timeout after %s", c.registerWait)
	}
	if err := c.waitForRegistration(attempt); err != nil {
		_ = socket.WriteClose(1001, []byte("registration failed"))
		return err
	}
	go c.pingLoop(socket)
	return nil
}

func (c *Client) connectStream(kind, endpoint string) error {
	addr := strings.TrimPrefix(strings.TrimPrefix(endpoint, "tcp://"), "kcp://")
	addr = strings.TrimPrefix(addr, "udp://")
	if strings.Contains(addr, "/") {
		addr = strings.SplitN(addr, "/", 2)[0]
	}
	var conn net.Conn
	var err error
	if kind == "kcp" {
		k, e := kcp.DialWithOptions(addr, nil, 0, 0)
		if e != nil {
			return fmt.Errorf("dial kcp: %w", e)
		}
		k.SetNoDelay(1, 20, 2, 1)
		k.SetWindowSize(256, 256)
		k.SetMtu(1200)
		k.SetStreamMode(true)
		k.SetWriteDelay(false)
		conn = k
	} else {
		conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			return fmt.Errorf("dial tcp: %w", err)
		}
	}
	transport := &streamClientTransport{conn: conn}
	attempt := c.activateTransport(transport, nil, endpoint)
	if err := c.send(c.registrationMessage()); err != nil {
		attempt.complete(fmt.Errorf("send registration: %w", err))
		_ = conn.Close()
		return fmt.Errorf("send registration: %w", err)
	}
	go c.streamReadLoop(conn, transport)
	if err := c.waitForRegistration(attempt); err != nil {
		_ = transport.Close("registration failed")
		return err
	}
	go c.streamPingLoop(transport)
	return nil
}

func (c *Client) activateTransport(transport clientTransport, conn *gws.Conn, endpoint string) *registrationAttempt {
	attempt := &registrationAttempt{
		transport: transport,
		endpoint:  endpoint,
		result:    make(chan error, 1),
	}
	c.mu.Lock()
	c.transport = transport
	c.conn = conn
	c.registration = attempt
	c.registered = false
	c.activeEndpoint = endpoint
	c.mu.Unlock()
	return attempt
}

func (c *Client) waitForRegistration(attempt *registrationAttempt) error {
	timer := time.NewTimer(c.registerWait)
	defer timer.Stop()
	select {
	case err := <-attempt.result:
		return err
	case <-timer.C:
		err := fmt.Errorf("registration timeout after %s", c.registerWait)
		attempt.complete(err)
		return err
	}
}

func (c *Client) isCurrentTransport(t clientTransport) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.transport == t
}

func (c *Client) streamReadLoop(conn net.Conn, transport clientTransport) {
	defer func() {
		c.closeCurrentTransport(transport, conn)
	}()
	_ = conn.SetReadDeadline(time.Now().Add(clientReadWait))
	for {
		frame, err := tframe.ReadFrame(conn)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(clientReadWait))
		if !c.isCurrentTransport(transport) {
			return
		}
		switch frame.Kind {
		case tframe.KindJSON:
			msg, err := protocol.Decode(frame.Payload)
			if err == nil {
				c.handleMessage(msg)
			}
		case tframe.KindBinary:
			(&wsEventHandler{client: c}).handleBinaryMessage(frame.Payload)
		case tframe.KindPing:
			_ = transport.(*streamClientTransport).write(tframe.KindPong, frame.Payload)
		case tframe.KindClose:
			return
		}
	}
}

func (c *Client) closeCurrentTransport(transport clientTransport, conn net.Conn) {
	c.mu.Lock()
	if c.transport != transport {
		c.mu.Unlock()
		return
	}
	attempt := c.registration
	wasRegistered := c.registered
	for sid, sess := range c.sessions {
		sess.close()
		delete(c.sessions, sid)
	}
	for fid, tcpConn := range c.forwards {
		tcpConn.Close()
		delete(c.forwards, fid)
	}
	for tid, upload := range c.uploads {
		upload.file.Close()
		delete(c.uploads, tid)
	}
	for tid, cancel := range c.downloads {
		close(cancel)
		delete(c.downloads, tid)
	}
	for sid, session := range c.desktopSessions {
		close(session.stop)
		delete(c.desktopSessions, sid)
	}
	c.transport = nil
	c.conn = nil
	c.registration = nil
	c.registered = false
	c.activeEndpoint = ""
	c.mu.Unlock()
	conn.Close()
	if attempt != nil {
		attempt.complete(fmt.Errorf("connection closed before registration"))
	}
	if wasRegistered {
		select {
		case c.done <- struct{}{}:
		default:
		}
	}
}

func (c *Client) handleMessage(msg *protocol.Message) {
	switch msg.Type {
	case protocol.MsgRegisterError:
		c.mu.Lock()
		attempt := c.registration
		transport := c.transport
		c.registration = nil
		c.registered = false
		c.mu.Unlock()
		registrationErr := errors.New("registration rejected")
		if strings.TrimSpace(msg.Error) != "" {
			registrationErr = fmt.Errorf("registration rejected: %s", strings.TrimSpace(msg.Error))
		}
		if attempt != nil {
			attempt.complete(registrationErr)
		}
		if transport != nil {
			_ = transport.Close("registration rejected")
		}
	case protocol.MsgRegister:
		c.mu.Lock()
		attempt := c.registration
		if attempt == nil || c.transport != attempt.transport {
			c.mu.Unlock()
			return
		}
		if msg.ClientID != "" {
			oldID := c.clientID
			c.clientID = msg.ClientID
			if oldID != "" && oldID != msg.ClientID {
				log.Printf("server assigned device ID %q for requested ID %q", msg.ClientID, c.requestedID)
			}
		}
		c.sshPort = msg.SSHPort
		c.httpHost = msg.HTTPHost
		c.registration = nil
		c.registered = true
		endpoint := c.activeEndpoint
		c.mu.Unlock()
		attempt.complete(nil)
		log.Printf("registered with %s as '%s'", endpoint, c.clientID)
		c.reconnectBackoffReset()
		if c.OnConnect != nil {
			c.OnConnect(c)
		}
	case protocol.MsgLogConfig:
		if c.logCollector != nil {
			c.logCollector.configure(msg)
		}
	case protocol.MsgNewSession:
		c.handleNewSession(msg)
	case protocol.MsgStdinClose:
		c.handleStdinClose(msg)
	case protocol.MsgResize:
		c.handleResize(msg)
	case protocol.MsgClose:
		c.handleClose(msg)

	// TCP forwarding control
	case protocol.MsgTCPConnect:
		c.handleTCPConnect(msg)
	case protocol.MsgTCPOpen:
		c.handleTCPOpen(msg)
	case protocol.MsgTCPListen:
		c.handleTCPListen(msg)
	case protocol.MsgTCPClose:
		c.handleTCPClose(msg)
	case protocol.MsgFileListRequest:
		go c.handleFileListRequest(msg)
	case protocol.MsgFileMkdir:
		go c.handleFileMkdir(msg)
	case protocol.MsgFileDelete:
		go c.handleFileDelete(msg)
	case protocol.MsgFileRename:
		go c.handleFileRename(msg)
	case protocol.MsgFileUploadStart:
		go c.handleManagedUploadStart(msg)
	case protocol.MsgFileUploadEnd:
		go c.handleManagedUploadEnd(msg)
	case protocol.MsgFileDownloadStart:
		go c.handleManagedDownloadStart(msg)
	case protocol.MsgFileTransferCancel:
		c.handleManagedTransferCancel(msg.TaskID)
	case protocol.MsgCloudTransferStart:
		c.handleCloudTransferStart(msg)
	case protocol.MsgDesktopStart:
		go c.handleDesktopStart(msg)
	case protocol.MsgDesktopInput:
		c.handleDesktopInput(msg)
	case protocol.MsgDesktopClipboard:
		c.handleDesktopClipboard(msg)
	case protocol.MsgDesktopClose:
		c.handleDesktopClose(msg.SessionID)
	}
}

func (c *Client) registrationMessage() *protocol.Message {
	return &protocol.Message{
		Type: protocol.MsgRegister, ClientID: c.requestedID, InstanceID: c.instanceID,
		ClientVersion: c.version, Password: c.password, DeviceSecret: c.deviceSecret,
		DesktopCapabilities: desktopCapabilities(), LogSupported: true, CloudTransferV1: true,
	}
}

func (c *Client) sendBinaryOffset(typ byte, id string, offset int64, data []byte) error {
	frame := protocol.EncodeBinFrameOffset(typ, id, offset, data)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.transport == nil {
		return fmt.Errorf("not connected")
	}
	return c.transport.WriteBinary(frame)
}

func (c *Client) sendFileTransferError(taskID, path, errText string) {
	c.send(&protocol.Message{Type: protocol.MsgFileTransferError, TaskID: taskID, Path: path, Error: errText})
}

func defaultFilePath(path string) string {
	if path != "" {
		return path
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		return cwd
	}
	return "."
}

func fileParent(path string) string {
	clean := filepath.Clean(defaultFilePath(path))
	parent := filepath.Dir(clean)
	if parent == "." && filepath.IsAbs(clean) {
		return clean
	}
	return parent
}

func (c *Client) handleFileListRequest(msg *protocol.Message) {
	path, err := resolveFileLocation(msg.Path, msg.Location)
	if err != nil {
		c.send(&protocol.Message{Type: protocol.MsgFileListResult, RequestID: msg.RequestID, Location: msg.Location, Error: err.Error()})
		return
	}
	entries, truncated, err := listFileEntries(path, 2000)
	if err != nil {
		c.send(&protocol.Message{Type: protocol.MsgFileListResult, RequestID: msg.RequestID, Path: path, Location: msg.Location, Error: err.Error()})
		return
	}
	home, _ := os.UserHomeDir()
	c.send(&protocol.Message{
		Type:        protocol.MsgFileListResult,
		RequestID:   msg.RequestID,
		Path:        filepath.Clean(path),
		Location:    msg.Location,
		ParentPath:  fileParent(path),
		HomePath:    home,
		FileEntries: entries,
		Truncated:   truncated,
	})
}

func listFileEntries(path string, limit int) ([]protocol.FileEntry, bool, error) {
	infos, err := os.ReadDir(path)
	if err != nil {
		return nil, false, err
	}
	sort.Slice(infos, func(i, j int) bool {
		if infos[i].IsDir() != infos[j].IsDir() {
			return infos[i].IsDir()
		}
		return strings.ToLower(infos[i].Name()) < strings.ToLower(infos[j].Name())
	})
	truncated := false
	if limit > 0 && len(infos) > limit {
		infos = infos[:limit]
		truncated = true
	}
	entries := make([]protocol.FileEntry, 0, len(infos))
	for _, ent := range infos {
		info, err := ent.Info()
		if err != nil {
			continue
		}
		entries = append(entries, protocol.FileEntry{
			Name:    ent.Name(),
			Path:    filepath.Join(path, ent.Name()),
			IsDir:   ent.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime().Format(time.RFC3339),
		})
	}
	return entries, truncated, nil
}

func safeJoinFile(dir, name string) (string, error) {
	if name == "" || name == "." || name == ".." || filepath.IsAbs(name) || filepath.VolumeName(name) != "" ||
		strings.ContainsAny(name, `/\`) || filepath.Base(name) != name {
		return "", errors.New("file name must be one path segment")
	}
	return filepath.Join(defaultFilePath(dir), name), nil
}

func (c *Client) sendFileOpResult(typ protocol.MessageType, requestID, path string, err error) {
	result := &protocol.Message{Type: typ, RequestID: requestID, Path: path, Success: err == nil}
	if err != nil {
		result.Error = err.Error()
	}
	c.send(result)
}

func (c *Client) handleFileMkdir(msg *protocol.Message) {
	path := msg.Path
	if path == "" && (msg.ParentPath != "" || msg.Name != "") {
		var err error
		path, err = safeJoinFile(msg.ParentPath, msg.Name)
		if err != nil {
			c.sendFileOpResult(protocol.MsgFileMkdirResult, msg.RequestID, "", err)
			return
		}
	}
	if path == "" {
		c.sendFileOpResult(protocol.MsgFileMkdirResult, msg.RequestID, "", errors.New("missing directory path"))
		return
	}
	path = filepath.Clean(path)
	err := os.MkdirAll(path, 0755)
	c.sendFileOpResult(protocol.MsgFileMkdirResult, msg.RequestID, path, err)
}

func (c *Client) handleFileDelete(msg *protocol.Message) {
	if msg.Path == "" {
		c.sendFileOpResult(protocol.MsgFileDeleteResult, msg.RequestID, "", errors.New("missing delete path"))
		return
	}
	path := filepath.Clean(msg.Path)
	var err error
	if msg.Recursive {
		err = os.RemoveAll(path)
	} else {
		err = os.Remove(path)
	}
	c.sendFileOpResult(protocol.MsgFileDeleteResult, msg.RequestID, path, err)
}

func (c *Client) handleFileRename(msg *protocol.Message) {
	if msg.Path == "" {
		c.sendFileOpResult(protocol.MsgFileRenameResult, msg.RequestID, "", errors.New("missing source path"))
		return
	}
	target := msg.FilePath
	if target == "" && (msg.ParentPath != "" || msg.Name != "") {
		var err error
		target, err = safeJoinFile(msg.ParentPath, msg.Name)
		if err != nil {
			c.sendFileOpResult(protocol.MsgFileRenameResult, msg.RequestID, filepath.Clean(msg.Path), err)
			return
		}
	}
	source := filepath.Clean(msg.Path)
	if target == "" {
		c.sendFileOpResult(protocol.MsgFileRenameResult, msg.RequestID, source, errors.New("missing target path"))
		return
	}
	target = filepath.Clean(target)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		c.sendFileOpResult(protocol.MsgFileRenameResult, msg.RequestID, source, err)
		return
	}
	if err := os.Rename(source, target); err != nil {
		c.sendFileOpResult(protocol.MsgFileRenameResult, msg.RequestID, source, err)
		return
	}
	c.sendFileOpResult(protocol.MsgFileRenameResult, msg.RequestID, target, nil)
}

func (c *Client) handleManagedUploadStart(msg *protocol.Message) {
	taskID := msg.TaskID
	if taskID == "" {
		return
	}
	target := msg.Path
	if target == "" {
		var err error
		target, err = safeJoinFile(msg.ParentPath, msg.Name)
		if err != nil {
			c.sendFileTransferError(taskID, "", err.Error())
			return
		}
	}
	if target == "" {
		c.sendFileTransferError(taskID, "", "missing target path")
		return
	}
	partPath := target + ".rdevpart"
	if err := os.MkdirAll(filepath.Dir(partPath), 0755); err != nil {
		c.sendFileTransferError(taskID, target, fmt.Sprintf("mkdir error: %v", err))
		return
	}
	f, err := os.OpenFile(partPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		c.sendFileTransferError(taskID, target, err.Error())
		return
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		c.sendFileTransferError(taskID, target, err.Error())
		return
	}
	offset := st.Size()
	if msg.Size >= 0 && offset > msg.Size {
		if err := f.Truncate(0); err != nil {
			f.Close()
			c.sendFileTransferError(taskID, target, err.Error())
			return
		}
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		c.sendFileTransferError(taskID, target, err.Error())
		return
	}
	c.mu.Lock()
	if old := c.uploads[taskID]; old != nil {
		old.file.Close()
	}
	c.uploads[taskID] = &managedUpload{path: target, partPath: partPath, file: f, size: msg.Size, offset: offset, startedAt: time.Now()}
	c.mu.Unlock()
	c.send(&protocol.Message{Type: protocol.MsgFileUploadReady, TaskID: taskID, Path: target, Offset: offset, Size: msg.Size})
}

func (c *Client) handleManagedUploadChunk(taskID string, offset int64, data []byte) {
	c.mu.Lock()
	up := c.uploads[taskID]
	c.mu.Unlock()
	if up == nil {
		c.sendFileTransferError(taskID, "", "upload not found")
		return
	}
	if offset != up.offset {
		c.sendFileTransferError(taskID, up.path, fmt.Sprintf("unexpected offset %d, want %d", offset, up.offset))
		return
	}
	n, err := up.file.Write(data)
	if err != nil {
		c.sendFileTransferError(taskID, up.path, err.Error())
		return
	}
	up.offset += int64(n)
	c.sendBinaryOffset(protocol.BinFileUploadAck, taskID, up.offset, nil)
}

func (c *Client) handleManagedUploadEnd(msg *protocol.Message) {
	taskID := msg.TaskID
	c.mu.Lock()
	up := c.uploads[taskID]
	delete(c.uploads, taskID)
	c.mu.Unlock()
	if up == nil {
		c.sendFileTransferError(taskID, msg.Path, "upload not found")
		return
	}
	if err := up.file.Sync(); err != nil {
		up.file.Close()
		c.sendFileTransferError(taskID, up.path, err.Error())
		return
	}
	if err := up.file.Close(); err != nil {
		c.sendFileTransferError(taskID, up.path, err.Error())
		return
	}
	if up.size >= 0 && up.offset != up.size {
		c.sendFileTransferError(taskID, up.path, fmt.Sprintf("size mismatch: wrote %d of %d", up.offset, up.size))
		return
	}
	if err := os.Rename(up.partPath, up.path); err != nil {
		c.sendFileTransferError(taskID, up.path, err.Error())
		return
	}
	c.send(&protocol.Message{Type: protocol.MsgFileTransferEnd, TaskID: taskID, Path: up.path, Size: up.offset, Success: true})
}

func (c *Client) handleManagedDownloadStart(msg *protocol.Message) {
	taskID := msg.TaskID
	path := msg.Path
	if taskID == "" || path == "" {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		c.sendFileTransferError(taskID, path, err.Error())
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		c.sendFileTransferError(taskID, path, err.Error())
		return
	}
	if st.IsDir() {
		c.sendFileTransferError(taskID, path, "cannot download directory")
		return
	}
	offset := msg.Offset
	if offset < 0 || offset > st.Size() {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		c.sendFileTransferError(taskID, path, err.Error())
		return
	}
	cancel := make(chan struct{})
	c.mu.Lock()
	if old := c.downloads[taskID]; old != nil {
		close(old)
	}
	c.downloads[taskID] = cancel
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.downloads[taskID] == cancel {
			delete(c.downloads, taskID)
		}
		c.mu.Unlock()
	}()
	c.send(&protocol.Message{Type: protocol.MsgFileDownloadStart, TaskID: taskID, Path: path, Name: filepath.Base(path), Size: st.Size(), Offset: offset, ModTime: st.ModTime().Format(time.RFC3339)})
	buf := make([]byte, 512*1024)
	cur := offset
	for {
		select {
		case <-cancel:
			return
		default:
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			select {
			case <-cancel:
				return
			default:
			}
			if err := c.sendBinaryOffset(protocol.BinFileDownloadChunk, taskID, cur, buf[:n]); err != nil {
				return
			}
			cur += int64(n)
		}
		if readErr == io.EOF {
			c.sendBinaryOffset(protocol.BinFileTransferEnd, taskID, cur, nil)
			c.send(&protocol.Message{Type: protocol.MsgFileTransferEnd, TaskID: taskID, Path: path, Size: st.Size(), Offset: cur, Success: true})
			return
		}
		if readErr != nil {
			c.sendFileTransferError(taskID, path, readErr.Error())
			return
		}
	}
}

func (c *Client) handleManagedTransferCancel(taskID string) {
	if taskID == "" {
		return
	}
	c.mu.Lock()
	if up := c.uploads[taskID]; up != nil {
		up.file.Close()
		delete(c.uploads, taskID)
	}
	if cancel := c.downloads[taskID]; cancel != nil {
		close(cancel)
		delete(c.downloads, taskID)
	}
	c.mu.Unlock()
}

func (c *Client) handleBinData(sessionID string, data []byte) {
	c.mu.Lock()
	sess, ok := c.sessions[sessionID]
	c.mu.Unlock()
	if !ok || len(data) == 0 {
		return
	}

	if sess.ptyProc != nil {
		sess.ptyProc.Write(data)
		return
	}
	if sess.writeStdin(data) {
		return
	}
	if sess.sftpInput != nil {
		sess.sftpInput.Write(data)
	}
}

func (c *Client) handleBinTCPData(forwardID string, data []byte) {
	c.mu.Lock()
	conn, ok := c.forwards[forwardID]
	c.mu.Unlock()
	if !ok || len(data) == 0 {
		return
	}
	conn.Write(data)
}

func (c *Client) sendFileResult(id, path string, success bool, errText string) {
	c.send(&protocol.Message{Type: protocol.MsgFileResult, SessionID: id, FilePath: path, Success: success, Error: errText})
}

func (c *Client) handleBinFileStart(id string, payload []byte) {
	path, mode, _, err := protocol.DecodeBinFilePut(payload)
	if err != nil {
		c.sendFileResult(id, "", false, fmt.Sprintf("decode error: %v", err))
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		c.sendFileResult(id, path, false, fmt.Sprintf("mkdir error: %v", err))
		return
	}
	fm := os.FileMode(0644)
	if mode > 0 {
		fm = os.FileMode(mode)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fm)
	if err != nil {
		c.sendFileResult(id, path, false, err.Error())
		return
	}
	c.mu.Lock()
	if old := c.fileStreams[id]; old != nil {
		old.file.Close()
	}
	c.fileStreams[id] = &fileStream{path: path, file: f, mode: fm}
	c.mu.Unlock()
}

func (c *Client) handleBinFileChunk(id string, data []byte) {
	c.mu.Lock()
	fs := c.fileStreams[id]
	c.mu.Unlock()
	if fs == nil {
		c.sendFileResult(id, "", false, "file stream not found")
		return
	}
	if _, err := fs.file.Write(data); err != nil {
		fs.file.Close()
		c.mu.Lock()
		delete(c.fileStreams, id)
		c.mu.Unlock()
		c.sendFileResult(id, fs.path, false, err.Error())
	}
}

func (c *Client) handleBinFileEnd(id string) {
	c.mu.Lock()
	fs := c.fileStreams[id]
	delete(c.fileStreams, id)
	c.mu.Unlock()
	if fs == nil {
		c.sendFileResult(id, "", false, "file stream not found")
		return
	}
	if err := fs.file.Close(); err != nil {
		c.sendFileResult(id, fs.path, false, err.Error())
		return
	}
	c.sendFileResult(id, fs.path, true, "")
}

func (c *Client) handleBinFilePut(id string, payload []byte) {
	path, mode, fileData, err := protocol.DecodeBinFilePut(payload)
	if err != nil {
		c.sendFileResult(id, "", false, fmt.Sprintf("decode error: %v", err))
		return
	}

	log.Printf("file_put: writing %s (%d bytes)", path, len(fileData))

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		c.sendFileResult(id, path, false, fmt.Sprintf("mkdir error: %v", err))
		return
	}

	fm := os.FileMode(0644)
	if mode > 0 {
		fm = os.FileMode(mode)
	}
	if err := os.WriteFile(path, fileData, fm); err != nil {
		c.sendFileResult(id, path, false, err.Error())
		return
	}

	log.Printf("file_put: wrote %d bytes to %s", len(fileData), path)
	c.sendFileResult(id, path, true, "")
}

// --- Session handling ---

func (c *Client) handleNewSession(msg *protocol.Message) {
	sessionID := msg.SessionID
	log.Printf("new session: id=%s subsystem=%q command=%q pty=%v",
		sessionID, msg.Subsystem, msg.Command, msg.Pty)

	_, err := c.startAndRegisterSession(sessionID, func() (*clientSession, error) {
		switch msg.Subsystem {
		case "sftp":
			return c.startSFTPSession(sessionID)
		default:
			return c.startShellExecSession(msg)
		}
	})

	if err != nil {
		log.Printf("session %s start failed: %v", sessionID, err)
		c.sendClose(sessionID)
		return
	}
}

func (c *Client) startAndRegisterSession(sessionID string, start func() (*clientSession, error)) (*clientSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sess, err := start()
	if err != nil {
		return nil, err
	}
	c.sessions[sessionID] = sess
	return sess, nil
}

func (c *Client) startShellExecSession(msg *protocol.Message) (*clientSession, error) {
	sess := &clientSession{
		id:        msg.SessionID,
		subsystem: msg.Subsystem,
		command:   msg.Command,
		pty:       msg.Pty,
		done:      make(chan struct{}),
	}

	if msg.Pty {
		cfg := &ptyutil.Config{
			Command: msg.Command,
			Shell:   c.shell,
			Env:     msg.Env,
			Term:    msg.Term,
			Rows:    uint16(msg.Rows),
			Cols:    uint16(msg.Cols),
			Modes:   convertModes(msg.Modes),
		}
		proc, ptyErr := ptyutil.Start(cfg)
		if ptyErr != nil {
			// PTY unavailable (e.g. ConPty on Wine, no /dev/pts) → fallback to exec mode
			log.Printf("session %s: PTY unavailable (%v), falling back to exec mode", msg.SessionID, ptyErr)
			sess.pty = false
		} else {
			sess.ptyProc = proc

			// Read PTY output -> coalesced binary send to server.
			// WinPTY on legacy Windows emits many tiny chunks; a slightly longer
			// output-only aggregation window keeps SSH input responsive while
			// avoiding WebSocket frame storms during screen redraws.
			cw := newCoalescingWriterWithInterval(c, msg.SessionID, protocol.BinData, 16*time.Millisecond)
			readDone := make(chan struct{})
			go func() {
				defer close(readDone)
				io.Copy(cw, proc)
				cw.flush()
			}()

			go func() {
				exitCode, _ := proc.Wait()

				// On some Windows versions, ConPTY output pipe does not EOF
				// after the process exits. Close the input side first so the
				// ConPTY host drains and closes the output pipe, unblocking Read.
				// For the go-pty ConPTY backend this means we close inPipe early;
				// Process.Close handles the rest idempotently.
				proc.CloseInput()

				// Give the read loop a few seconds to drain remaining output.
				select {
				case <-readDone:
					// read loop finished normally
				case <-time.After(5 * time.Second):
					log.Printf("session %s: PTY read did not finish after process exit, forcing close", msg.SessionID)
				}

				proc.Close()
				c.sendExitCode(msg.SessionID, exitCode)
				c.sendClose(msg.SessionID)
				sess.close()
			}()

			log.Printf("session %s: PTY started (cmd=%q)", msg.SessionID, msg.Command)
			return sess, nil
		}
	}

	if msg.Command != "" {
		if gitCmd, ok := parseGitSmartSSHCommand(msg.Command); ok && !hasSystemGitCommand(gitCmd.Name) {
			return c.startGitFallbackSession(sess, gitCmd)
		}
	}

	// Exec mode (non-PTY, or PTY fallback)
	shell := c.shell
	if shell == "" {
		shell = os.Getenv("SHELL")
		if shell == "" {
			shell = os.Getenv("COMSPEC")
			if shell == "" {
				if runtime.GOOS == "windows" {
					shell = "cmd.exe"
				} else {
					shell = "/bin/sh"
				}
			}
		}
	}

	flag := "-c"
	if runtime.GOOS == "windows" {
		flag = "/c"
	}

	var cmd *exec.Cmd
	if msg.Command != "" {
		cmd = exec.Command(shell, flag, msg.Command)
	} else {
		cmd = exec.Command(shell)
	}
	cmd.Env = append(os.Environ(), msg.Env...)

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		return nil, err
	}

	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	if err := cmd.Start(); err != nil {
		stdinR.Close()
		stdinW.Close()
		stdoutR.Close()
		stdoutW.Close()
		stderrR.Close()
		stderrW.Close()
		return nil, err
	}

	stdinR.Close()
	stdoutW.Close()
	stderrW.Close()

	rawIO := isSCPExecCommand(msg.Command)
	if rawIO {
		sess.stdinPipe = stdinW
	} else {
		sess.stdinPipe = wincompat.EncodeInput(stdinW)
	}
	sess.cmdWaitFn = func() (int, error) {
		err := cmd.Wait()
		if err == nil {
			return 0, nil
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return -1, err
	}

	var ioWg sync.WaitGroup

	ioWg.Add(1)
	go func() {
		defer ioWg.Done()
		defer stdoutR.Close()
		cw := newCoalescingWriter(c, msg.SessionID, protocol.BinData)
		reader := io.Reader(stdoutR)
		if !rawIO {
			reader = wincompat.DecodeOutput(stdoutR)
		}
		io.Copy(cw, reader)
		cw.flush()
	}()

	ioWg.Add(1)
	go func() {
		defer ioWg.Done()
		defer stderrR.Close()
		cw := newCoalescingWriter(c, msg.SessionID, protocol.BinStderr)
		io.Copy(cw, wincompat.DecodeOutput(stderrR))
		cw.flush()
	}()

	go func() {
		ioWg.Wait()
		exitCode, _ := sess.cmdWaitFn()
		c.sendExitCode(msg.SessionID, exitCode)
		c.sendClose(msg.SessionID)
		sess.close()
	}()

	log.Printf("session %s: exec started (cmd=%q)", msg.SessionID, msg.Command)

	return sess, nil
}

func isGitSmartSSHCommand(command string) bool {
	_, ok := parseGitSmartSSHCommand(command)
	return ok
}

func isSCPExecCommand(command string) bool {
	fields := strings.Fields(command)
	if len(fields) < 2 || fields[0] != "scp" {
		return false
	}
	for _, field := range fields[1:] {
		if field == "-t" || field == "-f" {
			return true
		}
	}
	return false
}

func (c *Client) startSFTPSession(sessionID string) (*clientSession, error) {
	pr1, pw1 := io.Pipe()
	pr2, pw2 := io.Pipe()

	rwc := &sftpRWC{reader: pr1, writer: pw2, closer: pw1}

	sess := &clientSession{
		id:         sessionID,
		subsystem:  "sftp",
		sftpInput:  pw1,
		sftpOutput: pr2,
		done:       make(chan struct{}),
	}

	go func() {
		defer pw2.Close()
		defer pr1.Close()

		server, err := sftp.NewServer(rwc)
		if err != nil {
			log.Printf("session %s: sftp init error: %v", sessionID, err)
			c.sendExitCode(sessionID, 1)
			c.sendClose(sessionID)
			return
		}
		defer server.Close()

		exitCode := 0
		if err := server.Serve(); err != nil && err != io.EOF {
			log.Printf("session %s: sftp error: %v", sessionID, err)
			exitCode = 1
		}
		c.sendExitCode(sessionID, exitCode)
		c.sendClose(sessionID)
	}()

	// SFTP output → binary frames (coalesced)
	go func() {
		cw := newCoalescingWriter(c, sessionID, protocol.BinData)
		io.Copy(cw, pr2)
		cw.flush()
	}()

	log.Printf("session %s: SFTP server started", sessionID)
	return sess, nil
}

func (c *Client) handleStdinClose(msg *protocol.Message) {
	c.mu.Lock()
	sess, ok := c.sessions[msg.SessionID]
	c.mu.Unlock()
	if !ok {
		return
	}
	sess.closeStdin()
	if sess.sftpInput != nil {
		sess.sftpInput.Close()
	}
}

func (c *Client) handleResize(msg *protocol.Message) {
	c.mu.Lock()
	sess, ok := c.sessions[msg.SessionID]
	c.mu.Unlock()
	if !ok || sess.ptyProc == nil {
		return
	}
	if err := sess.ptyProc.Resize(uint16(msg.Rows), uint16(msg.Cols)); err != nil {
		// Silently ignore resize on closed PTY (common during session teardown)
		log.Printf("session %s: resize error: %v", msg.SessionID, err)
	}
}

func (c *Client) handleClose(msg *protocol.Message) {
	c.mu.Lock()
	sess, ok := c.sessions[msg.SessionID]
	if ok {
		delete(c.sessions, msg.SessionID)
	}
	c.mu.Unlock()
	if ok {
		sess.close()
		log.Printf("session %s closed", msg.SessionID)
	}
}

// --- TCP forwarding (-L) ---

func (c *Client) handleTCPConnect(msg *protocol.Message) {
	addr := net.JoinHostPort(msg.Host, fmt.Sprintf("%d", msg.Port))
	log.Printf("forward: connecting to %s (id=%s)", addr, msg.ForwardID)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Printf("forward: connect to %s failed: %v", addr, err)
		c.send(&protocol.Message{
			Type:      protocol.MsgTCPFail,
			ForwardID: msg.ForwardID,
			Error:     err.Error(),
		})
		return
	}

	c.mu.Lock()
	c.forwards[msg.ForwardID] = conn
	c.mu.Unlock()

	c.send(&protocol.Message{Type: protocol.MsgTCPOpen, ForwardID: msg.ForwardID})

	// Read TCP response → binary frames
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				c.sendBinary(protocol.BinTCPData, msg.ForwardID, buf[:n])
			}
			if err != nil {
				c.send(&protocol.Message{Type: protocol.MsgTCPClose, ForwardID: msg.ForwardID})
				c.mu.Lock()
				delete(c.forwards, msg.ForwardID)
				c.mu.Unlock()
				return
			}
		}
	}()

	log.Printf("forward: connected to %s (id=%s)", addr, msg.ForwardID)
}

func (c *Client) handleTCPListen(msg *protocol.Message) {
	addr := net.JoinHostPort(msg.Host, fmt.Sprintf("%d", msg.Port))
	log.Printf("forward listen: %s (listenID=%s)", addr, msg.ListenID)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		c.send(&protocol.Message{Type: protocol.MsgTCPListenOK, ListenID: msg.ListenID, Error: err.Error()})
		return
	}
	_, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portText)

	c.mu.Lock()
	if old := c.listeners[msg.ListenID]; old != nil {
		old.Close()
	}
	c.listeners[msg.ListenID] = ln
	c.mu.Unlock()
	c.send(&protocol.Message{Type: protocol.MsgTCPListenOK, ListenID: msg.ListenID, Port: port})

	go func() {
		defer func() {
			c.mu.Lock()
			if c.listeners[msg.ListenID] == ln {
				delete(c.listeners, msg.ListenID)
			}
			c.mu.Unlock()
		}()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			forwardID := generateClientForwardID()
			openCh := make(chan struct{})
			c.mu.Lock()
			c.forwards[forwardID] = conn
			c.forwardOpen[forwardID] = openCh
			c.mu.Unlock()
			c.send(&protocol.Message{
				Type:       protocol.MsgTCPAccept,
				ListenID:   msg.ListenID,
				ForwardID:  forwardID,
				SourceAddr: conn.RemoteAddr().String(),
			})
			go func() {
				select {
				case <-openCh:
					c.readTCPForward(forwardID, conn)
				case <-time.After(10 * time.Second):
					c.handleTCPClose(&protocol.Message{ForwardID: forwardID})
				}
			}()
		}
	}()
}

func (c *Client) handleTCPOpen(msg *protocol.Message) {
	c.mu.Lock()
	openCh := c.forwardOpen[msg.ForwardID]
	delete(c.forwardOpen, msg.ForwardID)
	c.mu.Unlock()
	if openCh != nil {
		safeCloseForwardOpen(openCh)
	}
}

func (c *Client) readTCPForward(forwardID string, conn net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			c.sendBinary(protocol.BinTCPData, forwardID, buf[:n])
		}
		if err != nil {
			c.send(&protocol.Message{Type: protocol.MsgTCPClose, ForwardID: forwardID})
			c.mu.Lock()
			if c.forwards[forwardID] == conn {
				delete(c.forwards, forwardID)
			}
			delete(c.forwardOpen, forwardID)
			c.mu.Unlock()
			return
		}
	}
}

func (c *Client) handleTCPClose(msg *protocol.Message) {
	if msg.ListenID != "" {
		c.mu.Lock()
		ln, ok := c.listeners[msg.ListenID]
		if ok {
			delete(c.listeners, msg.ListenID)
		}
		c.mu.Unlock()
		if ok {
			ln.Close()
			log.Printf("forward listen: closed %s", msg.ListenID)
		}
		return
	}
	c.mu.Lock()
	conn, ok := c.forwards[msg.ForwardID]
	if ok {
		delete(c.forwards, msg.ForwardID)
	}
	openCh := c.forwardOpen[msg.ForwardID]
	delete(c.forwardOpen, msg.ForwardID)
	c.mu.Unlock()
	if openCh != nil {
		safeCloseForwardOpen(openCh)
	}
	if ok {
		conn.Close()
		log.Printf("forward: closed %s", msg.ForwardID)
	}
}

func safeCloseForwardOpen(ch chan struct{}) {
	defer func() { recover() }()
	close(ch)
}

func generateClientForwardID() string {
	return fmt.Sprintf("cf-%d-%d", time.Now().UnixNano(), os.Getpid())
}

// --- WebSocket send helpers ---

func (c *Client) send(msg *protocol.Message) error {
	c.mu.Lock()
	transport := c.transport
	c.mu.Unlock()
	if transport == nil {
		return fmt.Errorf("not connected")
	}
	data, err := protocol.Encode(msg)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return transport.WriteJSON(data)
}

func (c *Client) sendBinary(typ byte, id string, data []byte) error {
	c.mu.Lock()
	transport := c.transport
	c.mu.Unlock()
	if transport == nil {
		return fmt.Errorf("not connected")
	}
	frame := protocol.EncodeBinFrame(typ, id, data)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return transport.WriteBinary(frame)
}

func (c *Client) pingLoop(conn *gws.Conn) {
	ticker := time.NewTicker(clientPingPeriod)
	defer ticker.Stop()
	for range ticker.C {
		if !c.isCurrentConn(conn) {
			return
		}
		c.writeMu.Lock()
		_ = conn.SetWriteDeadline(time.Now().Add(clientWriteWait))
		err := conn.WritePing(nil)
		_ = conn.SetWriteDeadline(time.Time{})
		c.writeMu.Unlock()
		if err != nil {
			_ = conn.WriteClose(1001, []byte("ping failed"))
			return
		}
	}
}

func (c *Client) streamPingLoop(transport clientTransport) {
	ticker := time.NewTicker(clientPingPeriod)
	defer ticker.Stop()
	for range ticker.C {
		if !c.isCurrentTransport(transport) {
			return
		}
		c.writeMu.Lock()
		err := transport.WritePing(nil)
		c.writeMu.Unlock()
		if err != nil {
			_ = transport.Close("ping failed")
			return
		}
	}
}

func (c *Client) reconnectBackoffReset() {
	select {
	case c.reconnectReset <- struct{}{}:
	default:
	}
}

func (c *Client) sendClose(sessionID string) error {
	return c.send(&protocol.Message{
		Type:      protocol.MsgClose,
		SessionID: sessionID,
	})
}

func (c *Client) sendExitCode(sessionID string, code int) error {
	return c.send(&protocol.Message{
		Type:      protocol.MsgExitCode,
		SessionID: sessionID,
		ExitCode:  code,
	})
}

// --- Cleanup ---

func (c *Client) cleanup() {
	c.mu.Lock()
	for sid, sess := range c.sessions {
		sess.close()
		delete(c.sessions, sid)
	}
	for fid, conn := range c.forwards {
		conn.Close()
		delete(c.forwards, fid)
	}
	for id, fs := range c.fileStreams {
		fs.file.Close()
		delete(c.fileStreams, id)
	}
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		conn.WriteClose(1000, nil)
	}
	close(c.done)
}

// SSHPort returns the server's SSH port (received on register).
func (c *Client) SSHPort() string { return c.sshPort }

// ClientID returns the server-assigned client ID.
func (c *Client) ClientID() string { return c.clientID }

// HTTPHost returns the server's HTTP host:port (received on register).
func (c *Client) HTTPHost() string { return c.httpHost }
