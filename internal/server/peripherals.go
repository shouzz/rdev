package server

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lxzan/gws"
	"rdev/internal/protocol"
)

const (
	peripheralSerialFrameLimit = 16 * 1024
	peripheralSerialQueueSize  = 64
	peripheralControlTimeout   = 10 * time.Second
)

type peripheralMsg struct {
	Op           string                    `json:"op"`
	RequestID    string                    `json:"requestId,omitempty"`
	SessionID    string                    `json:"sessionId,omitempty"`
	SerialPortID string                    `json:"serialPortId,omitempty"`
	SerialConfig *protocol.SerialConfig    `json:"serialConfig,omitempty"`
	SerialPorts  []protocol.SerialPortInfo `json:"serialPorts,omitempty"`
	BytesDone    int64                     `json:"bytesDone,omitempty"`
	DroppedBytes uint64                    `json:"droppedBytes,omitempty"`
	Success      bool                      `json:"success,omitempty"`
	ErrorCode    string                    `json:"errorCode,omitempty"`
	Message      string                    `json:"message,omitempty"`
}

type peripheralSocket struct {
	conn       *gws.Conn
	srv        *Server
	deviceID   string
	instanceID string
	subject    string
	writeMu    sync.Mutex
}

func (s *peripheralSocket) writeText(msg peripheralMsg) bool {
	data, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	defer s.conn.SetWriteDeadline(time.Time{})
	return s.conn.WriteMessage(gws.OpcodeText, data) == nil
}

func (s *peripheralSocket) writeBinary(data []byte) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	defer s.conn.SetWriteDeadline(time.Time{})
	return s.conn.WriteMessage(gws.OpcodeBinary, data) == nil
}

type peripheralRequestRoute struct {
	requestID string
	socket    *peripheralSocket
	client    *ClientConn
	timer     *time.Timer
}

type serialRouteSocket interface {
	writeText(peripheralMsg) bool
	writeBinary([]byte) bool
}

type serialRoute struct {
	sessionID    string
	serialPortID string
	socket       serialRouteSocket
	subject      string
	client       *ClientConn
	output       chan []byte
	done         chan struct{}
	pumpDone     chan struct{}
	closeOnce    sync.Once
	finalizeOnce sync.Once
	inputMu      sync.Mutex
	dropped      atomic.Uint64
	received     atomic.Uint64
	delivered    atomic.Uint64
	transmitted  atomic.Uint64
	startedAt    time.Time
	operation    string
	requestID    string
	timer        *time.Timer
}

func (r *serialRoute) close(reason string) {
	r.closeOnce.Do(func() {
		close(r.done)
		go r.finalize(reason)
	})
}

func (r *serialRoute) finalize(reason string) {
	r.finalizeOnce.Do(func() {
		if r.pumpDone != nil {
			<-r.pumpDone
		}
		r.inputMu.Lock()
		defer r.inputMu.Unlock()
		received := r.received.Load()
		delivered := r.delivered.Load()
		if received > delivered {
			r.dropped.Add(received - delivered)
		}
		deviceID, instanceID := "", ""
		if r.client != nil {
			deviceID, instanceID = r.client.ID, r.client.InstanceID
		}
		log.Printf(
			"serial session audit: subject=%q device=%s instance=%s port=%s session=%s started_at=%s duration_ms=%d rx_bytes=%d tx_bytes=%d dropped_bytes=%d reason=%s",
			r.subject, deviceID, instanceID, r.serialPortID, r.sessionID,
			r.startedAt.UTC().Format(time.RFC3339), time.Since(r.startedAt).Milliseconds(),
			received, r.transmitted.Load(), r.dropped.Load(), reason,
		)
	})
}

type peripheralsWSHandler struct {
	gws.BuiltinEventHandler
	srv *Server
}

func (h *peripheralsWSHandler) OnOpen(conn *gws.Conn) {
	deviceRaw, _ := conn.Session().Load("deviceID")
	if deviceRaw == nil {
		_ = conn.WriteClose(1008, []byte("missing device"))
		return
	}
	deviceID := deviceRaw.(string)
	client, ok := h.srv.GetClient(deviceID)
	if !ok {
		data, _ := json.Marshal(peripheralMsg{Op: "error", ErrorCode: "device_offline", Message: "device is not connected"})
		_ = conn.WriteMessage(gws.OpcodeText, data)
		_ = conn.WriteClose(1001, []byte("device offline"))
		return
	}
	if !client.PeripheralV1 {
		data, _ := json.Marshal(peripheralMsg{Op: "unsupported", Message: "device client does not support peripheral debugging"})
		_ = conn.WriteMessage(gws.OpcodeText, data)
		_ = conn.WriteClose(1003, []byte("unsupported"))
		return
	}
	subjectRaw, _ := conn.Session().Load(browserSubjectSessionKey)
	subject, _ := subjectRaw.(string)
	if subject == "" {
		subject = "control-api"
	}
	socket := &peripheralSocket{conn: conn, srv: h.srv, deviceID: deviceID, instanceID: client.InstanceID, subject: subject}
	conn.Session().Store("peripheralSocket", socket)
	socket.writeText(peripheralMsg{Op: "ready", Success: true})
}

func (h *peripheralsWSHandler) OnClose(conn *gws.Conn, err error) {
	socket := peripheralSocketFromSession(conn)
	if socket == nil {
		return
	}
	h.srv.closePeripheralSocket(socket)
}

func (h *peripheralsWSHandler) OnMessage(conn *gws.Conn, message *gws.Message) {
	defer message.Close()
	socket := peripheralSocketFromSession(conn)
	if socket == nil {
		return
	}
	if message.Opcode == gws.OpcodeBinary {
		h.handleBinary(socket, message.Bytes())
		return
	}
	if message.Opcode != gws.OpcodeText {
		return
	}
	var msg peripheralMsg
	if err := json.Unmarshal(message.Bytes(), &msg); err != nil {
		socket.writeText(peripheralMsg{Op: "error", ErrorCode: "invalid_message", Message: "invalid peripheral message"})
		return
	}
	switch msg.Op {
	case "list":
		h.handleList(socket, msg)
	case "serial_open":
		h.handleOpen(socket, msg)
	case "serial_close":
		h.handleClose(socket, msg)
	default:
		socket.writeText(peripheralMsg{Op: "error", RequestID: msg.RequestID, ErrorCode: "unsupported_operation", Message: "unsupported peripheral operation"})
	}
}

func peripheralSocketFromSession(conn *gws.Conn) *peripheralSocket {
	raw, _ := conn.Session().Load("peripheralSocket")
	if raw == nil {
		return nil
	}
	return raw.(*peripheralSocket)
}

func (h *peripheralsWSHandler) currentClient(socket *peripheralSocket) (*ClientConn, bool) {
	client, ok := h.srv.GetClient(socket.deviceID)
	if !ok || client.InstanceID != socket.instanceID || !client.PeripheralV1 {
		socket.writeText(peripheralMsg{Op: "error", ErrorCode: "device_reconnected", Message: "device connection changed; reopen the peripheral workbench"})
		return nil, false
	}
	return client, true
}

func (h *peripheralsWSHandler) handleList(socket *peripheralSocket, msg peripheralMsg) {
	if msg.RequestID == "" {
		socket.writeText(peripheralMsg{Op: "list_result", ErrorCode: "invalid_request", Message: "missing requestId"})
		return
	}
	client, ok := h.currentClient(socket)
	if !ok {
		return
	}
	if h.srv.registerPeripheralRequest(msg.RequestID, socket, client) == nil {
		socket.writeText(peripheralMsg{Op: "list_result", RequestID: msg.RequestID, ErrorCode: "duplicate_request", Message: "requestId is already active"})
		return
	}
	if err := client.Send(&protocol.Message{Type: protocol.MsgPeripheralListRequest, RequestID: msg.RequestID}); err != nil {
		h.srv.removePeripheralRequest(msg.RequestID)
		socket.writeText(peripheralMsg{Op: "list_result", RequestID: msg.RequestID, ErrorCode: "device_unreachable", Message: "failed to reach device"})
	}
}

func (h *peripheralsWSHandler) handleOpen(socket *peripheralSocket, msg peripheralMsg) {
	if msg.RequestID == "" || msg.SerialPortID == "" || msg.SerialConfig == nil {
		socket.writeText(peripheralMsg{Op: "serial_open_result", RequestID: msg.RequestID, ErrorCode: "invalid_request", Message: "missing serial open fields"})
		return
	}
	client, ok := h.currentClient(socket)
	if !ok {
		return
	}
	sessionID := generateID()
	route := &serialRoute{
		sessionID:    sessionID,
		serialPortID: msg.SerialPortID,
		socket:       socket,
		subject:      socket.subject,
		client:       client,
		output:       make(chan []byte, peripheralSerialQueueSize),
		done:         make(chan struct{}),
		pumpDone:     make(chan struct{}),
		startedAt:    time.Now(),
		operation:    "open",
		requestID:    msg.RequestID,
	}
	if !h.srv.registerSerialRoute(route) {
		socket.writeText(peripheralMsg{Op: "serial_open_result", RequestID: msg.RequestID, ErrorCode: "session_conflict", Message: "serial session could not be reserved"})
		return
	}
	h.srv.scheduleSerialOperationTimeout(route, "open", msg.RequestID)
	go h.srv.pumpSerialRoute(route)
	if err := client.Send(&protocol.Message{
		Type:         protocol.MsgSerialOpen,
		RequestID:    msg.RequestID,
		SessionID:    sessionID,
		SerialPortID: msg.SerialPortID,
		SerialConfig: msg.SerialConfig,
	}); err != nil {
		h.srv.removeSerialRoute(sessionID)
		socket.writeText(peripheralMsg{Op: "serial_open_result", RequestID: msg.RequestID, SessionID: sessionID, ErrorCode: "device_unreachable", Message: "failed to reach device"})
	}
}

func (h *peripheralsWSHandler) handleClose(socket *peripheralSocket, msg peripheralMsg) {
	if msg.RequestID == "" || msg.SessionID == "" {
		socket.writeText(peripheralMsg{Op: "serial_close_result", RequestID: msg.RequestID, ErrorCode: "invalid_request", Message: "missing serial close fields"})
		return
	}
	route := h.srv.getSerialRoute(msg.SessionID)
	if route == nil || route.socket != socket {
		socket.writeText(peripheralMsg{Op: "serial_close_result", RequestID: msg.RequestID, SessionID: msg.SessionID, Success: true})
		return
	}
	if h.srv.clientByID(route.client.ID) != route.client {
		h.srv.failSerialRoute(route, "device_reconnected", "device connection changed")
		return
	}
	if !h.srv.beginSerialOperation(route, "close", msg.RequestID) {
		socket.writeText(peripheralMsg{Op: "serial_close_result", RequestID: msg.RequestID, SessionID: msg.SessionID, ErrorCode: "operation_in_progress", Message: "another serial operation is still active"})
		return
	}
	if err := route.client.Send(&protocol.Message{Type: protocol.MsgSerialClose, RequestID: msg.RequestID, SessionID: msg.SessionID}); err != nil {
		h.srv.failSerialRoute(route, "device_unreachable", "failed to reach device")
	}
}

func (h *peripheralsWSHandler) handleBinary(socket *peripheralSocket, raw []byte) {
	typ, sessionID, payload, err := protocol.DecodeBinFrame(raw)
	if err != nil || typ != protocol.BinSerialData || len(payload) == 0 {
		socket.writeText(peripheralMsg{Op: "serial_error", SessionID: sessionID, ErrorCode: "invalid_payload", Message: "invalid serial payload"})
		return
	}
	route := h.srv.getSerialRoute(sessionID)
	if route == nil || route.socket != socket || h.srv.clientByID(route.client.ID) != route.client {
		socket.writeText(peripheralMsg{Op: "serial_error", SessionID: sessionID, ErrorCode: "session_closed", Message: "serial session is not open"})
		return
	}
	if len(payload) > peripheralSerialFrameLimit {
		route.dropped.Add(uint64(len(payload)))
		_ = route.client.Send(&protocol.Message{Type: protocol.MsgSerialClose, SessionID: sessionID})
		h.srv.failSerialRoute(route, "invalid_payload", "browser sent a serial frame larger than 16384 bytes")
		return
	}
	if err = route.client.SendBinary(protocol.BinSerialData, sessionID, payload); err != nil {
		h.srv.failSerialRoute(route, "device_unreachable", "failed to write serial data")
	}
}

func (s *Server) registerPeripheralRequest(requestID string, socket *peripheralSocket, client *ClientConn) *peripheralRequestRoute {
	route := &peripheralRequestRoute{requestID: requestID, socket: socket, client: client}
	s.peripheralMu.Lock()
	if _, exists := s.peripheralRequests[requestID]; exists {
		s.peripheralMu.Unlock()
		return nil
	}
	s.peripheralRequests[requestID] = route
	s.peripheralMu.Unlock()
	s.schedulePeripheralRequestTimeoutAfter(route, peripheralControlTimeout)
	return route
}

func (s *Server) removePeripheralRequest(requestID string) *peripheralRequestRoute {
	s.peripheralMu.Lock()
	route := s.peripheralRequests[requestID]
	delete(s.peripheralRequests, requestID)
	if route != nil && route.timer != nil {
		route.timer.Stop()
		route.timer = nil
	}
	s.peripheralMu.Unlock()
	return route
}

func (s *Server) takePeripheralRequestForClient(requestID string, client *ClientConn) *peripheralRequestRoute {
	s.peripheralMu.Lock()
	defer s.peripheralMu.Unlock()
	route := s.peripheralRequests[requestID]
	if route == nil || route.client != client {
		return nil
	}
	delete(s.peripheralRequests, requestID)
	if route.timer != nil {
		route.timer.Stop()
		route.timer = nil
	}
	return route
}

func (s *Server) schedulePeripheralRequestTimeoutAfter(route *peripheralRequestRoute, wait time.Duration) {
	s.peripheralMu.Lock()
	defer s.peripheralMu.Unlock()
	if s.peripheralRequests[route.requestID] != route || route.timer != nil {
		return
	}
	route.timer = time.AfterFunc(wait, func() {
		s.peripheralMu.Lock()
		if s.peripheralRequests[route.requestID] != route {
			s.peripheralMu.Unlock()
			return
		}
		delete(s.peripheralRequests, route.requestID)
		route.timer = nil
		s.peripheralMu.Unlock()
		route.socket.writeText(peripheralMsg{Op: "list_result", RequestID: route.requestID, ErrorCode: "timeout", Message: "device did not return the peripheral list in time"})
	})
}

func (s *Server) registerSerialRoute(route *serialRoute) bool {
	s.peripheralMu.Lock()
	defer s.peripheralMu.Unlock()
	if _, exists := s.serialRoutes[route.sessionID]; exists {
		return false
	}
	for _, active := range s.serialRoutes {
		if active.client == route.client && active.serialPortID == route.serialPortID {
			return false
		}
	}
	s.serialRoutes[route.sessionID] = route
	return true
}

func (s *Server) getSerialRoute(sessionID string) *serialRoute {
	s.peripheralMu.RLock()
	defer s.peripheralMu.RUnlock()
	return s.serialRoutes[sessionID]
}

func (s *Server) removeSerialRoute(sessionID string) *serialRoute {
	return s.removeSerialRouteWithReason(sessionID, "route_removed")
}

func (s *Server) removeSerialRouteWithReason(sessionID, reason string) *serialRoute {
	s.peripheralMu.Lock()
	route := s.serialRoutes[sessionID]
	delete(s.serialRoutes, sessionID)
	if route != nil && route.timer != nil {
		route.timer.Stop()
		route.timer = nil
	}
	s.peripheralMu.Unlock()
	if route != nil {
		route.close(reason)
	}
	return route
}

func (s *Server) scheduleSerialOperationTimeout(route *serialRoute, operation, requestID string) {
	s.scheduleSerialOperationTimeoutAfter(route, operation, requestID, peripheralControlTimeout)
}

func (s *Server) scheduleSerialOperationTimeoutAfter(route *serialRoute, operation, requestID string, wait time.Duration) {
	s.peripheralMu.Lock()
	defer s.peripheralMu.Unlock()
	if s.serialRoutes[route.sessionID] != route || route.operation != operation || route.requestID != requestID || route.timer != nil {
		return
	}
	route.timer = time.AfterFunc(wait, func() {
		s.peripheralMu.Lock()
		if s.serialRoutes[route.sessionID] != route || route.operation != operation || route.requestID != requestID {
			s.peripheralMu.Unlock()
			return
		}
		delete(s.serialRoutes, route.sessionID)
		route.timer = nil
		s.peripheralMu.Unlock()
		route.close("operation_timeout")
		op := "serial_" + operation + "_result"
		route.socket.writeText(peripheralMsg{Op: op, RequestID: requestID, SessionID: route.sessionID, SerialPortID: route.serialPortID, ErrorCode: "timeout", Message: "device did not confirm the serial operation in time"})
		if operation == "open" {
			_ = route.client.Send(&protocol.Message{Type: protocol.MsgSerialClose, SessionID: route.sessionID})
		}
	})
}

func (s *Server) beginSerialOperation(route *serialRoute, operation, requestID string) bool {
	s.peripheralMu.Lock()
	if s.serialRoutes[route.sessionID] != route || route.operation != "" {
		s.peripheralMu.Unlock()
		return false
	}
	route.operation = operation
	route.requestID = requestID
	s.peripheralMu.Unlock()
	s.scheduleSerialOperationTimeout(route, operation, requestID)
	return true
}

func (s *Server) finishSerialOperation(route *serialRoute, operation, requestID string) bool {
	s.peripheralMu.Lock()
	defer s.peripheralMu.Unlock()
	if s.serialRoutes[route.sessionID] != route || route.operation != operation || route.requestID != requestID {
		return false
	}
	if route.timer != nil {
		route.timer.Stop()
		route.timer = nil
	}
	route.operation = ""
	route.requestID = ""
	return true
}

func (s *Server) pumpSerialRoute(route *serialRoute) {
	if route.pumpDone != nil {
		defer close(route.pumpDone)
	}
	for {
		select {
		case <-route.done:
			return
		default:
		}
		select {
		case data := <-route.output:
			select {
			case <-route.done:
				return
			default:
			}
			frame := protocol.EncodeBinFrame(protocol.BinSerialData, route.sessionID, data)
			if !route.socket.writeBinary(frame) {
				s.removeSerialRoute(route.sessionID)
				return
			}
			route.delivered.Add(uint64(len(data)))
		case <-route.done:
			return
		}
	}
}

func (s *Server) failSerialRoute(route *serialRoute, code, message string) {
	if s.removeSerialRouteWithReason(route.sessionID, code) == nil {
		return
	}
	go func() {
		route.finalize(code)
		route.socket.writeText(peripheralMsg{
			Op:           "serial_error",
			SessionID:    route.sessionID,
			DroppedBytes: route.dropped.Load(),
			ErrorCode:    code,
			Message:      message,
		})
	}()
}

func (s *Server) handlePeripheralMessage(client *ClientConn, msg *protocol.Message) {
	switch msg.Type {
	case protocol.MsgPeripheralListResult:
		route := s.takePeripheralRequestForClient(msg.RequestID, client)
		if route == nil {
			return
		}
		route.socket.writeText(peripheralMsg{Op: "list_result", RequestID: msg.RequestID, SerialPorts: msg.SerialPorts, Success: msg.Success, Message: msg.Error})
	case protocol.MsgSerialOpenResult:
		route := s.getSerialRoute(msg.SessionID)
		if route == nil || route.client != client {
			if msg.Success && msg.SessionID != "" {
				_ = client.Send(&protocol.Message{Type: protocol.MsgSerialClose, SessionID: msg.SessionID})
			}
			return
		}
		if !s.finishSerialOperation(route, "open", msg.RequestID) {
			return
		}
		result := peripheralMsg{Op: "serial_open_result", RequestID: msg.RequestID, SessionID: msg.SessionID, SerialPortID: msg.SerialPortID, Success: msg.Success, Message: msg.Error}
		if !msg.Success {
			s.removeSerialRoute(msg.SessionID)
		}
		if !route.socket.writeText(result) && msg.Success {
			s.removeSerialRoute(msg.SessionID)
			_ = client.Send(&protocol.Message{Type: protocol.MsgSerialClose, SessionID: msg.SessionID})
			return
		}
		if msg.Success {
			log.Printf("serial session opened: device=%s instance=%s port=%s session=%s", client.ID, client.InstanceID, msg.SerialPortID, msg.SessionID)
		}
	case protocol.MsgSerialWriteResult:
		route := s.getSerialRoute(msg.SessionID)
		if route != nil && route.client == client {
			if msg.Success && msg.BytesDone > 0 {
				route.transmitted.Add(uint64(msg.BytesDone))
			}
			route.socket.writeText(peripheralMsg{Op: "serial_write_result", SessionID: msg.SessionID, BytesDone: msg.BytesDone, Success: msg.Success, Message: msg.Error})
		}
	case protocol.MsgSerialCloseResult:
		route := s.getSerialRoute(msg.SessionID)
		if route == nil || route.client != client {
			return
		}
		if !s.finishSerialOperation(route, "close", msg.RequestID) {
			return
		}
		if s.removeSerialRouteWithReason(msg.SessionID, "client_close") == nil {
			return
		}
		route.socket.writeText(peripheralMsg{Op: "serial_close_result", RequestID: msg.RequestID, SessionID: msg.SessionID, Success: msg.Success, Message: msg.Error})
		log.Printf("serial session closed: device=%s instance=%s port=%s session=%s", client.ID, client.InstanceID, route.serialPortID, msg.SessionID)
	case protocol.MsgSerialError:
		route := s.getSerialRoute(msg.SessionID)
		if route != nil && route.client == client {
			if msg.DroppedBytes > 0 {
				route.dropped.Add(msg.DroppedBytes)
			}
			code := "device_error"
			if msg.ErrorCode == "backpressure" {
				code = "backpressure"
			}
			s.failSerialRoute(route, code, msg.Error)
		}
	}
}

func (s *Server) handleSerialData(client *ClientConn, sessionID string, payload []byte) {
	route := s.getSerialRoute(sessionID)
	if route == nil || route.client != client || len(payload) == 0 {
		return
	}
	route.inputMu.Lock()
	defer route.inputMu.Unlock()
	if s.getSerialRoute(sessionID) != route {
		return
	}
	if len(payload) > peripheralSerialFrameLimit {
		route.dropped.Add(uint64(len(payload)))
		_ = client.Send(&protocol.Message{Type: protocol.MsgSerialClose, SessionID: sessionID})
		s.failSerialRoute(route, "invalid_payload", "device sent a serial frame larger than 16384 bytes")
		return
	}
	data := append([]byte(nil), payload...)
	route.received.Add(uint64(len(data)))
	select {
	case route.output <- data:
	default:
		s.failSerialRoute(route, "backpressure", "browser could not keep up with serial input; session closed")
		go func() {
			_ = client.Send(&protocol.Message{Type: protocol.MsgSerialClose, SessionID: sessionID})
		}()
	}
}

func (s *Server) closePeripheralSocket(socket *peripheralSocket) {
	var routes []*serialRoute
	s.peripheralMu.Lock()
	for requestID, route := range s.peripheralRequests {
		if route.socket == socket {
			if route.timer != nil {
				route.timer.Stop()
				route.timer = nil
			}
			delete(s.peripheralRequests, requestID)
		}
	}
	for sessionID, route := range s.serialRoutes {
		if route.socket == socket {
			if route.timer != nil {
				route.timer.Stop()
				route.timer = nil
			}
			delete(s.serialRoutes, sessionID)
			routes = append(routes, route)
		}
	}
	s.peripheralMu.Unlock()
	for _, route := range routes {
		route.close("browser_disconnected")
		if s.clientByID(route.client.ID) == route.client {
			_ = route.client.Send(&protocol.Message{Type: protocol.MsgSerialClose, SessionID: route.sessionID})
		}
	}
}

func (s *Server) closePeripheralsForClient(client *ClientConn) {
	var routes []*serialRoute
	s.peripheralMu.Lock()
	for requestID, route := range s.peripheralRequests {
		if route.client == client {
			if route.timer != nil {
				route.timer.Stop()
				route.timer = nil
			}
			delete(s.peripheralRequests, requestID)
		}
	}
	for sessionID, route := range s.serialRoutes {
		if route.client == client {
			if route.timer != nil {
				route.timer.Stop()
				route.timer = nil
			}
			delete(s.serialRoutes, sessionID)
			routes = append(routes, route)
		}
	}
	s.peripheralMu.Unlock()
	for _, route := range routes {
		route.close("device_disconnected")
		route.socket.writeText(peripheralMsg{Op: "serial_error", SessionID: route.sessionID, ErrorCode: "device_offline", Message: "device disconnected"})
	}
}

// HandlePeripheralsWS handles the account-authorized browser peripheral channel.
func (s *Server) HandlePeripheralsWS(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	deviceID := r.URL.Query().Get("device")
	if deviceID == "" {
		http.Error(w, "missing device parameter", http.StatusBadRequest)
		return
	}
	upgrader := gws.NewUpgrader(&peripheralsWSHandler{srv: s}, &gws.ServerOption{
		ReadMaxPayloadSize: peripheralSerialFrameLimit + 1024,
		ParallelGolimit:    runtime.GOMAXPROCS(0),
		SubProtocols:       []string{browserSocketProtocol},
		Authorize: func(r *http.Request, session gws.SessionStorage) bool {
			session.Store("deviceID", deviceID)
			return s.authorizeBrowserUpgrade(r, session, deviceID)
		},
		PermessageDeflate: gws.PermessageDeflate{Enabled: false},
	})
	conn, err := upgrader.Upgrade(w, r)
	if err != nil {
		log.Printf("peripherals ws upgrade error: %v", err)
		return
	}
	if _, ok := s.trackBrowserTicketConnection(conn); !ok {
		_ = conn.WriteClose(4003, []byte("browser access expired"))
		return
	}
	defer s.untrackBrowserTicketConnection(conn)
	conn.ReadLoop()
}
