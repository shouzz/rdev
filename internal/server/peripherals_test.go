package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lxzan/gws"
	"rdev/internal/protocol"
)

type peripheralServerCaptureTransport struct {
	jsonCh      chan *protocol.Message
	binaryCh    chan []byte
	jsonGate    chan struct{}
	jsonEntered chan struct{}
}

func newPeripheralServerCaptureTransport() *peripheralServerCaptureTransport {
	return &peripheralServerCaptureTransport{jsonCh: make(chan *protocol.Message, 16), binaryCh: make(chan []byte, 16)}
}

func (t *peripheralServerCaptureTransport) WriteJSON(data []byte) error {
	msg, err := protocol.Decode(data)
	if err != nil {
		return err
	}
	if t.jsonEntered != nil {
		select {
		case t.jsonEntered <- struct{}{}:
		default:
		}
	}
	if t.jsonGate != nil {
		<-t.jsonGate
	}
	t.jsonCh <- msg
	return nil
}

func (t *peripheralServerCaptureTransport) WriteBinary(data []byte) error {
	t.binaryCh <- append([]byte(nil), data...)
	return nil
}

func (*peripheralServerCaptureTransport) WritePing([]byte) error { return nil }
func (*peripheralServerCaptureTransport) Close(string) error     { return nil }
func (*peripheralServerCaptureTransport) RemoteAddr() string     { return "127.0.0.1:1" }

type peripheralBrowserCapture struct {
	gws.BuiltinEventHandler
	textCh   chan peripheralMsg
	binaryCh chan []byte
}

type blockingSerialRouteSocket struct {
	binaryEntered chan struct{}
	releaseBinary chan struct{}
	textCh        chan peripheralMsg
}

func newBlockingSerialRouteSocket() *blockingSerialRouteSocket {
	return &blockingSerialRouteSocket{
		binaryEntered: make(chan struct{}, 1),
		releaseBinary: make(chan struct{}),
		textCh:        make(chan peripheralMsg, 1),
	}
}

func (socket *blockingSerialRouteSocket) writeText(msg peripheralMsg) bool {
	socket.textCh <- msg
	return true
}

func (socket *blockingSerialRouteSocket) writeBinary([]byte) bool {
	socket.binaryEntered <- struct{}{}
	<-socket.releaseBinary
	return true
}

func newPeripheralBrowserCapture() *peripheralBrowserCapture {
	return &peripheralBrowserCapture{textCh: make(chan peripheralMsg, 16), binaryCh: make(chan []byte, 16)}
}

func (h *peripheralBrowserCapture) OnMessage(_ *gws.Conn, message *gws.Message) {
	defer message.Close()
	if message.Opcode == gws.OpcodeBinary {
		h.binaryCh <- append([]byte(nil), message.Bytes()...)
		return
	}
	var msg peripheralMsg
	if json.Unmarshal(message.Bytes(), &msg) == nil {
		h.textCh <- msg
	}
}

func waitPeripheralBrowserMessage(t *testing.T, capture *peripheralBrowserCapture, op string) peripheralMsg {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case msg := <-capture.textCh:
			if msg.Op == op {
				return msg
			}
		case <-deadline:
			t.Fatalf("timed out waiting for browser op %q", op)
		}
	}
}

func waitPeripheralDeviceMessage(t *testing.T, capture *peripheralServerCaptureTransport, typ protocol.MessageType) *protocol.Message {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case msg := <-capture.jsonCh:
			if msg.Type == typ {
				return msg
			}
		case <-deadline:
			t.Fatalf("timed out waiting for device message %q", typ)
		}
	}
}

func TestSerialRouteIsExclusivePerDeviceConnectionAndPort(t *testing.T) {
	srv := NewServer()
	client := &ClientConn{ID: "device", InstanceID: "instance"}
	first := &serialRoute{
		sessionID: "session-one", serialPortID: "port-one", client: client,
		output: make(chan []byte, 1), done: make(chan struct{}),
	}
	if !srv.registerSerialRoute(first) {
		t.Fatal("first serial route was rejected")
	}
	conflict := &serialRoute{
		sessionID: "session-two", serialPortID: "port-one", client: client,
		output: make(chan []byte, 1), done: make(chan struct{}),
	}
	if srv.registerSerialRoute(conflict) {
		t.Fatal("same device connection opened the same port twice")
	}
	otherPort := &serialRoute{
		sessionID: "session-three", serialPortID: "port-two", client: client,
		output: make(chan []byte, 1), done: make(chan struct{}),
	}
	if !srv.registerSerialRoute(otherPort) {
		t.Fatal("different port was rejected")
	}
	srv.removeSerialRoute(first.sessionID)
	srv.removeSerialRoute(otherPort.sessionID)
}

func TestHandleSerialDataRequiresExactClientConnection(t *testing.T) {
	srv := NewServer()
	current := &ClientConn{ID: "device", InstanceID: "instance-two"}
	stale := &ClientConn{ID: "device", InstanceID: "instance-one"}
	route := &serialRoute{
		sessionID: "session", serialPortID: "port", client: current,
		output: make(chan []byte, 1), done: make(chan struct{}),
	}
	if !srv.registerSerialRoute(route) {
		t.Fatal("route registration failed")
	}

	srv.handleSerialData(stale, route.sessionID, []byte("stale"))
	select {
	case <-route.output:
		t.Fatal("data from stale client connection was accepted")
	default:
	}

	srv.handleSerialData(current, route.sessionID, []byte("current"))
	select {
	case data := <-route.output:
		if string(data) != "current" {
			t.Fatalf("unexpected payload %q", data)
		}
	case <-time.After(time.Second):
		t.Fatal("current client payload was not routed")
	}
	srv.removeSerialRoute(route.sessionID)
}

func TestHandleSerialDataBackpressureReportsAllUndeliveredBytes(t *testing.T) {
	srv := NewServer()
	deviceTransport := newPeripheralServerCaptureTransport()
	client := &ClientConn{ID: "device", InstanceID: "instance", Transport: deviceTransport}
	socket := newBlockingSerialRouteSocket()
	route := &serialRoute{
		sessionID: "session", serialPortID: "port", socket: socket, subject: "test-subject", client: client,
		output: make(chan []byte, 2), done: make(chan struct{}), pumpDone: make(chan struct{}), startedAt: time.Now(),
	}
	if !srv.registerSerialRoute(route) {
		t.Fatal("route registration failed")
	}
	go srv.pumpSerialRoute(route)

	inFlight := []byte("sent")
	queuedOne := []byte("queued-one")
	queuedTwo := []byte("queued-two-longer")
	overflow := []byte("overflow")
	srv.handleSerialData(client, route.sessionID, inFlight)
	select {
	case <-socket.binaryEntered:
	case <-time.After(time.Second):
		t.Fatal("first browser write did not block")
	}
	srv.handleSerialData(client, route.sessionID, queuedOne)
	srv.handleSerialData(client, route.sessionID, queuedTwo)
	deviceTransport.jsonGate = make(chan struct{})
	deviceTransport.jsonEntered = make(chan struct{}, 1)
	overflowReturned := make(chan struct{})
	go func() {
		srv.handleSerialData(client, route.sessionID, overflow)
		close(overflowReturned)
	}()
	select {
	case <-overflowReturned:
	case <-time.After(time.Second):
		t.Fatal("server backpressure blocked on the device close message")
	}
	if current := srv.getSerialRoute(route.sessionID); current != nil {
		t.Fatal("backpressured route remained registered")
	}
	select {
	case <-deviceTransport.jsonEntered:
	case <-time.After(time.Second):
		t.Fatal("server backpressure did not start the device close message")
	}
	close(deviceTransport.jsonGate)
	closeRequest := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialClose)
	if closeRequest.SessionID != route.sessionID {
		t.Fatalf("unexpected device close request: %+v", closeRequest)
	}
	close(socket.releaseBinary)

	var reported peripheralMsg
	select {
	case reported = <-socket.textCh:
	case <-time.After(time.Second):
		t.Fatal("backpressure error was not reported after the browser writer stopped")
	}
	wantDropped := uint64(len(queuedOne) + len(queuedTwo) + len(overflow))
	if reported.Op != "serial_error" || reported.ErrorCode != "backpressure" || reported.DroppedBytes != wantDropped {
		t.Fatalf("unexpected final backpressure report: %+v, want dropped=%d", reported, wantDropped)
	}
	if route.delivered.Load() != uint64(len(inFlight)) {
		t.Fatalf("delivered bytes = %d, want %d", route.delivered.Load(), len(inFlight))
	}
	if route.dropped.Load() != wantDropped {
		t.Fatalf("audited dropped bytes = %d, want %d", route.dropped.Load(), wantDropped)
	}
}

func TestPeripheralListResultRequiresExactClientConnection(t *testing.T) {
	srv := NewServer()
	current := &ClientConn{ID: "device", InstanceID: "instance-two"}
	stale := &ClientConn{ID: "device", InstanceID: "instance-one"}
	route := &peripheralRequestRoute{requestID: "list-one", client: current}
	srv.peripheralRequests[route.requestID] = route

	if taken := srv.takePeripheralRequestForClient(route.requestID, stale); taken != nil {
		t.Fatal("stale client connection took the current peripheral request")
	}
	if srv.peripheralRequests[route.requestID] != route {
		t.Fatal("stale client connection removed the current peripheral request")
	}
	if taken := srv.takePeripheralRequestForClient(route.requestID, current); taken != route {
		t.Fatal("current client connection did not take its peripheral request")
	}
	if _, exists := srv.peripheralRequests[route.requestID]; exists {
		t.Fatal("completed peripheral request remained registered")
	}
}

func TestPeripheralBrowserAndDeviceRoundTrip(t *testing.T) {
	srv := NewServer()
	srv.ControlToken = "control-secret"
	deviceTransport := newPeripheralServerCaptureTransport()
	client := &ClientConn{
		ID: "device", InstanceID: "instance", PeripheralV1: true, Transport: deviceTransport,
		Sessions: make(map[string]*ProxySession), Forwards: make(map[string]*ProxyForward),
	}
	srv.clients[client.ID] = client
	ticket := issueScopedAccessTicketWithSubject(
		t, srv, client.ID, "feidu-browser:42", 60, []string{browserCapabilityPeripherals},
	)
	httpServer := httptest.NewServer(http.HandlerFunc(srv.HandlePeripheralsWS))
	t.Cleanup(httpServer.Close)

	browserCapture := newPeripheralBrowserCapture()
	header := make(http.Header)
	header.Set("Sec-WebSocket-Protocol", browserSocketProtocol+", "+browserTicketProtocol+ticket)
	browser, _, err := gws.NewClient(browserCapture, &gws.ClientOption{
		Addr:          "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/peripherals?device=device",
		RequestHeader: header,
	})
	if err != nil {
		t.Fatalf("connect browser: %v", err)
	}
	go browser.ReadLoop()
	t.Cleanup(func() { _ = browser.WriteClose(1000, nil) })
	if ready := waitPeripheralBrowserMessage(t, browserCapture, "ready"); !ready.Success {
		t.Fatalf("unexpected ready message: %+v", ready)
	}

	listRequest := peripheralMsg{Op: "list", RequestID: "list-one"}
	listData, _ := json.Marshal(listRequest)
	if err = browser.WriteMessage(gws.OpcodeText, listData); err != nil {
		t.Fatalf("send list: %v", err)
	}
	deviceList := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgPeripheralListRequest)
	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgPeripheralListResult, RequestID: deviceList.RequestID, Success: true,
		SerialPorts: []protocol.SerialPortInfo{{ID: "port-one", Name: "COM7", USB: true}},
	})
	listed := waitPeripheralBrowserMessage(t, browserCapture, "list_result")
	if !listed.Success || len(listed.SerialPorts) != 1 || listed.SerialPorts[0].Name != "COM7" {
		t.Fatalf("unexpected browser list result: %+v", listed)
	}

	openRequest := peripheralMsg{
		Op: "serial_open", RequestID: "open-one", SerialPortID: "port-one",
		SerialConfig: &protocol.SerialConfig{BaudRate: 115200, DataBits: 8, Parity: "none", StopBits: "1", FlowControl: "none"},
	}
	openData, _ := json.Marshal(openRequest)
	if err = browser.WriteMessage(gws.OpcodeText, openData); err != nil {
		t.Fatalf("send open: %v", err)
	}
	deviceOpen := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialOpen)
	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgSerialOpenResult, RequestID: deviceOpen.RequestID, SessionID: deviceOpen.SessionID,
		SerialPortID: deviceOpen.SerialPortID, Success: true,
	})
	opened := waitPeripheralBrowserMessage(t, browserCapture, "serial_open_result")
	if !opened.Success || opened.SessionID != deviceOpen.SessionID {
		t.Fatalf("unexpected browser open result: %+v", opened)
	}

	uplink := protocol.EncodeBinFrame(protocol.BinSerialData, opened.SessionID, []byte("browser-to-device"))
	if err = browser.WriteMessage(gws.OpcodeBinary, uplink); err != nil {
		t.Fatalf("send serial data: %v", err)
	}
	select {
	case frame := <-deviceTransport.binaryCh:
		typ, sessionID, payload, decodeErr := protocol.DecodeBinFrame(frame)
		if decodeErr != nil || typ != protocol.BinSerialData || sessionID != opened.SessionID || string(payload) != "browser-to-device" {
			t.Fatalf("unexpected device serial frame: type=%x session=%q payload=%q err=%v", typ, sessionID, payload, decodeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for browser-to-device data")
	}

	srv.handleClientBinary(client, protocol.EncodeBinFrame(protocol.BinSerialData, opened.SessionID, []byte("device-to-browser")))
	select {
	case frame := <-browserCapture.binaryCh:
		typ, sessionID, payload, decodeErr := protocol.DecodeBinFrame(frame)
		if decodeErr != nil || typ != protocol.BinSerialData || sessionID != opened.SessionID || string(payload) != "device-to-browser" {
			t.Fatalf("unexpected browser serial frame: type=%x session=%q payload=%q err=%v", typ, sessionID, payload, decodeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for device-to-browser data")
	}

	closeRequest := peripheralMsg{Op: "serial_close", RequestID: "close-one", SessionID: opened.SessionID}
	closeData, _ := json.Marshal(closeRequest)
	if err = browser.WriteMessage(gws.OpcodeText, closeData); err != nil {
		t.Fatalf("send close: %v", err)
	}
	deviceClose := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialClose)
	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgSerialCloseResult, RequestID: deviceClose.RequestID, SessionID: deviceClose.SessionID, Success: true,
	})
	closed := waitPeripheralBrowserMessage(t, browserCapture, "serial_close_result")
	if !closed.Success || closed.SessionID != opened.SessionID {
		t.Fatalf("unexpected browser close result: %+v", closed)
	}

	reopenRequest := openRequest
	reopenRequest.RequestID = "open-two"
	reopenData, _ := json.Marshal(reopenRequest)
	if err = browser.WriteMessage(gws.OpcodeText, reopenData); err != nil {
		t.Fatalf("send reopen: %v", err)
	}
	deviceReopen := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialOpen)
	if deviceReopen.SerialPortID != openRequest.SerialPortID || deviceReopen.SessionID == opened.SessionID {
		t.Fatalf("unexpected device reopen request: %+v", deviceReopen)
	}
	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgSerialOpenResult, RequestID: deviceReopen.RequestID, SessionID: deviceReopen.SessionID,
		SerialPortID: deviceReopen.SerialPortID, Success: true,
	})
	reopened := waitPeripheralBrowserMessage(t, browserCapture, "serial_open_result")
	if !reopened.Success || reopened.SessionID != deviceReopen.SessionID {
		t.Fatalf("unexpected browser reopen result: %+v", reopened)
	}

	srv.handleSerialData(client, reopened.SessionID, make([]byte, peripheralSerialFrameLimit+1))
	oversized := waitPeripheralBrowserMessage(t, browserCapture, "serial_error")
	if oversized.ErrorCode != "invalid_payload" || oversized.DroppedBytes != peripheralSerialFrameLimit+1 {
		t.Fatalf("oversized device frame was not rejected precisely: %+v", oversized)
	}
	deviceCloseAfterOversized := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialClose)
	if deviceCloseAfterOversized.SessionID != reopened.SessionID {
		t.Fatalf("unexpected oversized-frame close request: %+v", deviceCloseAfterOversized)
	}

	browserOversizeOpen := openRequest
	browserOversizeOpen.RequestID = "open-browser-oversize"
	browserOversizeOpenData, _ := json.Marshal(browserOversizeOpen)
	if err = browser.WriteMessage(gws.OpcodeText, browserOversizeOpenData); err != nil {
		t.Fatalf("send browser-oversize open: %v", err)
	}
	browserOversizeDeviceOpen := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialOpen)
	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgSerialOpenResult, RequestID: browserOversizeDeviceOpen.RequestID,
		SessionID: browserOversizeDeviceOpen.SessionID, SerialPortID: browserOversizeDeviceOpen.SerialPortID, Success: true,
	})
	browserOversizeOpened := waitPeripheralBrowserMessage(t, browserCapture, "serial_open_result")
	if !browserOversizeOpened.Success || browserOversizeOpened.SessionID != browserOversizeDeviceOpen.SessionID {
		t.Fatalf("unexpected browser-oversize open result: %+v", browserOversizeOpened)
	}
	if err = browser.WriteMessage(
		gws.OpcodeBinary,
		protocol.EncodeBinFrame(protocol.BinSerialData, browserOversizeOpened.SessionID, make([]byte, peripheralSerialFrameLimit+1)),
	); err != nil {
		t.Fatalf("send oversized browser serial frame: %v", err)
	}
	browserOversized := waitPeripheralBrowserMessage(t, browserCapture, "serial_error")
	if browserOversized.ErrorCode != "invalid_payload" || browserOversized.DroppedBytes != peripheralSerialFrameLimit+1 {
		t.Fatalf("oversized browser frame was not rejected precisely: %+v", browserOversized)
	}
	browserOversizeClose := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialClose)
	if browserOversizeClose.SessionID != browserOversizeOpened.SessionID {
		t.Fatalf("unexpected browser oversized-frame close request: %+v", browserOversizeClose)
	}

	backpressureOpen := openRequest
	backpressureOpen.RequestID = "open-backpressure"
	backpressureOpenData, _ := json.Marshal(backpressureOpen)
	if err = browser.WriteMessage(gws.OpcodeText, backpressureOpenData); err != nil {
		t.Fatalf("send backpressure open: %v", err)
	}
	backpressureDeviceOpen := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialOpen)
	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgSerialOpenResult, RequestID: backpressureDeviceOpen.RequestID,
		SessionID: backpressureDeviceOpen.SessionID, SerialPortID: backpressureDeviceOpen.SerialPortID, Success: true,
	})
	backpressureOpened := waitPeripheralBrowserMessage(t, browserCapture, "serial_open_result")
	if !backpressureOpened.Success || backpressureOpened.SessionID != backpressureDeviceOpen.SessionID {
		t.Fatalf("unexpected backpressure open result: %+v", backpressureOpened)
	}
	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgSerialError, SessionID: backpressureOpened.SessionID,
		ErrorCode: "backpressure", Error: "serial receive queue is full; session closed", DroppedBytes: 7,
	})
	backpressureError := waitPeripheralBrowserMessage(t, browserCapture, "serial_error")
	if backpressureError.ErrorCode != "backpressure" || backpressureError.DroppedBytes != 7 {
		t.Fatalf("client backpressure was not reported precisely: %+v", backpressureError)
	}

	unknownErrorOpen := openRequest
	unknownErrorOpen.RequestID = "open-unknown-error"
	unknownErrorOpenData, _ := json.Marshal(unknownErrorOpen)
	if err = browser.WriteMessage(gws.OpcodeText, unknownErrorOpenData); err != nil {
		t.Fatalf("send unknown-error open: %v", err)
	}
	unknownErrorDeviceOpen := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialOpen)
	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgSerialOpenResult, RequestID: unknownErrorDeviceOpen.RequestID,
		SessionID: unknownErrorDeviceOpen.SessionID, SerialPortID: unknownErrorDeviceOpen.SerialPortID, Success: true,
	})
	unknownErrorOpened := waitPeripheralBrowserMessage(t, browserCapture, "serial_open_result")
	if !unknownErrorOpened.Success || unknownErrorOpened.SessionID != unknownErrorDeviceOpen.SessionID {
		t.Fatalf("unexpected unknown-error open result: %+v", unknownErrorOpened)
	}
	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgSerialError, SessionID: unknownErrorOpened.SessionID,
		ErrorCode: "future-client-code", Error: "future client error", DroppedBytes: 3,
	})
	unknownError := waitPeripheralBrowserMessage(t, browserCapture, "serial_error")
	if unknownError.ErrorCode != "device_error" || unknownError.DroppedBytes != 3 {
		t.Fatalf("unknown client error code was not normalized: %+v", unknownError)
	}

	timedListData, _ := json.Marshal(peripheralMsg{Op: "list", RequestID: "list-timeout"})
	if err = browser.WriteMessage(gws.OpcodeText, timedListData); err != nil {
		t.Fatalf("send timed list: %v", err)
	}
	_ = waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgPeripheralListRequest)
	srv.peripheralMu.Lock()
	timedListRoute := srv.peripheralRequests["list-timeout"]
	if timedListRoute == nil {
		srv.peripheralMu.Unlock()
		t.Fatal("timed list route was not registered")
	}
	timedListRoute.timer.Stop()
	timedListRoute.timer = nil
	srv.peripheralMu.Unlock()
	srv.schedulePeripheralRequestTimeoutAfter(timedListRoute, 10*time.Millisecond)
	timedList := waitPeripheralBrowserMessage(t, browserCapture, "list_result")
	if timedList.RequestID != "list-timeout" || timedList.ErrorCode != "timeout" {
		t.Fatalf("unexpected list timeout result: %+v", timedList)
	}

	timedOpenData, _ := json.Marshal(peripheralMsg{
		Op: "serial_open", RequestID: "open-timeout", SerialPortID: "port-one", SerialConfig: openRequest.SerialConfig,
	})
	if err = browser.WriteMessage(gws.OpcodeText, timedOpenData); err != nil {
		t.Fatalf("send timed open: %v", err)
	}
	timedDeviceOpen := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialOpen)
	timedRoute := srv.getSerialRoute(timedDeviceOpen.SessionID)
	if timedRoute == nil {
		t.Fatal("timed serial route was not registered")
	}
	srv.peripheralMu.Lock()
	timedRoute.timer.Stop()
	timedRoute.timer = nil
	srv.peripheralMu.Unlock()
	srv.scheduleSerialOperationTimeoutAfter(timedRoute, "open", "open-timeout", 10*time.Millisecond)
	timedOpen := waitPeripheralBrowserMessage(t, browserCapture, "serial_open_result")
	if timedOpen.RequestID != "open-timeout" || timedOpen.ErrorCode != "timeout" {
		t.Fatalf("unexpected serial open timeout result: %+v", timedOpen)
	}
	timeoutClose := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialClose)
	if timeoutClose.SessionID != timedDeviceOpen.SessionID {
		t.Fatalf("timed-out open was not cancelled on the device: %+v", timeoutClose)
	}

	srv.handleClientMessage(client, &protocol.Message{
		Type: protocol.MsgSerialOpenResult, RequestID: timedDeviceOpen.RequestID, SessionID: timedDeviceOpen.SessionID,
		SerialPortID: timedDeviceOpen.SerialPortID, Success: true,
	})
	lateClose := waitPeripheralDeviceMessage(t, deviceTransport, protocol.MsgSerialClose)
	if lateClose.SessionID != timedDeviceOpen.SessionID {
		t.Fatalf("late successful open was not closed idempotently: %+v", lateClose)
	}
}
