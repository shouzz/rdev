package client

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"rdev/internal/protocol"
)

type peripheralCaptureTransport struct {
	jsonCh        chan *protocol.Message
	binaryCh      chan []byte
	binaryGate    chan struct{}
	binaryEntered chan struct{}
}

func newPeripheralCaptureTransport() *peripheralCaptureTransport {
	return &peripheralCaptureTransport{
		jsonCh:   make(chan *protocol.Message, 32),
		binaryCh: make(chan []byte, 32),
	}
}

func (t *peripheralCaptureTransport) WriteJSON(data []byte) error {
	msg, err := protocol.Decode(data)
	if err != nil {
		return err
	}
	t.jsonCh <- msg
	return nil
}

func (t *peripheralCaptureTransport) WriteBinary(data []byte) error {
	if t.binaryEntered != nil {
		select {
		case t.binaryEntered <- struct{}{}:
		default:
		}
	}
	if t.binaryGate != nil {
		<-t.binaryGate
	}
	t.binaryCh <- append([]byte(nil), data...)
	return nil
}

func (*peripheralCaptureTransport) WritePing([]byte) error { return nil }
func (*peripheralCaptureTransport) Close(string) error     { return nil }

type fakePeripheralPort struct {
	readCh    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	mu        sync.Mutex
	writes    []byte
	maxWrite  int
}

func newFakePeripheralPort() *fakePeripheralPort {
	return &fakePeripheralPort{readCh: make(chan []byte, serialReceiveQueueSize+4), closed: make(chan struct{})}
}

func (p *fakePeripheralPort) Read(dst []byte) (int, error) {
	select {
	case data := <-p.readCh:
		return copy(dst, data), nil
	case <-p.closed:
		return 0, io.EOF
	}
}

func (p *fakePeripheralPort) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	limit := len(data)
	if p.maxWrite > 0 && limit > p.maxWrite {
		limit = p.maxWrite
	}
	p.writes = append(p.writes, data[:limit]...)
	return limit, nil
}

func (p *fakePeripheralPort) Close() error {
	p.closeOnce.Do(func() { close(p.closed) })
	return nil
}

type fakePeripheralDriver struct {
	ports      []protocol.SerialPortInfo
	port       *fakePeripheralPort
	openErr    error
	openErrors []error
	opens      int
}

type blockingOpenPeripheralDriver struct {
	port    peripheralPort
	entered chan struct{}
	release chan struct{}
}

func (d *blockingOpenPeripheralDriver) ListPorts() ([]protocol.SerialPortInfo, error) {
	return nil, nil
}

func (d *blockingOpenPeripheralDriver) OpenPort(string, *protocol.SerialConfig) (peripheralPort, error) {
	close(d.entered)
	<-d.release
	return d.port, nil
}

type blockingPeripheralPort struct {
	entered      chan struct{}
	release      chan struct{}
	closed       chan struct{}
	closeEntered chan struct{}
	closeRelease chan struct{}
	once         sync.Once
	active       atomic.Int32
	maximum      atomic.Int32
}

func newBlockingPeripheralPort() *blockingPeripheralPort {
	return &blockingPeripheralPort{
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (p *blockingPeripheralPort) Read([]byte) (int, error) {
	<-p.closed
	return 0, io.EOF
}

func (p *blockingPeripheralPort) Write(data []byte) (int, error) {
	active := p.active.Add(1)
	for {
		maximum := p.maximum.Load()
		if active <= maximum || p.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	p.entered <- struct{}{}
	<-p.release
	p.active.Add(-1)
	return len(data), nil
}

func (p *blockingPeripheralPort) Close() error {
	if p.closeEntered != nil {
		select {
		case p.closeEntered <- struct{}{}:
		default:
		}
	}
	if p.closeRelease != nil {
		<-p.closeRelease
	}
	p.once.Do(func() { close(p.closed) })
	return nil
}

func (d *fakePeripheralDriver) ListPorts() ([]protocol.SerialPortInfo, error) {
	return append([]protocol.SerialPortInfo(nil), d.ports...), nil
}

func (d *fakePeripheralDriver) OpenPort(string, *protocol.SerialConfig) (peripheralPort, error) {
	d.opens++
	if len(d.openErrors) > 0 {
		err := d.openErrors[0]
		d.openErrors = d.openErrors[1:]
		if err != nil {
			return nil, err
		}
	}
	if d.openErr != nil {
		return nil, d.openErr
	}
	return d.port, nil
}

func testSerialConfig() *protocol.SerialConfig {
	return &protocol.SerialConfig{BaudRate: 115200, DataBits: 8, Parity: "none", StopBits: "1", FlowControl: "none"}
}

func newPeripheralTestClient(driver peripheralDriver) (*Client, *peripheralCaptureTransport) {
	client := NewClient("wss://example.invalid", "device", "", "")
	transport := newPeripheralCaptureTransport()
	client.transport = transport
	client.peripherals = newPeripheralManager(client, driver)
	return client, transport
}

func installPeripheralTestSession(manager *peripheralManager, sessionID, portID string, port peripheralPort) *peripheralSession {
	session := newPeripheralSession(sessionID, portID, port)
	manager.mu.Lock()
	manager.sessions[sessionID] = session
	manager.portOwners[portID] = sessionID
	manager.startSessionLocked(session)
	manager.mu.Unlock()
	close(session.readStart)
	return session
}

func waitPeripheralMessage(t *testing.T, transport *peripheralCaptureTransport, typ protocol.MessageType) *protocol.Message {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case msg := <-transport.jsonCh:
			if msg.Type == typ {
				return msg
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", typ)
		}
	}
}

func TestSerialModeValidatesPortableConfiguration(t *testing.T) {
	if _, err := serialMode(testSerialConfig()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	tests := []protocol.SerialConfig{
		{BaudRate: 0, DataBits: 8, Parity: "none", StopBits: "1", FlowControl: "none"},
		{BaudRate: 115200, DataBits: 9, Parity: "none", StopBits: "1", FlowControl: "none"},
		{BaudRate: 115200, DataBits: 8, Parity: "mark", StopBits: "1", FlowControl: "none"},
		{BaudRate: 115200, DataBits: 8, Parity: "none", StopBits: "1.5", FlowControl: "none"},
		{BaudRate: 115200, DataBits: 8, Parity: "none", StopBits: "1", FlowControl: "rtscts"},
	}
	for _, config := range tests {
		if _, err := serialMode(&config); err == nil {
			t.Fatalf("invalid config accepted: %+v", config)
		}
	}
}

func TestPeripheralManagerSerialRoundTripAndExclusivePort(t *testing.T) {
	port := newFakePeripheralPort()
	port.maxWrite = 2
	driver := &fakePeripheralDriver{
		ports: []protocol.SerialPortInfo{{ID: "serial-one", Name: "COM7", USB: true, VendorID: "1234", ProductID: "ABCD"}},
		port:  port,
	}
	client, transport := newPeripheralTestClient(driver)
	manager := client.peripherals

	manager.handleList(&protocol.Message{RequestID: "list-one"})
	listed := waitPeripheralMessage(t, transport, protocol.MsgPeripheralListResult)
	if !listed.Success || len(listed.SerialPorts) != 1 || listed.SerialPorts[0].ID != "serial-one" {
		t.Fatalf("unexpected list result: %+v", listed)
	}

	manager.handleOpen(&protocol.Message{
		RequestID: "open-one", SessionID: "session-one", SerialPortID: "serial-one", SerialConfig: testSerialConfig(),
	})
	opened := waitPeripheralMessage(t, transport, protocol.MsgSerialOpenResult)
	if !opened.Success || opened.SessionID != "session-one" {
		t.Fatalf("unexpected open result: %+v", opened)
	}

	manager.handleOpen(&protocol.Message{
		RequestID: "open-two", SessionID: "session-two", SerialPortID: "serial-one", SerialConfig: testSerialConfig(),
	})
	conflict := waitPeripheralMessage(t, transport, protocol.MsgSerialOpenResult)
	if conflict.Success || conflict.Error != "serial port is already in use" || driver.opens != 1 {
		t.Fatalf("exclusive open was not enforced: %+v opens=%d", conflict, driver.opens)
	}

	port.readCh <- []byte{0x00, 0x41, 0xff}
	select {
	case frame := <-transport.binaryCh:
		typ, sessionID, payload, err := protocol.DecodeBinFrame(frame)
		if err != nil || typ != protocol.BinSerialData || sessionID != "session-one" || string(payload) != string([]byte{0x00, 0x41, 0xff}) {
			t.Fatalf("unexpected serial frame: type=%x session=%q payload=%v err=%v", typ, sessionID, payload, err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for serial data")
	}

	manager.handleWrite("session-one", []byte("hello"))
	written := waitPeripheralMessage(t, transport, protocol.MsgSerialWriteResult)
	if !written.Success || written.BytesDone != 5 {
		t.Fatalf("unexpected write result: %+v", written)
	}
	port.mu.Lock()
	gotWrite := string(port.writes)
	port.mu.Unlock()
	if gotWrite != "hello" {
		t.Fatalf("serial write mismatch: %q", gotWrite)
	}

	manager.handleClose(&protocol.Message{RequestID: "close-one", SessionID: "session-one"})
	closed := waitPeripheralMessage(t, transport, protocol.MsgSerialCloseResult)
	if !closed.Success {
		t.Fatalf("close failed: %+v", closed)
	}
	manager.handleClose(&protocol.Message{RequestID: "close-two", SessionID: "session-one"})
	if repeated := waitPeripheralMessage(t, transport, protocol.MsgSerialCloseResult); !repeated.Success {
		t.Fatalf("repeated close must be idempotent: %+v", repeated)
	}
}

func TestPeripheralManagerReportsOpenFailure(t *testing.T) {
	driver := &fakePeripheralDriver{openErr: errors.New("port busy")}
	client, transport := newPeripheralTestClient(driver)
	client.peripherals.handleOpen(&protocol.Message{
		RequestID: "open", SessionID: "session", SerialPortID: "serial", SerialConfig: testSerialConfig(),
	})
	result := waitPeripheralMessage(t, transport, protocol.MsgSerialOpenResult)
	if result.Success || result.Error != "port busy" {
		t.Fatalf("unexpected open failure: %+v", result)
	}
}

func TestPeripheralManagerRetriesOnlyAfterItsOwnRecentClose(t *testing.T) {
	port := newFakePeripheralPort()
	driver := &fakePeripheralDriver{
		port:       port,
		openErrors: []error{errors.New("still releasing"), errors.New("still releasing")},
	}
	client, transport := newPeripheralTestClient(driver)
	client.peripherals.recentClose["serial"] = time.Now()
	client.peripherals.handleOpen(&protocol.Message{
		RequestID: "open", SessionID: "session", SerialPortID: "serial", SerialConfig: testSerialConfig(),
	})
	result := waitPeripheralMessage(t, transport, protocol.MsgSerialOpenResult)
	if !result.Success || driver.opens != 3 {
		t.Fatalf("recently closed port was not retried: result=%+v opens=%d", result, driver.opens)
	}
	client.peripherals.closeAll()

	failingDriver := &fakePeripheralDriver{openErr: errors.New("owned elsewhere")}
	failingClient, failingTransport := newPeripheralTestClient(failingDriver)
	failingClient.peripherals.handleOpen(&protocol.Message{
		RequestID: "open", SessionID: "session", SerialPortID: "serial", SerialConfig: testSerialConfig(),
	})
	failure := waitPeripheralMessage(t, failingTransport, protocol.MsgSerialOpenResult)
	if failure.Success || failingDriver.opens != 1 {
		t.Fatalf("unrelated port failure was retried: result=%+v opens=%d", failure, failingDriver.opens)
	}
}

func TestPeripheralManagerRejectsOversizedWrite(t *testing.T) {
	client, transport := newPeripheralTestClient(&fakePeripheralDriver{})
	client.peripherals.handleWrite("missing", make([]byte, serialWriteLimitBytes+1))
	result := waitPeripheralMessage(t, transport, protocol.MsgSerialError)
	if result.Error != "serial write payload is empty or too large" {
		t.Fatalf("unexpected write error: %+v", result)
	}
}

func TestPeripheralManagerSerializesWritesPerSession(t *testing.T) {
	client, transport := newPeripheralTestClient(&fakePeripheralDriver{})
	port := newBlockingPeripheralPort()
	session := installPeripheralTestSession(client.peripherals, "session", "port", port)

	client.peripherals.handleWrite("session", []byte("first"))
	select {
	case <-port.entered:
	case <-time.After(time.Second):
		t.Fatal("first write did not enter the driver")
	}
	client.peripherals.handleWrite("session", []byte("second"))
	select {
	case <-port.entered:
		t.Fatal("second write entered the driver before the first write completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(port.release)
	if result := waitPeripheralMessage(t, transport, protocol.MsgSerialWriteResult); !result.Success {
		t.Fatalf("first write failed: %+v", result)
	}
	if result := waitPeripheralMessage(t, transport, protocol.MsgSerialWriteResult); !result.Success {
		t.Fatalf("second write failed: %+v", result)
	}
	if port.maximum.Load() != 1 {
		t.Fatalf("maximum concurrent writes = %d, want 1", port.maximum.Load())
	}
	client.peripherals.closeAll()
	select {
	case <-session.workersDone:
	case <-time.After(time.Second):
		t.Fatal("serial workers did not stop")
	}
}

func TestPeripheralManagerTransmitQueueBackpressureClosesSession(t *testing.T) {
	client, transport := newPeripheralTestClient(&fakePeripheralDriver{})
	port := newBlockingPeripheralPort()
	port.closeEntered = make(chan struct{}, 1)
	port.closeRelease = make(chan struct{})
	session := installPeripheralTestSession(client.peripherals, "session", "port", port)
	client.peripherals.handleWrite("session", []byte("blocked"))
	select {
	case <-port.entered:
	case <-time.After(time.Second):
		t.Fatal("first write did not enter the driver")
	}
	for i := 0; i < serialTransmitQueueSize; i++ {
		client.peripherals.handleWrite("session", []byte{byte(i)})
	}
	dropped := []byte("overflow")
	returned := make(chan struct{})
	go func() {
		client.peripherals.handleWrite("session", dropped)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("transmit backpressure blocked on serial close")
	}
	select {
	case <-port.closeEntered:
	case <-time.After(time.Second):
		t.Fatal("transmit backpressure did not start serial close")
	}
	client.peripherals.mu.Lock()
	_, exists := client.peripherals.sessions[session.id]
	client.peripherals.mu.Unlock()
	if exists {
		t.Fatal("backpressured transmit session remained registered")
	}
	close(port.closeRelease)
	close(port.release)
	result := waitPeripheralMessage(t, transport, protocol.MsgSerialError)
	wantDropped := uint64(serialTransmitQueueSize + len(dropped))
	if result.ErrorCode != serialBackpressureCode || result.DroppedBytes != wantDropped {
		t.Fatalf("unexpected transmit backpressure result: %+v, want dropped=%d", result, wantDropped)
	}
	select {
	case <-session.workersDone:
	case <-time.After(time.Second):
		t.Fatal("backpressured transmit workers did not stop")
	}
}

func TestPeripheralManagerReceiveQueueBackpressureClosesSession(t *testing.T) {
	client, transport := newPeripheralTestClient(&fakePeripheralDriver{})
	transport.binaryGate = make(chan struct{})
	transport.binaryEntered = make(chan struct{}, 1)
	port := newFakePeripheralPort()
	session := installPeripheralTestSession(client.peripherals, "session", "port", port)
	port.readCh <- []byte("blocked")
	select {
	case <-transport.binaryEntered:
	case <-time.After(time.Second):
		t.Fatal("first receive did not enter the transport")
	}
	for i := 0; i < serialReceiveQueueSize+1; i++ {
		port.readCh <- []byte{byte(i)}
	}
	deadline := time.After(time.Second)
	for {
		client.peripherals.mu.Lock()
		_, exists := client.peripherals.sessions[session.id]
		client.peripherals.mu.Unlock()
		if !exists {
			break
		}
		select {
		case <-deadline:
			t.Fatal("receive backpressure did not detach the session")
		case <-time.After(time.Millisecond):
		}
	}
	close(transport.binaryGate)
	result := waitPeripheralMessage(t, transport, protocol.MsgSerialError)
	wantDropped := uint64(serialReceiveQueueSize + 1)
	if result.ErrorCode != serialBackpressureCode || result.DroppedBytes != wantDropped {
		t.Fatalf("unexpected receive backpressure result: %+v, want dropped=%d", result, wantDropped)
	}
	select {
	case <-session.workersDone:
	case <-time.After(time.Second):
		t.Fatal("backpressured receive workers did not stop")
	}
}

func TestPeripheralManagerCancelsOpeningSession(t *testing.T) {
	port := newFakePeripheralPort()
	driver := &blockingOpenPeripheralDriver{port: port, entered: make(chan struct{}), release: make(chan struct{})}
	client, transport := newPeripheralTestClient(driver)
	opened := make(chan struct{})
	go func() {
		client.peripherals.handleOpen(&protocol.Message{
			RequestID: "open", SessionID: "session", SerialPortID: "port", SerialConfig: testSerialConfig(),
		})
		close(opened)
	}()
	select {
	case <-driver.entered:
	case <-time.After(time.Second):
		t.Fatal("serial open did not enter the driver")
	}
	client.peripherals.handleClose(&protocol.Message{RequestID: "close", SessionID: "session"})
	if result := waitPeripheralMessage(t, transport, protocol.MsgSerialCloseResult); !result.Success {
		t.Fatalf("opening cancellation failed: %+v", result)
	}
	close(driver.release)
	select {
	case <-opened:
	case <-time.After(time.Second):
		t.Fatal("cancelled serial open did not return")
	}
	select {
	case <-port.closed:
	case <-time.After(time.Second):
		t.Fatal("port returned by cancelled open was not closed")
	}
	client.peripherals.mu.Lock()
	defer client.peripherals.mu.Unlock()
	if len(client.peripherals.sessions) != 0 || len(client.peripherals.openings) != 0 || len(client.peripherals.portOwners) != 0 {
		t.Fatalf("cancelled open leaked manager state: sessions=%d openings=%d owners=%d",
			len(client.peripherals.sessions), len(client.peripherals.openings), len(client.peripherals.portOwners))
	}
}

func TestPeripheralManagerCloseReportsBlockedWriter(t *testing.T) {
	client, transport := newPeripheralTestClient(&fakePeripheralDriver{})
	port := newBlockingPeripheralPort()
	session := installPeripheralTestSession(client.peripherals, "session", "port", port)
	client.peripherals.handleWrite("session", []byte("blocked"))
	select {
	case <-port.entered:
	case <-time.After(time.Second):
		t.Fatal("write did not enter the driver")
	}
	client.peripherals.handleClose(&protocol.Message{RequestID: "close", SessionID: "session"})
	result := waitPeripheralMessage(t, transport, protocol.MsgSerialCloseResult)
	if result.Success || result.Error != "serial workers did not stop after close" {
		t.Fatalf("unexpected close result for blocked writer: %+v", result)
	}
	close(port.release)
	select {
	case <-session.workersDone:
	case <-time.After(time.Second):
		t.Fatal("blocked writer did not stop after release")
	}
}

func TestClientCleanupClosesPeripheralSessions(t *testing.T) {
	client, _ := newPeripheralTestClient(&fakePeripheralDriver{})
	port := newFakePeripheralPort()
	session := installPeripheralTestSession(client.peripherals, "session", "port", port)
	client.cleanup()
	select {
	case <-port.closed:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not close the peripheral port")
	}
	select {
	case <-session.workersDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not stop peripheral workers")
	}
	client.peripherals.mu.Lock()
	defer client.peripherals.mu.Unlock()
	if len(client.peripherals.sessions) != 0 || len(client.peripherals.portOwners) != 0 {
		t.Fatal("cleanup left peripheral session state")
	}
}

func TestReleasePortReservationRequiresExactSession(t *testing.T) {
	client, _ := newPeripheralTestClient(&fakePeripheralDriver{})
	client.peripherals.portOwners["port"] = "new-session"
	client.peripherals.releasePortReservation("port", "old-session")
	if client.peripherals.portOwners["port"] != "new-session" {
		t.Fatal("stale open failure released the current port reservation")
	}
	client.peripherals.releasePortReservation("port", "new-session")
	if _, exists := client.peripherals.portOwners["port"]; exists {
		t.Fatal("current session did not release its port reservation")
	}
}
