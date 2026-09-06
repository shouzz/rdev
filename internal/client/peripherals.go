package client

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
	"rdev/internal/protocol"
)

const (
	serialReadBufferBytes   = 16 * 1024
	serialWriteLimitBytes   = 16 * 1024
	serialTransmitQueueSize = 64
	serialReceiveQueueSize  = 64
	serialReadTimeout       = 250 * time.Millisecond
	serialCloseWait         = time.Second
	serialReopenWindow      = time.Second
	serialReopenInterval    = 50 * time.Millisecond
	serialBackpressureCode  = "backpressure"
)

type peripheralPort interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

type peripheralDriver interface {
	ListPorts() ([]protocol.SerialPortInfo, error)
	OpenPort(string, *protocol.SerialConfig) (peripheralPort, error)
}

type systemPeripheralDriver struct{}

type peripheralSession struct {
	id               string
	portID           string
	port             peripheralPort
	transmit         chan []byte
	receive          chan []byte
	readStart        chan struct{}
	done             chan struct{}
	workersDone      chan struct{}
	workers          sync.WaitGroup
	closeOnce        sync.Once
	transmitAccepted atomic.Uint64
	transmitWritten  atomic.Uint64
	receiveRead      atomic.Uint64
	receiveDelivered atomic.Uint64
}

func (s *peripheralSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.port.Close()
	})
}

type peripheralOpening struct {
	portID     string
	generation uint64
	cancelled  bool
}

type peripheralFailureFlow uint8

const (
	peripheralFailureTransmit peripheralFailureFlow = iota + 1
	peripheralFailureReceive
)

type peripheralManager struct {
	client      *Client
	driver      peripheralDriver
	mu          sync.Mutex
	sessions    map[string]*peripheralSession
	openings    map[string]*peripheralOpening
	portOwners  map[string]string
	recentClose map[string]time.Time
	generation  uint64
}

func newPeripheralManager(client *Client, driver peripheralDriver) *peripheralManager {
	return &peripheralManager{
		client:      client,
		driver:      driver,
		sessions:    make(map[string]*peripheralSession),
		openings:    make(map[string]*peripheralOpening),
		portOwners:  make(map[string]string),
		recentClose: make(map[string]time.Time),
	}
}

func serialPortID(name string) string {
	digest := sha256.Sum256([]byte(runtime.GOOS + "\x00" + name))
	return "serial_" + hex.EncodeToString(digest[:])
}

func (systemPeripheralDriver) ListPorts() ([]protocol.SerialPortInfo, error) {
	details, detailErr := enumerator.GetDetailedPortsList()
	if detailErr == nil {
		ports := make([]protocol.SerialPortInfo, 0, len(details))
		for _, detail := range details {
			if detail == nil || strings.TrimSpace(detail.Name) == "" {
				continue
			}
			ports = append(ports, protocol.SerialPortInfo{
				ID:           serialPortID(detail.Name),
				Name:         detail.Name,
				USB:          detail.IsUSB,
				VendorID:     strings.ToUpper(detail.VID),
				ProductID:    strings.ToUpper(detail.PID),
				Manufacturer: detail.Manufacturer,
				Product:      detail.Product,
			})
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i].Name < ports[j].Name })
		return ports, nil
	}

	names, listErr := serial.GetPortsList()
	if listErr != nil {
		return nil, fmt.Errorf("enumerate serial ports: %v; fallback: %w", detailErr, listErr)
	}
	ports := make([]protocol.SerialPortInfo, 0, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		ports = append(ports, protocol.SerialPortInfo{ID: serialPortID(name), Name: name})
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Name < ports[j].Name })
	return ports, nil
}

func (driver systemPeripheralDriver) OpenPort(portID string, config *protocol.SerialConfig) (peripheralPort, error) {
	mode, err := serialMode(config)
	if err != nil {
		return nil, err
	}
	ports, err := driver.ListPorts()
	if err != nil {
		return nil, err
	}
	var name string
	for _, port := range ports {
		if port.ID == portID {
			name = port.Name
			break
		}
	}
	if name == "" {
		return nil, errors.New("serial port is no longer available")
	}
	port, err := serial.Open(name, mode)
	if err != nil {
		return nil, err
	}
	if err = port.SetReadTimeout(serialReadTimeout); err != nil {
		_ = port.Close()
		return nil, fmt.Errorf("configure serial read timeout: %w", err)
	}
	return port, nil
}

func serialMode(config *protocol.SerialConfig) (*serial.Mode, error) {
	if config == nil {
		return nil, errors.New("missing serial configuration")
	}
	if config.BaudRate < 1 || config.BaudRate > 4_000_000 {
		return nil, errors.New("baud rate must be between 1 and 4000000")
	}
	if config.DataBits < 5 || config.DataBits > 8 {
		return nil, errors.New("data bits must be between 5 and 8")
	}
	mode := &serial.Mode{BaudRate: config.BaudRate, DataBits: config.DataBits}
	switch config.Parity {
	case "none":
		mode.Parity = serial.NoParity
	case "odd":
		mode.Parity = serial.OddParity
	case "even":
		mode.Parity = serial.EvenParity
	default:
		return nil, errors.New("unsupported serial parity")
	}
	switch config.StopBits {
	case "1":
		mode.StopBits = serial.OneStopBit
	case "2":
		mode.StopBits = serial.TwoStopBits
	default:
		return nil, errors.New("unsupported serial stop bits")
	}
	if config.FlowControl != "none" {
		return nil, errors.New("unsupported serial flow control")
	}
	return mode, nil
}

func (m *peripheralManager) handleList(msg *protocol.Message) {
	ports, err := m.driver.ListPorts()
	result := &protocol.Message{Type: protocol.MsgPeripheralListResult, RequestID: msg.RequestID, SerialPorts: ports, Success: err == nil}
	if err != nil {
		result.Error = err.Error()
	}
	_ = m.client.send(result)
}

func (m *peripheralManager) handleOpen(msg *protocol.Message) {
	result := &protocol.Message{
		Type:         protocol.MsgSerialOpenResult,
		RequestID:    msg.RequestID,
		SessionID:    msg.SessionID,
		SerialPortID: msg.SerialPortID,
	}
	if msg.RequestID == "" || msg.SessionID == "" || msg.SerialPortID == "" {
		result.Error = "missing serial open identifier"
		_ = m.client.send(result)
		return
	}
	if _, err := serialMode(msg.SerialConfig); err != nil {
		result.Error = err.Error()
		_ = m.client.send(result)
		return
	}

	m.mu.Lock()
	if _, exists := m.sessions[msg.SessionID]; exists {
		m.mu.Unlock()
		result.Error = "serial session already exists"
		_ = m.client.send(result)
		return
	}
	if _, exists := m.openings[msg.SessionID]; exists {
		m.mu.Unlock()
		result.Error = "serial session already exists"
		_ = m.client.send(result)
		return
	}
	if _, busy := m.portOwners[msg.SerialPortID]; busy {
		m.mu.Unlock()
		result.Error = "serial port is already in use"
		_ = m.client.send(result)
		return
	}
	opening := &peripheralOpening{portID: msg.SerialPortID, generation: m.generation}
	m.openings[msg.SessionID] = opening
	m.portOwners[msg.SerialPortID] = msg.SessionID
	m.mu.Unlock()

	port, err := m.openPortAfterRecentClose(msg.SerialPortID, msg.SerialConfig)
	if err != nil {
		cancelled := m.finishOpening(msg.SessionID, opening)
		if cancelled {
			return
		}
		result.Error = err.Error()
		_ = m.client.send(result)
		return
	}
	session := newPeripheralSession(msg.SessionID, msg.SerialPortID, port)
	m.mu.Lock()
	currentOpening := m.openings[msg.SessionID]
	if currentOpening != opening || opening.cancelled || m.generation != opening.generation || m.portOwners[msg.SerialPortID] != msg.SessionID {
		if currentOpening == opening {
			delete(m.openings, msg.SessionID)
		}
		if m.portOwners[msg.SerialPortID] == msg.SessionID {
			delete(m.portOwners, msg.SerialPortID)
		}
		m.mu.Unlock()
		session.close()
		return
	}
	delete(m.openings, msg.SessionID)
	m.sessions[msg.SessionID] = session
	delete(m.recentClose, msg.SerialPortID)
	m.startSessionLocked(session)
	m.mu.Unlock()
	result.Success = true
	if err = m.client.send(result); err != nil {
		m.closeCurrentSession(session)
		return
	}
	close(session.readStart)
}

func newPeripheralSession(sessionID, portID string, port peripheralPort) *peripheralSession {
	return &peripheralSession{
		id:          sessionID,
		portID:      portID,
		port:        port,
		transmit:    make(chan []byte, serialTransmitQueueSize),
		receive:     make(chan []byte, serialReceiveQueueSize),
		readStart:   make(chan struct{}),
		done:        make(chan struct{}),
		workersDone: make(chan struct{}),
	}
}

func (m *peripheralManager) startSessionLocked(session *peripheralSession) {
	session.workers.Add(3)
	go func() {
		defer session.workers.Done()
		m.readLoop(session)
	}()
	go func() {
		defer session.workers.Done()
		m.receiveLoop(session)
	}()
	go func() {
		defer session.workers.Done()
		m.transmitLoop(session)
	}()
	go func() {
		session.workers.Wait()
		close(session.workersDone)
	}()
}

func (m *peripheralManager) finishOpening(sessionID string, opening *peripheralOpening) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.openings[sessionID] == opening {
		delete(m.openings, sessionID)
	}
	if m.portOwners[opening.portID] == sessionID {
		delete(m.portOwners, opening.portID)
	}
	return opening.cancelled || m.generation != opening.generation
}

func (m *peripheralManager) openPortAfterRecentClose(portID string, config *protocol.SerialConfig) (peripheralPort, error) {
	m.mu.Lock()
	closedAt, recentlyClosed := m.recentClose[portID]
	if recentlyClosed && time.Since(closedAt) >= serialReopenWindow {
		delete(m.recentClose, portID)
		recentlyClosed = false
	}
	m.mu.Unlock()

	retryUntil := closedAt.Add(serialReopenWindow)
	for {
		port, err := m.driver.OpenPort(portID, config)
		if err == nil || !recentlyClosed || !time.Now().Before(retryUntil) {
			return port, err
		}
		time.Sleep(serialReopenInterval)
	}
}

func (m *peripheralManager) releasePortReservation(portID, sessionID string) {
	m.mu.Lock()
	if m.portOwners[portID] == sessionID {
		delete(m.portOwners, portID)
	}
	m.mu.Unlock()
}

func (m *peripheralManager) readLoop(session *peripheralSession) {
	select {
	case <-session.readStart:
	case <-session.done:
		return
	}
	buffer := make([]byte, serialReadBufferBytes)
	for {
		n, err := session.port.Read(buffer)
		if n > 0 {
			session.receiveRead.Add(uint64(n))
			data := append([]byte(nil), buffer[:n]...)
			select {
			case session.receive <- data:
			case <-session.done:
				return
			default:
				m.failCurrentSession(session, serialBackpressureCode, "serial receive queue is full; session closed", peripheralFailureReceive)
				return
			}
		}
		if err != nil {
			if m.sessionCurrent(session) {
				_ = m.client.send(&protocol.Message{Type: protocol.MsgSerialError, SessionID: session.id, Error: err.Error()})
			}
			m.closeSession(session.id)
			return
		}
	}
}

func (m *peripheralManager) receiveLoop(session *peripheralSession) {
	for {
		select {
		case data := <-session.receive:
			select {
			case <-session.done:
				return
			default:
			}
			if sendErr := m.client.sendBinary(protocol.BinSerialData, session.id, data); sendErr != nil {
				m.closeCurrentSession(session)
				return
			}
			session.receiveDelivered.Add(uint64(len(data)))
		case <-session.done:
			return
		}
	}
}

func (m *peripheralManager) transmitLoop(session *peripheralSession) {
	for {
		select {
		case data := <-session.transmit:
			select {
			case <-session.done:
				return
			default:
			}
			written, err := writePeripheral(session.port, data)
			if written > 0 {
				session.transmitWritten.Add(uint64(written))
			}
			result := &protocol.Message{Type: protocol.MsgSerialWriteResult, SessionID: session.id, BytesDone: int64(written), Success: err == nil}
			if err != nil {
				result.Error = err.Error()
			}
			_ = m.client.send(result)
			if err != nil {
				m.failCurrentSession(session, "device_error", "serial write failed; session closed", peripheralFailureTransmit)
				return
			}
		case <-session.done:
			return
		}
	}
}

func (m *peripheralManager) sessionCurrent(session *peripheralSession) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[session.id] == session
}

func (m *peripheralManager) handleWrite(sessionID string, data []byte) {
	if len(data) == 0 || len(data) > serialWriteLimitBytes {
		_ = m.client.send(&protocol.Message{Type: protocol.MsgSerialError, SessionID: sessionID, Error: "serial write payload is empty or too large"})
		return
	}
	payload := append([]byte(nil), data...)
	m.mu.Lock()
	session := m.sessions[sessionID]
	if session == nil {
		m.mu.Unlock()
		_ = m.client.send(&protocol.Message{Type: protocol.MsgSerialError, SessionID: sessionID, Error: "serial session is not open"})
		return
	}
	session.transmitAccepted.Add(uint64(len(payload)))
	select {
	case session.transmit <- payload:
		m.mu.Unlock()
		return
	default:
		m.detachSessionLocked(session)
		m.mu.Unlock()
		m.closeAndReportFailure(session, serialBackpressureCode, "serial transmit queue is full; session closed", peripheralFailureTransmit)
	}
}

func writePeripheral(port peripheralPort, data []byte) (int, error) {
	written := 0
	for written < len(data) {
		n, err := port.Write(data[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

func (m *peripheralManager) handleClose(msg *protocol.Message) {
	m.mu.Lock()
	session := m.sessions[msg.SessionID]
	if session != nil {
		m.detachSessionLocked(session)
	}
	if opening := m.openings[msg.SessionID]; opening != nil {
		opening.cancelled = true
	}
	m.mu.Unlock()
	result := &protocol.Message{Type: protocol.MsgSerialCloseResult, RequestID: msg.RequestID, SessionID: msg.SessionID, Success: true}
	if session != nil {
		session.close()
		m.mu.Lock()
		m.recentClose[session.portID] = time.Now()
		m.mu.Unlock()
		select {
		case <-session.workersDone:
		case <-time.After(serialCloseWait):
			result.Success = false
			result.Error = "serial workers did not stop after close"
		}
	}
	_ = m.client.send(result)
}

func (m *peripheralManager) closeSession(sessionID string) bool {
	m.mu.Lock()
	session := m.sessions[sessionID]
	if session != nil {
		m.detachSessionLocked(session)
	}
	m.mu.Unlock()
	if session == nil {
		return false
	}
	session.close()
	return true
}

func (m *peripheralManager) closeCurrentSession(session *peripheralSession) bool {
	m.mu.Lock()
	if m.sessions[session.id] != session {
		m.mu.Unlock()
		return false
	}
	m.detachSessionLocked(session)
	m.mu.Unlock()
	session.close()
	return true
}

func (m *peripheralManager) failCurrentSession(session *peripheralSession, errorCode, message string, flow peripheralFailureFlow) {
	m.mu.Lock()
	if m.sessions[session.id] != session {
		m.mu.Unlock()
		return
	}
	m.detachSessionLocked(session)
	m.mu.Unlock()
	m.closeAndReportFailure(session, errorCode, message, flow)
}

func (m *peripheralManager) closeAndReportFailure(session *peripheralSession, errorCode, message string, flow peripheralFailureFlow) {
	go session.close()
	m.reportFailureAfterWorkers(session, errorCode, message, flow)
}

func (m *peripheralManager) reportFailureAfterWorkers(session *peripheralSession, errorCode, message string, flow peripheralFailureFlow) {
	go func() {
		<-session.workersDone
		var accepted, delivered uint64
		switch flow {
		case peripheralFailureTransmit:
			accepted = session.transmitAccepted.Load()
			delivered = session.transmitWritten.Load()
		case peripheralFailureReceive:
			accepted = session.receiveRead.Load()
			delivered = session.receiveDelivered.Load()
		}
		dropped := uint64(0)
		if accepted > delivered {
			dropped = accepted - delivered
		}
		_ = m.client.send(&protocol.Message{
			Type: protocol.MsgSerialError, SessionID: session.id, ErrorCode: errorCode,
			Error: message, DroppedBytes: dropped,
		})
	}()
}

func (m *peripheralManager) detachSessionLocked(session *peripheralSession) {
	delete(m.sessions, session.id)
	if m.portOwners[session.portID] == session.id {
		delete(m.portOwners, session.portID)
	}
}

func (m *peripheralManager) closeAll() {
	m.mu.Lock()
	sessions := make([]*peripheralSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.sessions = make(map[string]*peripheralSession)
	for _, opening := range m.openings {
		opening.cancelled = true
	}
	m.openings = make(map[string]*peripheralOpening)
	m.portOwners = make(map[string]string)
	m.recentClose = make(map[string]time.Time)
	m.generation++
	m.mu.Unlock()
	for _, session := range sessions {
		session.close()
	}
	deadline := time.Now().Add(serialCloseWait)
	for _, session := range sessions {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		timer := time.NewTimer(remaining)
		select {
		case <-session.workersDone:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			return
		}
	}
}
