package server

import (
	"bytes"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"rdev/internal/protocol"
)

func forwardWorkers() int {
	stack := make([]byte, 4<<20)
	n := runtime.Stack(stack, true)
	return bytes.Count(stack[:n], []byte("handleDirectTCPIP.func")) + bytes.Count(stack[:n], []byte("bridgeForward.func"))
}

// A device may never acknowledge TCP close (or acknowledge after map removal).
// Repeated short HTTP probes must release their queues and worker goroutines.
func TestDirectForwardClientCloseReleasesWorkers(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	client, device := maintenanceOnlineClient(t, s, "forward-lifecycle")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, client.ID, grant)
	server, err := NewSSHServer(s, "127.0.0.1:0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.server.Serve(listener) }()
	defer server.server.Close()
	connection, err := gossh.Dial("tcp", listener.Addr().String(), &gossh.ClientConfig{
		User: client.ID, Auth: []gossh.AuthMethod{gossh.Password(token)},
		HostKeyCallback: gossh.FixedHostKey(server.hostKey.PublicKey()), Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	baseline := forwardWorkers()
	for i := 0; i < 24; i++ {
		opened := make(chan net.Conn, 1)
		failed := make(chan error, 1)
		go func() {
			c, e := connection.Dial("tcp", "127.0.0.1:80")
			if e != nil {
				failed <- e
			} else {
				opened <- c
			}
		}()
		req := waitPeripheralDeviceMessage(t, device, protocol.MsgTCPConnect)
		s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgTCPOpen, ForwardID: req.ForwardID})
		var c net.Conn
		select {
		case c = <-opened:
		case e := <-failed:
			t.Fatal(e)
		case <-time.After(3 * time.Second):
			t.Fatal("forward did not open")
		}
		if i == 23 {
			connection.Close()
			waitPeripheralDeviceMessage(t, device, protocol.MsgTCPClose)
			break
		}
		if i%3 == 2 {
			payload := bytes.Repeat([]byte("queued response"), 8192)
			s.handleClientBinary(client, protocol.EncodeBinFrame(protocol.BinTCPData, req.ForwardID, payload))
			s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgTCPClose, ForwardID: req.ForwardID})
			completed := make(chan []byte, 1)
			go func() { b, _ := io.ReadAll(c); completed <- b }()
			select {
			case got := <-completed:
				if !bytes.Equal(got, payload) {
					t.Fatal("device close truncated queued response")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("device close stalled")
			}
			c.Close()
			waitPeripheralDeviceMessage(t, device, protocol.MsgTCPClose)
			continue
		}
		s.handleClientBinary(client, protocol.EncodeBinFrame(protocol.BinTCPData, req.ForwardID, []byte("HTTP response")))
		body := make([]byte, len("HTTP response"))
		read := make(chan error, 1)
		go func() { _, e := io.ReadFull(c, body); read <- e }()
		select {
		case e := <-read:
			if e != nil || string(body) != "HTTP response" {
				t.Fatal("forward payload changed", e)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("payload stalled")
		}
		c.Close()
		waitPeripheralDeviceMessage(t, device, protocol.MsgTCPClose)
		deadline := time.Now().Add(time.Second)
		for s.getForward(req.ForwardID) != nil && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if s.getForward(req.ForwardID) != nil {
			t.Fatal("forward remains registered")
		}
		// Alternate no acknowledgement with one arriving too late for lookup.
		if i%2 == 0 {
			s.handleClientMessage(client, &protocol.Message{Type: protocol.MsgTCPClose, ForwardID: req.ForwardID})
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for forwardWorkers() > baseline && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if remaining := forwardWorkers() - baseline; remaining > 0 {
		t.Fatalf("%d forward worker stack frames remain after 24 closed connections", remaining)
	}
}
