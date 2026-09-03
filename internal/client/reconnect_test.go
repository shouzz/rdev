package client

import (
	"bufio"
	"fmt"
	"net"
	"testing"
	"time"

	"rdev/internal/protocol"
	tframe "rdev/internal/transport"
)

func TestReconnectBackoffJitterAndCap(t *testing.T) {
	backoff := newReconnectBackoff(time.Second, 4*time.Second)

	for i, wantBase := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
		got := backoff.Next()
		min := wantBase - wantBase/5
		max := wantBase + wantBase/5
		if got < min || got > max {
			t.Fatalf("attempt %d delay = %s, want between %s and %s", i, got, min, max)
		}
	}
}

func TestReconnectBackoffReset(t *testing.T) {
	backoff := newReconnectBackoff(time.Second, 30*time.Second)
	_ = backoff.Next()
	_ = backoff.Next()

	backoff.Reset()
	got := backoff.Next()
	if got < 800*time.Millisecond || got > 1200*time.Millisecond {
		t.Fatalf("delay after reset = %s, want around 1s", got)
	}
}

func startRegistrationServer(t *testing.T, respond bool) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := tframe.ReadFrame(bufio.NewReader(conn)); err != nil {
			return
		}
		if respond {
			payload, _ := protocol.Encode(&protocol.Message{Type: protocol.MsgRegister, ClientID: "registered", SSHPort: "18112"})
			_ = tframe.WriteFrame(conn, tframe.KindJSON, payload)
		}
		<-time.After(500 * time.Millisecond)
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}

func TestConnectDoesNotReportSilentEndpointAndFallsThrough(t *testing.T) {
	silent, stopSilent := startRegistrationServer(t, false)
	defer stopSilent()
	working, stopWorking := startRegistrationServer(t, true)
	defer stopWorking()

	c := NewClient(fmt.Sprintf("tcp://%s,tcp://%s", silent, working), "requested", "", "")
	c.registerWait = 100 * time.Millisecond
	connected := make(chan struct{}, 1)
	c.OnConnect = func(*Client) { connected <- struct{}{} }
	started := time.Now()
	if err := c.connect(); err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("silent endpoint fallback took %s", elapsed)
	}
	select {
	case <-connected:
	case <-time.After(time.Second):
		t.Fatal("OnConnect was not called after registration")
	}
	if got := c.ClientID(); got != "registered" {
		t.Fatalf("client ID = %q, want registered", got)
	}
	c.mu.Lock()
	transport := c.transport
	c.mu.Unlock()
	if transport != nil {
		_ = transport.Close("test complete")
	}
}

func TestConnectDoesNotReportSilentKCP(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	silentKCP := udp.LocalAddr().String()
	_ = udp.Close()
	working, stopWorking := startRegistrationServer(t, true)
	defer stopWorking()

	c := NewClient(fmt.Sprintf("kcp://%s,tcp://%s", silentKCP, working), "requested", "", "")
	c.registerWait = 100 * time.Millisecond
	if err := c.connect(); err != nil {
		t.Fatalf("connect failed after silent KCP: %v", err)
	}
	if got := c.ClientID(); got != "registered" {
		t.Fatalf("client ID = %q, want registered", got)
	}
	c.mu.Lock()
	transport := c.transport
	c.mu.Unlock()
	if transport != nil {
		_ = transport.Close("test complete")
	}
}
