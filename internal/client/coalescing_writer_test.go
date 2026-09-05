package client

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"rdev/internal/protocol"
)

type orderedBinaryTransport struct {
	mu     sync.Mutex
	frames [][]byte
}

func (*orderedBinaryTransport) WriteJSON([]byte) error { return nil }
func (*orderedBinaryTransport) WritePing([]byte) error { return nil }
func (*orderedBinaryTransport) Close(string) error     { return nil }

func (t *orderedBinaryTransport) WriteBinary(frame []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.frames = append(t.frames, append([]byte(nil), frame...))
	return nil
}

func (t *orderedBinaryTransport) payload(tester *testing.T, sessionID string) []byte {
	tester.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	var payload []byte
	for _, frame := range t.frames {
		typ, id, data, err := protocol.DecodeBinFrame(frame)
		if err != nil {
			tester.Fatalf("decode frame: %v", err)
		}
		if typ != protocol.BinData || id != sessionID {
			tester.Fatalf("frame identity = (%d, %q), want (%d, %q)", typ, id, protocol.BinData, sessionID)
		}
		payload = append(payload, data...)
	}
	return payload
}

func TestCoalescingWriterPreservesSmallPrefixBeforeLargePayload(t *testing.T) {
	transport := &orderedBinaryTransport{}
	client := &Client{transport: transport}
	writer := newCoalescingWriterWithInterval(client, "sftp-session", protocol.BinData, time.Microsecond)

	prefix := []byte{0, 0, 32, 0}
	large := bytes.Repeat([]byte{0xa5}, 32*1024)
	want := make([]byte, 0, len(prefix)+len(large))
	want = append(want, prefix...)
	want = append(want, large...)

	for attempt := 0; attempt < 1000; attempt++ {
		if _, err := writer.Write(prefix); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(large); err != nil {
			t.Fatal(err)
		}
	}
	writer.flush()

	got := transport.payload(t, "sftp-session")
	if !bytes.Equal(got, bytes.Repeat(want, 1000)) {
		t.Fatal("coalesced binary frames changed stream byte order")
	}
}
