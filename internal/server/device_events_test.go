package server

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDeviceEventsHistoryAndGapRecovery(t *testing.T) {
	srv := NewServer()
	client := &ClientConn{
		ID:          "device-one",
		RequestedID: "device-one",
		ConnectedAt: time.Unix(1_700_000_000, 0),
		Sessions:    make(map[string]*ProxySession),
		Forwards:    make(map[string]*ProxyForward),
	}
	srv.publishDeviceEvent("device.online", client, "", "", "")
	events, reset, current := srv.deviceEventsAfter(0)
	if reset || current != 1 || len(events) != 1 {
		t.Fatalf("initial history = (%d events, reset=%v, current=%d), want (1, false, 1)", len(events), reset, current)
	}
	if events[0].Sequence != 1 || events[0].Type != "device.online" || events[0].Device == nil || events[0].Device.ID != "device-one" {
		t.Fatalf("initial event = %#v", events[0])
	}

	for i := 0; i < deviceEventHistoryLimit; i++ {
		srv.publishDeviceEvent("device.offline", nil, "device-one", "", "")
	}
	if _, reset, current = srv.deviceEventsAfter(0); !reset || current != deviceEventHistoryLimit+1 {
		t.Fatalf("expired history = (reset=%v, current=%d), want (true, %d)", reset, current, deviceEventHistoryLimit+1)
	}
	if _, reset, _ = srv.deviceEventsAfter(current + 1); !reset {
		t.Fatal("future sequence did not request snapshot recovery")
	}
}

func TestHandleDeviceEventsAPIStreamsSnapshotAndLiveEvent(t *testing.T) {
	const controlToken = "0123456789abcdef0123456789abcdef"
	srv := NewServer()
	srv.ControlToken = controlToken
	client := &ClientConn{
		ID:          "device-stream",
		RequestedID: "device-stream",
		Version:     "test-version",
		ConnectedAt: time.Unix(1_700_000_000, 0),
		Sessions:    make(map[string]*ProxySession),
		Forwards:    make(map[string]*ProxyForward),
	}
	srv.mu.Lock()
	srv.clients[client.ID] = client
	srv.mu.Unlock()
	srv.publishDeviceEvent("device.online", client, "", "", "")

	httpServer := httptest.NewServer(http.HandlerFunc(srv.HandleDeviceEventsAPI))
	defer httpServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL, nil)
	if err != nil {
		t.Fatalf("create stream request: %v", err)
	}
	request.Header.Set("X-RDev-Control-Token", controlToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("open event stream: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("event stream status = %d, want 200", response.StatusCode)
	}
	if got := response.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}

	reader := bufio.NewReader(response.Body)
	snapshot := readDeviceSSEForTest(t, reader)
	if snapshot.Type != "device.snapshot" || snapshot.Sequence != 1 || len(snapshot.Devices) != 1 || snapshot.Devices[0].ID != client.ID {
		t.Fatalf("snapshot = %#v", snapshot)
	}

	srv.mu.Lock()
	delete(srv.clients, client.ID)
	srv.mu.Unlock()
	srv.publishDeviceEvent("device.offline", client, client.ID, "", "")
	offline := readDeviceSSEForTest(t, reader)
	if offline.Type != "device.offline" || offline.Sequence != 2 || offline.DeviceID != client.ID {
		t.Fatalf("offline event = %#v", offline)
	}
}

func TestHandleDeviceEventsAPIRequiresControlToken(t *testing.T) {
	srv := NewServer()
	srv.ControlToken = "0123456789abcdef0123456789abcdef"
	request := httptest.NewRequest(http.MethodGet, "/api/control/device-events", nil)
	response := httptest.NewRecorder()
	srv.HandleDeviceEventsAPI(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestDisconnectManagedDevicePublishesOfflineEvent(t *testing.T) {
	srv := NewServer()
	client := &ClientConn{
		ID: "managed-device", RequestedID: "managed-device", OwnerSubject: "feidu-user:42",
		ConnectedAt: time.Unix(1_700_000_000, 0), Sessions: make(map[string]*ProxySession), Forwards: make(map[string]*ProxyForward),
	}
	srv.mu.Lock()
	srv.clients[client.ID] = client
	srv.mu.Unlock()

	srv.disconnectManagedDevice(client.ID, "device revoked")
	events, reset, current := srv.deviceEventsAfter(0)
	if reset || current != 1 || len(events) != 1 {
		t.Fatalf("disconnect events = (%d events, reset=%v, current=%d), want (1, false, 1)", len(events), reset, current)
	}
	event := events[0]
	if event.Type != "device.offline" || event.DeviceID != client.ID || event.OwnerSubject != client.OwnerSubject {
		t.Fatalf("disconnect event = %#v", event)
	}
}

func readDeviceSSEForTest(t *testing.T, reader *bufio.Reader) deviceEvent {
	t.Helper()
	var eventType string
	var sequence uint64
	var payload []byte
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read event stream: %v", err)
		}
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		switch {
		case strings.HasPrefix(line, "id: "):
			sequence, err = strconv.ParseUint(strings.TrimPrefix(line, "id: "), 10, 64)
			if err != nil {
				t.Fatalf("parse event id: %v", err)
			}
		case strings.HasPrefix(line, "event: "):
			eventType = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			payload = append(payload, strings.TrimPrefix(line, "data: ")...)
		}
	}
	var event deviceEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode event payload %q: %v", payload, err)
	}
	if event.Type != eventType || event.Sequence != sequence {
		t.Fatalf("SSE envelope = (%q, %d), payload = (%q, %d)", eventType, sequence, event.Type, event.Sequence)
	}
	return event
}
