package client

import (
	"context"
	"sync"
	"time"

	"rdev/internal/protocol"
)

// DeviceActionHandler is installed by the executable, which knows its updater
// and installation context. After runs only after the result write completes.
type DeviceActionOutcome struct {
	State string
	After func() error
}

type DeviceActionHandler func(context.Context, string, bool) (DeviceActionOutcome, error)

type clientManagement struct {
	mu      sync.Mutex
	handler DeviceActionHandler
	busy    bool
	seen    map[string]bool
}

// SetDeviceActionHandler must be called before Run.
func (c *Client) SetDeviceActionHandler(handler DeviceActionHandler) {
	c.management.handler = handler
}

func (c *Client) handleDeviceAction(msg *protocol.Message) {
	c.mu.Lock()
	valid := c.registered && c.deviceSecret != "" && msg.ClientID == c.clientID && msg.InstanceID == c.instanceID
	transport := c.transport
	c.mu.Unlock()
	if !valid || !validCloudTransferRequestID(msg.RequestID) {
		return
	}
	// Capture the connection: never report an old operation on a new connection.
	if transport == nil {
		return
	}
	reply := func(state string) {
		data, _ := protocol.Encode(&protocol.Message{
			Type: protocol.MsgDeviceActionResult, ClientID: msg.ClientID, InstanceID: msg.InstanceID,
			RequestID: msg.RequestID, Action: msg.Action, ActionState: state,
		})
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		_ = transport.WriteJSON(data)
	}
	m := &c.management
	m.mu.Lock()
	if m.seen == nil {
		m.seen = make(map[string]bool)
	}
	if m.seen[msg.RequestID] {
		m.mu.Unlock()
		return // never execute the same request twice
	}
	if m.busy || len(m.seen) >= 1024 || m.handler == nil ||
		(msg.Action != "upgrade" && msg.Action != "stop" && msg.Action != "uninstall") ||
		(msg.DeleteIdentity && msg.Action != "uninstall") {
		m.mu.Unlock()
		reply("failed")
		return
	}
	m.seen[msg.RequestID] = true
	m.busy = true
	m.mu.Unlock()
	go func() {
		defer func() {
			m.mu.Lock()
			m.busy = false
			m.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		outcome, err := m.handler(ctx, msg.Action, msg.DeleteIdentity)
		if err != nil {
			reply("failed") // never serialize updater URLs, local paths or credentials
			return
		}
		reply(outcome.State)
		if outcome.After != nil {
			if err := outcome.After(); err != nil {
				reply("failed")
			}
		}
	}()
}
