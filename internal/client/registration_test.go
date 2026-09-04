package client

import (
	"strings"
	"testing"
	"time"

	"rdev/internal/protocol"
)

type registrationTestTransport struct {
	closeReason string
}

func (*registrationTestTransport) WriteJSON([]byte) error   { return nil }
func (*registrationTestTransport) WriteBinary([]byte) error { return nil }
func (*registrationTestTransport) WritePing([]byte) error   { return nil }
func (t *registrationTestTransport) Close(reason string) error {
	t.closeReason = reason
	return nil
}

func TestRegistrationMessageSeparatesAccessPasswordAndDeviceSecret(t *testing.T) {
	c := NewClient("wss://rdev.example.com", "device-one", "ssh-password", "")
	c.SetDeviceSecret("managed-secret")
	message := c.registrationMessage()
	if message.Password != "ssh-password" || message.DeviceSecret != "managed-secret" {
		t.Fatalf("registration credentials were not separated: %#v", message)
	}
	if !message.CloudTransferV1 {
		t.Fatal("registration did not advertise cloud transfer v1")
	}
}

func TestRegistrationErrorCompletesAttemptImmediately(t *testing.T) {
	transport := &registrationTestTransport{}
	attempt := &registrationAttempt{transport: transport, result: make(chan error, 1)}
	c := NewClient("wss://rdev.example.com", "device-one", "", "")
	c.transport = transport
	c.registration = attempt
	c.handleMessage(&protocol.Message{Type: protocol.MsgRegisterError, Error: "managed device credential rejected"})
	select {
	case err := <-attempt.result:
		if err == nil || !strings.Contains(err.Error(), "managed device credential rejected") {
			t.Fatalf("registration error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("registration rejection did not complete the attempt")
	}
	if transport.closeReason != "registration rejected" {
		t.Fatalf("close reason = %q", transport.closeReason)
	}
}
