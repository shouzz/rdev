package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"testing"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type sshAuthTestContext struct {
	context.Context
	sync.Mutex
	user     string
	valuesMu sync.Mutex
	values   map[interface{}]interface{}
}

func newSSHAuthTestContext(user string) *sshAuthTestContext {
	return &sshAuthTestContext{Context: context.Background(), user: user, values: make(map[interface{}]interface{})}
}

func (c *sshAuthTestContext) User() string                  { return c.user }
func (c *sshAuthTestContext) SessionID() string             { return "test-session" }
func (c *sshAuthTestContext) ClientVersion() string         { return "test-client" }
func (c *sshAuthTestContext) ServerVersion() string         { return "test-server" }
func (c *sshAuthTestContext) RemoteAddr() net.Addr          { return &net.TCPAddr{} }
func (c *sshAuthTestContext) LocalAddr() net.Addr           { return &net.TCPAddr{} }
func (c *sshAuthTestContext) Permissions() *ssh.Permissions { return &ssh.Permissions{} }

func (c *sshAuthTestContext) Value(key interface{}) interface{} {
	c.valuesMu.Lock()
	value, ok := c.values[key]
	c.valuesMu.Unlock()
	if ok {
		return value
	}
	return c.Context.Value(key)
}

func (c *sshAuthTestContext) SetValue(key, value interface{}) {
	c.valuesMu.Lock()
	c.values[key] = value
	c.valuesMu.Unlock()
}

func TestSSHAuthorizationBindingRejectsReconnectedInstance(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	first := &ClientConn{ID: "device", InstanceID: "instance-one", Password: "device-secret"}
	s.clients[first.ID] = first
	sshServer := &SSHServer{srv: s}
	ctx := newSSHAuthTestContext(first.ID)

	if !sshServer.handlePassword(ctx, first.Password) {
		t.Fatal("initial password authentication failed")
	}
	if client, ok := s.authorizedSSHClient(ctx); !ok || client != first {
		t.Fatal("fresh SSH authorization binding was rejected")
	}

	second := &ClientConn{ID: first.ID, InstanceID: "instance-two", Password: first.Password}
	s.clients[first.ID] = second
	if _, ok := s.authorizedSSHClient(ctx); ok {
		t.Fatal("old SSH context remained authorized after device instance changed")
	}
}

func TestSSHAccessTicketBindsDeviceAuthorization(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "instance-one", Password: "device-secret"}
	s.clients[client.ID] = client
	ticket := issueAccessTicket(t, s, client.ID, 60)
	sshServer := &SSHServer{srv: s}
	ctx := newSSHAuthTestContext(client.ID)

	if !sshServer.handlePassword(ctx, ticket) {
		t.Fatal("access-ticket SSH authentication failed")
	}
	if authorized, ok := s.authorizedSSHClient(ctx); !ok || authorized != client {
		t.Fatal("access-ticket SSH authentication did not bind the device identity")
	}
}

func TestSSHForwardingRejectsStaleAuthorizationBinding(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	first := &ClientConn{ID: "device", InstanceID: "instance-one", Password: "device-secret"}
	s.clients[first.ID] = first
	sshServer, err := NewSSHServer(s, "127.0.0.1:0", "", "")
	if err != nil {
		t.Fatal(err)
	}
	ctx := newSSHAuthTestContext(first.ID)
	if !sshServer.handlePassword(ctx, first.Password) {
		t.Fatal("initial password authentication failed")
	}
	if !sshServer.server.LocalPortForwardingCallback(ctx, "127.0.0.1", 80) {
		t.Fatal("fresh local-forward authorization was rejected")
	}
	if !sshServer.server.ReversePortForwardingCallback(ctx, "127.0.0.1", 0) {
		t.Fatal("fresh reverse-forward authorization was rejected")
	}

	s.clients[first.ID] = &ClientConn{ID: first.ID, InstanceID: "instance-two", Password: first.Password}
	if sshServer.server.LocalPortForwardingCallback(ctx, "127.0.0.1", 80) {
		t.Fatal("local-forward callback accepted a stale SSH context")
	}
	if sshServer.server.ReversePortForwardingCallback(ctx, "127.0.0.1", 0) {
		t.Fatal("reverse-forward callback accepted a stale SSH context")
	}
	if ok, _ := sshServer.fwdHandler.HandleSSHRequest(ctx, sshServer.server, &gossh.Request{Type: "cancel-tcpip-forward"}); ok {
		t.Fatal("reverse-forward request accepted a stale SSH context")
	}
}

func TestSSHSecureModeRejectsGlobalAuthorizedKey(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := gossh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer()
	s.ControlToken = "control-secret"
	client := &ClientConn{ID: "device", InstanceID: "instance-one", Password: "device-secret"}
	s.clients[client.ID] = client
	sshServer := &SSHServer{srv: s, authKeys: []gossh.PublicKey{key}}
	ctx := newSSHAuthTestContext(client.ID)

	if sshServer.handlePublicKey(ctx, key) {
		t.Fatal("global authorized key bypassed secure device credential authentication")
	}
	if _, ok := s.authorizedSSHClient(ctx); ok {
		t.Fatal("rejected public key created an SSH authorization binding")
	}
}

func TestSSHSecureModeRejectsOfflineDeviceAuthentication(t *testing.T) {
	s := NewServer()
	s.ControlToken = "control-secret"
	sshServer := &SSHServer{srv: s}
	ctx := newSSHAuthTestContext("offline-device")

	if sshServer.handlePassword(ctx, "device-secret") {
		t.Fatal("password authentication accepted an offline device in secure mode")
	}
	if sshServer.handlePublicKey(ctx, nil) {
		t.Fatal("public-key authentication accepted an offline device in secure mode")
	}
	challenged := false
	if sshServer.handleKeyboardInteractive(ctx, func(_, _ string, _ []string, _ []bool) ([]string, error) {
		challenged = true
		return []string{"device-secret"}, nil
	}) {
		t.Fatal("keyboard-interactive authentication accepted an offline device in secure mode")
	}
	if challenged {
		t.Fatal("offline secure-mode authentication prompted for a credential")
	}
}

func TestSSHPublicKeyOpenModeBindsDevice(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := gossh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer()
	client := &ClientConn{ID: "device", InstanceID: "instance-one", Password: "device-secret"}
	s.clients[client.ID] = client
	sshServer := &SSHServer{srv: s, authKeys: []gossh.PublicKey{key}}
	ctx := newSSHAuthTestContext(client.ID)

	if !sshServer.handlePublicKey(ctx, key) {
		t.Fatal("global authorized key was rejected in open mode")
	}
	if authorized, ok := s.authorizedSSHClient(ctx); !ok || authorized != client {
		t.Fatal("open-mode public-key authentication did not bind the device identity")
	}
}
