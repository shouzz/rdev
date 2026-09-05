package client

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"rdev/internal/protocol"
)

type sessionMessageTransport struct {
	messages chan *protocol.Message
}

func (t *sessionMessageTransport) WriteJSON(data []byte) error {
	message, err := protocol.Decode(data)
	if err != nil {
		return err
	}
	t.messages <- message
	return nil
}
func (*sessionMessageTransport) WriteBinary([]byte) error { return nil }
func (*sessionMessageTransport) WritePing([]byte) error   { return nil }
func (*sessionMessageTransport) Close(string) error       { return nil }

func TestSFTPSessionReportsSuccessfulExitOnEOF(t *testing.T) {
	transport := &sessionMessageTransport{messages: make(chan *protocol.Message, 2)}
	client := NewClient("", "test", "", "")
	client.transport = transport
	session, err := client.startSFTPSession("sftp-clean-eof")
	if err != nil {
		t.Fatalf("startSFTPSession: %v", err)
	}
	if err := session.sftpInput.Close(); err != nil {
		t.Fatalf("close SFTP input: %v", err)
	}

	var messages []*protocol.Message
	for len(messages) < 2 {
		select {
		case message := <-transport.messages:
			messages = append(messages, message)
		case <-time.After(5 * time.Second):
			t.Fatalf("received %d SFTP completion messages, want 2", len(messages))
		}
	}
	if messages[0].Type != protocol.MsgExitCode || messages[0].ExitCode != 0 {
		t.Fatalf("first completion message = %#v, want successful exit code", messages[0])
	}
	if messages[1].Type != protocol.MsgClose {
		t.Fatalf("second completion message = %#v, want close", messages[1])
	}
}

func TestStartAndRegisterSessionDoesNotDropEarlyInput(t *testing.T) {
	client := NewClient("", "test", "", "")
	sessionID := "early-input"
	payload := []byte("scp header\x00")
	reader, writer := io.Pipe()
	defer reader.Close()

	received := make(chan []byte, 1)
	go func() {
		data := make([]byte, len(payload))
		if _, err := io.ReadFull(reader, data); err == nil {
			received <- data
		}
	}()

	inputStarted := make(chan struct{})
	inputFinished := make(chan struct{})
	session := &clientSession{id: sessionID, stdinPipe: writer, done: make(chan struct{})}
	_, err := client.startAndRegisterSession(sessionID, func() (*clientSession, error) {
		go func() {
			close(inputStarted)
			client.handleBinData(sessionID, payload)
			close(inputFinished)
		}()
		<-inputStarted
		return session, nil
	})
	if err != nil {
		t.Fatalf("startAndRegisterSession: %v", err)
	}

	select {
	case <-inputFinished:
	case <-time.After(5 * time.Second):
		t.Fatal("early input remained blocked after session registration")
	}
	select {
	case data := <-received:
		if string(data) != string(payload) {
			t.Fatalf("received payload = %q, want %q", data, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("early input was dropped before session registration")
	}
	session.close()
}

func TestIsSCPExecCommand(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{command: "scp -t rdev-scp-sftp-e2e.bin", want: true},
		{command: "scp -f rdev-scp-sftp-e2e.bin", want: true},
		{command: "scp -v -t rdev-scp-sftp-e2e.bin", want: true},
		{command: "scp local.bin remote.bin", want: false},
		{command: "cmd.exe /c scp -t file.bin", want: false},
		{command: "", want: false},
	}

	for _, test := range tests {
		if got := isSCPExecCommand(test.command); got != test.want {
			t.Fatalf("isSCPExecCommand(%q) = %v, want %v", test.command, got, test.want)
		}
	}
}

func TestExecSessionKeepsStdinForRsyncServerCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell script")
	}
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	fakeRsync := filepath.Join(binDir, "rsync")
	if err := os.WriteFile(fakeRsync, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$RDEV_RSYNC_ARGS\"\ncat > \"$RDEV_RSYNC_STDIN\"\n"), 0755); err != nil {
		t.Fatalf("write fake rsync: %v", err)
	}
	argsPath := filepath.Join(tmpDir, "rsync-args.txt")
	stdinPath := filepath.Join(tmpDir, "rsync-stdin.bin")

	client := NewClient("", "test", "", "/bin/sh")
	sessionID := "stdin-rsync-server-command"
	sess, err := client.startShellExecSession(&protocol.Message{
		SessionID: sessionID,
		Command:   "rsync --server -logDtpre.iLsfxCIvu . " + strconv.Quote(filepath.Join(tmpDir, "dst")) + "/",
		Env: []string{
			"PATH=" + binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
			"RDEV_RSYNC_ARGS=" + argsPath,
			"RDEV_RSYNC_STDIN=" + stdinPath,
		},
	})
	if err != nil {
		t.Fatalf("startShellExecSession: %v", err)
	}
	if sess.stdinPipe == nil {
		t.Fatalf("rsync server command stdinPipe is nil")
	}
	client.mu.Lock()
	client.sessions[sessionID] = sess
	client.mu.Unlock()

	payload := []byte("rsync protocol payload\x00\x01\n")
	client.handleBinData(sessionID, payload)
	client.handleStdinClose(&protocol.Message{SessionID: sessionID})

	select {
	case <-sess.done:
	case <-time.After(5 * time.Second):
		sess.close()
		t.Fatalf("rsync server command did not finish after stdin close")
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read args: %v", err)
	}
	if !strings.Contains(string(args), "--server\n") {
		t.Fatalf("args = %q, want --server", string(args))
	}
	data, err := os.ReadFile(stdinPath)
	if err != nil {
		t.Fatalf("read stdin: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("stdin payload = %q, want %q", string(data), string(payload))
	}
}

func TestExecSessionKeepsStdinForRegularCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell redirection")
	}
	outputPath := t.TempDir() + "/stdin-output.txt"
	client := NewClient("", "test", "", "/bin/sh")
	sessionID := "stdin-regular-command"
	sess, err := client.startShellExecSession(&protocol.Message{
		SessionID: sessionID,
		Command:   "cat > " + strconv.Quote(outputPath),
	})
	if err != nil {
		t.Fatalf("startShellExecSession: %v", err)
	}
	if sess.stdinPipe == nil {
		t.Fatalf("regular exec command stdinPipe is nil")
	}
	client.mu.Lock()
	client.sessions[sessionID] = sess
	client.mu.Unlock()

	client.handleBinData(sessionID, []byte("hello from stdin\n"))
	client.handleStdinClose(&protocol.Message{SessionID: sessionID})

	select {
	case <-sess.done:
	case <-time.After(5 * time.Second):
		sess.close()
		t.Fatalf("session did not finish after stdin close")
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(data) != "hello from stdin\n" {
		t.Fatalf("output = %q, want stdin payload", string(data))
	}
}
