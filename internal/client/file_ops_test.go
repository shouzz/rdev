package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"rdev/internal/protocol"
)

type fileOpCaptureTransport struct {
	messages chan protocol.Message
}

func (t *fileOpCaptureTransport) WriteJSON(data []byte) error {
	var msg protocol.Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return err
	}
	t.messages <- msg
	return nil
}

func (*fileOpCaptureTransport) WriteBinary([]byte) error { return nil }
func (*fileOpCaptureTransport) WritePing([]byte) error   { return nil }
func (*fileOpCaptureTransport) Close(string) error       { return nil }

func newFileOpTestClient() (*Client, *fileOpCaptureTransport) {
	transport := &fileOpCaptureTransport{messages: make(chan protocol.Message, 1)}
	client := NewClient("wss://rdev.example.com", "device-one", "", "")
	client.transport = transport
	return client, transport
}

func waitFileOpResult(t *testing.T, transport *fileOpCaptureTransport) protocol.Message {
	t.Helper()
	select {
	case msg := <-transport.messages:
		return msg
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for file operation result")
		return protocol.Message{}
	}
}

func TestFileMkdirRenameDeleteRoundTrip(t *testing.T) {
	client, transport := newFileOpTestClient()
	root := t.TempDir()
	directory := filepath.Join(root, "nested", "source")

	client.handleMessage(&protocol.Message{
		Type: protocol.MsgFileMkdir, RequestID: "mkdir-1", Path: directory,
	})
	mkdirResult := waitFileOpResult(t, transport)
	if mkdirResult.Type != protocol.MsgFileMkdirResult || !mkdirResult.Success || mkdirResult.Path != directory {
		t.Fatalf("mkdir result = %#v", mkdirResult)
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		t.Fatalf("directory was not created: info=%v err=%v", info, err)
	}

	source := filepath.Join(directory, "payload.txt")
	if err := os.WriteFile(source, []byte("rdev"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	target := filepath.Join(root, "renamed", "payload.txt")
	client.handleMessage(&protocol.Message{
		Type: protocol.MsgFileRename, RequestID: "rename-1", Path: source, FilePath: target,
	})
	renameResult := waitFileOpResult(t, transport)
	if renameResult.Type != protocol.MsgFileRenameResult || !renameResult.Success || renameResult.Path != target {
		t.Fatalf("rename result = %#v", renameResult)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("renamed target is missing: %v", err)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists after rename: %v", err)
	}

	client.handleMessage(&protocol.Message{
		Type: protocol.MsgFileDelete, RequestID: "delete-1", Path: filepath.Join(root, "renamed"), Recursive: true,
	})
	deleteResult := waitFileOpResult(t, transport)
	if deleteResult.Type != protocol.MsgFileDeleteResult || !deleteResult.Success {
		t.Fatalf("delete result = %#v", deleteResult)
	}
	if _, err := os.Stat(filepath.Join(root, "renamed")); !os.IsNotExist(err) {
		t.Fatalf("recursive delete did not remove directory: %v", err)
	}
}

func TestFileDeleteNonRecursiveRejectsNonEmptyDirectory(t *testing.T) {
	client, transport := newFileOpTestClient()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "keep.txt"), []byte("keep"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	client.handleMessage(&protocol.Message{
		Type: protocol.MsgFileDelete, RequestID: "delete-2", Path: directory, Recursive: false,
	})
	result := waitFileOpResult(t, transport)
	if result.Type != protocol.MsgFileDeleteResult || result.Success || result.Error == "" {
		t.Fatalf("non-recursive delete result = %#v", result)
	}
	if _, err := os.Stat(directory); err != nil {
		t.Fatalf("non-recursive delete removed directory: %v", err)
	}
}

func TestFileOperationsRejectMissingPaths(t *testing.T) {
	client, transport := newFileOpTestClient()
	tests := []struct {
		message protocol.Message
		want    protocol.MessageType
	}{
		{message: protocol.Message{Type: protocol.MsgFileMkdir, RequestID: "mkdir-empty"}, want: protocol.MsgFileMkdirResult},
		{message: protocol.Message{Type: protocol.MsgFileDelete, RequestID: "delete-empty", Recursive: true}, want: protocol.MsgFileDeleteResult},
		{message: protocol.Message{Type: protocol.MsgFileRename, RequestID: "rename-empty"}, want: protocol.MsgFileRenameResult},
	}
	for _, test := range tests {
		client.handleMessage(&test.message)
		result := waitFileOpResult(t, transport)
		if result.Type != test.want || result.Success || result.Error == "" {
			t.Fatalf("missing-path result = %#v, want type %q failure", result, test.want)
		}
	}
}

func TestSafeJoinFileRejectsNamesThatEscapeTheParent(t *testing.T) {
	for _, name := range []string{".", "..", "/tmp/escape", `..\escape`, `nested/file`, `C:\escape`} {
		if joined, err := safeJoinFile(t.TempDir(), name); err == nil {
			t.Fatalf("unsafe name %q joined as %q", name, joined)
		}
	}
	parent := t.TempDir()
	joined, err := safeJoinFile(parent, "firmware.bin")
	if err != nil || joined != filepath.Join(parent, "firmware.bin") {
		t.Fatalf("safe name result = %q, err = %v", joined, err)
	}
}
