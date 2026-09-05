package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
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

func TestManagedUploadPublishesOnlyAfterSHA256Matches(t *testing.T) {
	client, transport := newFileOpTestClient()
	payload := []byte("verified RDev transfer")
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	target := filepath.Join(t.TempDir(), "payload.bin")
	client.handleManagedUploadStart(&protocol.Message{
		TaskID: "upload-ok", Path: target, Size: int64(len(payload)), SHA256: digest,
	})
	ready := waitFileOpResult(t, transport)
	if ready.Type != protocol.MsgFileUploadReady || ready.Offset != 0 {
		t.Fatalf("upload ready = %#v", ready)
	}
	client.handleManagedUploadChunk("upload-ok", 0, payload)
	client.handleManagedUploadEnd(&protocol.Message{TaskID: "upload-ok", Path: target})
	completed := waitFileOpResult(t, transport)
	if completed.Type != protocol.MsgFileTransferEnd || !completed.Success || completed.SHA256 != digest {
		t.Fatalf("upload completion = %#v", completed)
	}
	stored, err := os.ReadFile(target)
	if err != nil || string(stored) != string(payload) {
		t.Fatalf("published file = %q, err = %v", stored, err)
	}
}

func TestManagedUploadResetsPartialFileOnSHA256Mismatch(t *testing.T) {
	client, transport := newFileOpTestClient()
	payload := []byte("corrupted transfer")
	target := filepath.Join(t.TempDir(), "payload.bin")
	client.handleManagedUploadStart(&protocol.Message{
		TaskID: "upload-mismatch", Path: target, Size: int64(len(payload)), SHA256: fmt.Sprintf("%064x", 1),
	})
	_ = waitFileOpResult(t, transport)
	client.handleManagedUploadChunk("upload-mismatch", 0, payload)
	client.handleManagedUploadEnd(&protocol.Message{TaskID: "upload-mismatch", Path: target})
	failed := waitFileOpResult(t, transport)
	if failed.Type != protocol.MsgFileTransferError || failed.Success || failed.Error != "SHA-256 mismatch" {
		t.Fatalf("upload failure = %#v", failed)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("mismatched upload was published: %v", err)
	}
	if stored, err := os.ReadFile(target + ".rdevpart"); err != nil || len(stored) != 0 {
		t.Fatalf("reset partial file = %q, err = %v", stored, err)
	}
}

func TestManagedUploadRejectsEqualLengthCorruptPartialBeforeResume(t *testing.T) {
	client, transport := newFileOpTestClient()
	target := filepath.Join(t.TempDir(), "payload.bin")
	wanted := []byte("verified payload")
	corrupt := []byte("damaged payload!")
	if len(corrupt) != len(wanted) {
		t.Fatal("test payload lengths differ")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(wanted))
	if err := os.WriteFile(target+".rdevpart", corrupt, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target+".rdevpart.meta", managedUploadMetadata(int64(len(wanted)), digest), 0600); err != nil {
		t.Fatal(err)
	}

	client.handleManagedUploadStart(&protocol.Message{
		TaskID: "upload-corrupt-resume", Path: target, Size: int64(len(wanted)), SHA256: digest,
	})
	ready := waitFileOpResult(t, transport)
	if ready.Type != protocol.MsgFileUploadReady || ready.Offset != 0 {
		t.Fatalf("upload ready = %#v, want offset 0", ready)
	}
	stored, err := os.ReadFile(target + ".rdevpart")
	if err != nil || len(stored) != 0 {
		t.Fatalf("corrupt partial was not reset: %q, err = %v", stored, err)
	}
	client.handleManagedTransferCancel("upload-corrupt-resume")
}

func TestManagedUploadRestartsAfterSHA256Mismatch(t *testing.T) {
	client, transport := newFileOpTestClient()
	target := filepath.Join(t.TempDir(), "payload.bin")
	wanted := []byte("verified payload")
	digest := fmt.Sprintf("%x", sha256.Sum256(wanted))

	client.handleManagedUploadStart(&protocol.Message{TaskID: "upload-retry", Path: target, Size: int64(len(wanted)), SHA256: digest})
	_ = waitFileOpResult(t, transport)
	client.handleManagedUploadChunk("upload-retry", 0, []byte("damaged payload!"))
	client.handleManagedUploadEnd(&protocol.Message{TaskID: "upload-retry", Path: target})
	if failed := waitFileOpResult(t, transport); failed.Type != protocol.MsgFileTransferError || failed.Error != "SHA-256 mismatch" {
		t.Fatalf("first completion = %#v", failed)
	}

	client.handleManagedUploadStart(&protocol.Message{TaskID: "upload-retry", Path: target, Size: int64(len(wanted)), SHA256: digest})
	if ready := waitFileOpResult(t, transport); ready.Type != protocol.MsgFileUploadReady || ready.Offset != 0 {
		t.Fatalf("retry ready = %#v", ready)
	}
	client.handleManagedUploadChunk("upload-retry", 0, wanted)
	client.handleManagedUploadEnd(&protocol.Message{TaskID: "upload-retry", Path: target})
	if completed := waitFileOpResult(t, transport); completed.Type != protocol.MsgFileTransferEnd || !completed.Success || completed.SHA256 != digest {
		t.Fatalf("retry completion = %#v", completed)
	}
	if stored, err := os.ReadFile(target); err != nil || !bytes.Equal(stored, wanted) {
		t.Fatalf("published retry = %q, err = %v", stored, err)
	}
}

func TestFileHandleSHA256RestoresOpenedFilePosition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.bin")
	payload := []byte("opened file")
	if err := os.WriteFile(path, payload, 0644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.Seek(3, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	digest, err := fileHandleSHA256(file)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", sha256.Sum256(payload))
	if digest != want {
		t.Fatalf("opened file digest = %q, want %q", digest, want)
	}
	remainder, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remainder, payload[3:]) {
		t.Fatalf("opened file position was not restored: %q", remainder)
	}
}
