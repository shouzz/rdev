package server

import (
	"testing"
	"time"

	"rdev/internal/protocol"
)

func TestFileBinaryCompletionKeepsRouteForVerifiedTextCompletion(t *testing.T) {
	if !fileBinaryFrameAwaitsTextCompletion(protocol.BinFileTransferEnd) {
		t.Fatal("binary transfer end did not wait for verified text completion")
	}
	if fileBinaryFrameClosesRoute(protocol.BinFileTransferEnd) {
		t.Fatal("binary transfer end removed the route before verified text completion")
	}
	if !fileBinaryFrameClosesRoute(protocol.BinFileTransferCancel) {
		t.Fatal("binary transfer cancellation did not close the route")
	}
}

func TestFileBinaryCompletionRouteExpiresWithoutTextCompletion(t *testing.T) {
	srv := NewServer()
	srv.registerFileTask("download-one", nil, "device-one")
	route := srv.getFileTask("download-one")
	srv.scheduleFileTaskCompletionCleanupAfter("download-one", route, 10*time.Millisecond)

	deadline := time.Now().Add(time.Second)
	for srv.getFileTask("download-one") != nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if srv.getFileTask("download-one") != nil {
		t.Fatal("file task route remained after the text completion grace period")
	}
}

func TestReplacingFileTaskCancelsPreviousCompletionCleanup(t *testing.T) {
	srv := NewServer()
	completionWait := 10 * time.Millisecond
	srv.registerFileTask("download-one", nil, "device-one")
	previous := srv.getFileTask("download-one")
	srv.scheduleFileTaskCompletionCleanupAfter("download-one", previous, completionWait)
	srv.registerFileTask("download-one", nil, "device-two")

	time.Sleep(4 * completionWait)
	current := srv.getFileTask("download-one")
	if current == nil || current == previous || current.deviceID != "device-two" {
		t.Fatalf("replacement file task route was removed: %#v", current)
	}
	srv.removeFileTask("download-one")
}
