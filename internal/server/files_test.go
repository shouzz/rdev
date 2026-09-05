package server

import (
	"testing"

	"rdev/internal/protocol"
)

func TestFileBinaryCompletionKeepsRouteForVerifiedTextCompletion(t *testing.T) {
	if fileBinaryFrameClosesRoute(protocol.BinFileTransferEnd) {
		t.Fatal("binary transfer end removed the route before verified text completion")
	}
	if !fileBinaryFrameClosesRoute(protocol.BinFileTransferCancel) {
		t.Fatal("binary transfer cancellation did not close the route")
	}
}
