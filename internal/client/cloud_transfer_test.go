package client

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"rdev/internal/protocol"
)

func TestCloudTransferStageErrorDoesNotExposeUnderlyingDetails(t *testing.T) {
	underlying := fmt.Errorf("request https://pan.feidu.fit/device/v1/rdev-transfers/example?token=secret failed")
	err := cloudTransferFailure("plan_fetch", underlying)
	if got := err.Error(); got != "cloud transfer plan_fetch failed" {
		t.Fatalf("safe error = %q", got)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "https://") {
		t.Fatalf("safe error exposed an underlying URL or credential: %q", err.Error())
	}
	if got := cloudTransferFailureStage(err); got != "plan_fetch" {
		t.Fatalf("failure stage = %q", got)
	}
}

func TestCloudTransferCategoryErrorDoesNotExposeUnderlyingDetails(t *testing.T) {
	underlying := fmt.Errorf("request https://pan.feidu.fit/device/v1/rdev-transfers/example?token=secret failed")
	err := cloudTransferFailure("plan_fetch", cloudTransferCategory("network", underlying))
	if got := err.Error(); got != "cloud transfer plan_fetch failed" {
		t.Fatalf("safe error = %q", got)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "https://") {
		t.Fatalf("safe error exposed an underlying URL or credential: %q", err.Error())
	}
	if got := cloudTransferFailureCategory(err); got != "network" {
		t.Fatalf("failure category = %q", got)
	}
}

const cloudTransferTestID = "12345678-1234-1234-1234-1234567890ab"

type cloudTransferMessageTransport struct {
	mu       sync.Mutex
	messages [][]byte
}

func (t *cloudTransferMessageTransport) WriteJSON(data []byte) error {
	t.mu.Lock()
	t.messages = append(t.messages, append([]byte(nil), data...))
	t.mu.Unlock()
	return nil
}

func (*cloudTransferMessageTransport) WriteBinary([]byte) error { return nil }
func (*cloudTransferMessageTransport) WritePing([]byte) error   { return nil }
func (*cloudTransferMessageTransport) Close(string) error       { return nil }

func (t *cloudTransferMessageTransport) decoded(tst *testing.T) []*protocol.Message {
	tst.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]*protocol.Message, 0, len(t.messages))
	for _, raw := range t.messages {
		message, err := protocol.Decode(raw)
		if err != nil {
			tst.Fatalf("decode cloud transfer result: %v", err)
		}
		result = append(result, message)
	}
	return result
}

func cloudTransferTestToken() string {
	return "fdtx_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
}

func TestCloudTransferHTTPClientsAreReused(t *testing.T) {
	if cloudTransferAPIClient() != cloudTransferAPIClient() {
		t.Fatal("cloud transfer API client was recreated")
	}
	if cloudTransferDataClient(false) != cloudTransferDataClient(false) {
		t.Fatal("cloud transfer upload client was recreated")
	}
	if cloudTransferDownloadClient() != cloudTransferDownloadClient() {
		t.Fatal("cloud transfer download client was recreated")
	}
	if cloudTransferDataClient(false) == cloudTransferDownloadClient() {
		t.Fatal("upload and redirecting download clients were not separated")
	}
}

func TestCloudTransferSameGenerationRedispatchAcknowledgesExistingRun(t *testing.T) {
	client := NewClient("wss://rdev.example.com", "device", "", "")
	transport := &cloudTransferMessageTransport{}
	client.transport = transport
	runContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	bootstrapURL := "https://pan.feidu.fit/device/v1/rdev-transfers/" + cloudTransferTestID
	tokenHash := sha256.Sum256([]byte(cloudTransferTestToken()))
	client.cloudTransfers[cloudTransferTestID] = &cloudTransferRun{
		transferID: cloudTransferTestID, generation: 4, bootstrapURL: bootstrapURL, tokenHash: tokenHash,
		ctx: runContext, cancel: cancel,
		state: "running", requestIDs: make(map[string]struct{}),
	}
	client.handleCloudTransferStart(&protocol.Message{
		Type: protocol.MsgCloudTransferStart, RequestID: strings.Repeat("1", 32),
		TransferID: cloudTransferTestID, TransferGeneration: 4,
		BootstrapURL:  bootstrapURL,
		TransferToken: cloudTransferTestToken(),
	})
	messages := transport.decoded(t)
	if len(messages) != 1 || messages[0].Type != protocol.MsgCloudTransferResult ||
		messages[0].RequestID != strings.Repeat("1", 32) || messages[0].TransferID != cloudTransferTestID ||
		messages[0].TransferGeneration != 4 || messages[0].TransferState != "running" {
		t.Fatalf("same-generation ACK = %#v", messages)
	}
}

func TestCloudTransferSameGenerationRejectsDifferentCredentialIdentity(t *testing.T) {
	client := NewClient("wss://rdev.example.com", "device", "", "")
	transport := &cloudTransferMessageTransport{}
	client.transport = transport
	bootstrapURL := "https://pan.feidu.fit/device/v1/rdev-transfers/" + cloudTransferTestID
	firstToken := cloudTransferTestToken()
	firstTokenHash := sha256.Sum256([]byte(firstToken))
	runContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.cloudTransfers[cloudTransferTestID] = &cloudTransferRun{
		transferID: cloudTransferTestID, generation: 4, bootstrapURL: bootstrapURL, tokenHash: firstTokenHash,
		ctx: runContext, cancel: cancel, state: "running", requestIDs: make(map[string]struct{}),
	}
	differentToken := "fdtx_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32))
	client.handleCloudTransferStart(&protocol.Message{
		Type: protocol.MsgCloudTransferStart, RequestID: strings.Repeat("5", 32),
		TransferID: cloudTransferTestID, TransferGeneration: 4,
		BootstrapURL: bootstrapURL, TransferToken: differentToken,
	})
	messages := transport.decoded(t)
	if len(messages) != 1 || messages[0].TransferState != "failed" || messages[0].TransferGeneration != 4 {
		t.Fatalf("mismatched same-generation result = %#v", messages)
	}
}

func TestCloudTransferNewGenerationCancelsOldRunAndOldCleanupKeepsNewRun(t *testing.T) {
	client := NewClient("wss://rdev.example.com", "device", "", "")
	oldContext, oldCancel := context.WithCancel(context.Background())
	oldRun := &cloudTransferRun{
		transferID: cloudTransferTestID, generation: 2, ctx: oldContext, cancel: oldCancel,
		state: "running", requestIDs: make(map[string]struct{}),
	}
	client.cloudTransfers[cloudTransferTestID] = oldRun
	message := &protocol.Message{
		Type: protocol.MsgCloudTransferStart, RequestID: strings.Repeat("2", 32),
		TransferID: cloudTransferTestID, TransferGeneration: 3,
		BootstrapURL:  "https://pan.feidu.fit/device/v1/rdev-transfers/" + cloudTransferTestID,
		TransferToken: cloudTransferTestToken(),
	}
	newRun, start := client.prepareCloudTransfer(message)
	if !start || newRun == oldRun || newRun.generation != 3 {
		t.Fatalf("new generation preparation = run:%#v start:%v", newRun, start)
	}
	select {
	case <-oldContext.Done():
	default:
		t.Fatal("new generation did not cancel the old execution context")
	}
	if err := client.finishCloudTransfer(oldRun, "failed"); err != nil {
		t.Fatalf("finish old generation: %v", err)
	}
	client.mu.Lock()
	current := client.cloudTransfers[cloudTransferTestID]
	client.mu.Unlock()
	if current != newRun {
		t.Fatal("old generation cleanup removed the new generation")
	}
	newRun.cancel()
}

func TestCloudTransferStartingGenerationAcknowledgesEveryRedispatchAfterAcceptance(t *testing.T) {
	client := NewClient("wss://rdev.example.com", "device", "", "")
	transport := &cloudTransferMessageTransport{}
	client.transport = transport
	runContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	bootstrapURL := "https://pan.feidu.fit/device/v1/rdev-transfers/" + cloudTransferTestID
	tokenHash := sha256.Sum256([]byte(cloudTransferTestToken()))
	run := &cloudTransferRun{
		transferID: cloudTransferTestID, generation: 5, bootstrapURL: bootstrapURL, tokenHash: tokenHash,
		ctx: runContext, cancel: cancel,
		state: "starting", requestIDs: map[string]struct{}{strings.Repeat("3", 32): {}},
	}
	client.cloudTransfers[cloudTransferTestID] = run
	client.handleCloudTransferStart(&protocol.Message{
		Type: protocol.MsgCloudTransferStart, RequestID: strings.Repeat("4", 32),
		TransferID: cloudTransferTestID, TransferGeneration: 5,
		BootstrapURL:  bootstrapURL,
		TransferToken: cloudTransferTestToken(),
	})
	if messages := transport.decoded(t); len(messages) != 0 {
		t.Fatalf("starting generation acknowledged before acceptance: %#v", messages)
	}
	if err := client.publishCloudTransferState(run, "running"); err != nil {
		t.Fatalf("publish accepted generation: %v", err)
	}
	messages := transport.decoded(t)
	if len(messages) != 2 {
		t.Fatalf("accepted ACK count = %d, want 2", len(messages))
	}
	seen := map[string]bool{}
	for _, message := range messages {
		if message.TransferGeneration != 5 || message.TransferState != "running" {
			t.Fatalf("accepted ACK = %#v", message)
		}
		seen[message.RequestID] = true
	}
	if !seen[strings.Repeat("3", 32)] || !seen[strings.Repeat("4", 32)] {
		t.Fatalf("accepted request IDs = %#v", seen)
	}
}

func TestCloudDownloadResumesAndStripsAuthorizationOnRedirect(t *testing.T) {
	content := bytes.Repeat([]byte("rdev-cloud-download-"), 8000)
	digest := sha1.Sum(content)
	destination := filepath.Join(t.TempDir(), "artifact.bin")
	partPath := destination + ".rdev-cloud.part"
	if err := os.WriteFile(partPath, content[:8192], 0600); err != nil {
		t.Fatal(err)
	}
	artifact := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("redirected download carried Authorization: %q", got)
		}
		if got := r.Header.Get("Referer"); got != "" {
			t.Fatalf("redirected download carried Referer: %q", got)
		}
		if got := r.Header.Get("Range"); got != "bytes=8192-" {
			t.Fatalf("download Range = %q", got)
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 8192-%d/%d", len(content)-1, len(content)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(content[8192:])
	}))
	defer artifact.Close()

	var states []string
	var api *httptest.Server
	api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+cloudTransferTestToken() {
			t.Fatalf("API Authorization = %q", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/transfer":
			writeCloudTransferEnvelope(t, w, cloudTransferPlan{
				Schema: cloudTransferSchema, TransferID: cloudTransferTestID, Direction: cloudTransferDownload,
				DestinationParentPath: filepath.Dir(destination), FileName: filepath.Base(destination),
				SizeBytes: int64(len(content)), SHA1: hex.EncodeToString(digest[:]),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/transfer/content":
			http.Redirect(w, r, artifact.URL+"/artifact?signature=download-token", http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/transfer/progress":
			var progress cloudTransferProgress
			if err := json.NewDecoder(r.Body).Decode(&progress); err != nil {
				t.Fatal(err)
			}
			states = append(states, progress.State)
			writeCloudTransferEnvelope(t, w, struct{}{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	if err := executeCloudTransfer(context.Background(), api.URL+"/transfer", cloudTransferTestToken(), cloudTransferTestID); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("downloaded content differs")
	}
	if _, err = os.Stat(partPath); !errorsIsNotExist(err) {
		t.Fatalf("download part remained after publish: %v", err)
	}
	if len(states) < 2 || states[0] != "running" || states[len(states)-1] != "completed" {
		t.Fatalf("progress states = %#v", states)
	}
}

func TestCloudDownloadPublishesAlreadyCompletePartWithoutRedownloading(t *testing.T) {
	content := bytes.Repeat([]byte("complete-rdev-cloud-part"), 4096)
	digest := sha1.Sum(content)
	destination := filepath.Join(t.TempDir(), "artifact.bin")
	partPath := destination + ".rdev-cloud.part"
	if err := os.WriteFile(partPath, content, 0600); err != nil {
		t.Fatal(err)
	}
	contentRequests := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/transfer":
			writeCloudTransferEnvelope(t, w, cloudTransferPlan{
				Schema: cloudTransferSchema, TransferID: cloudTransferTestID, Direction: cloudTransferDownload,
				DestinationParentPath: filepath.Dir(destination), FileName: filepath.Base(destination),
				SizeBytes: int64(len(content)), SHA1: hex.EncodeToString(digest[:]),
			})
		case r.Method == http.MethodGet && r.URL.Path == "/transfer/content":
			contentRequests++
			http.Error(w, "complete part must not be downloaded again", http.StatusRequestedRangeNotSatisfiable)
		case r.Method == http.MethodPost && r.URL.Path == "/transfer/progress":
			writeCloudTransferEnvelope(t, w, struct{}{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	if err := executeCloudTransfer(context.Background(), api.URL+"/transfer", cloudTransferTestToken(), cloudTransferTestID); err != nil {
		t.Fatal(err)
	}
	if contentRequests != 0 {
		t.Fatalf("cloud content requests = %d, want 0", contentRequests)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("published complete part differs")
	}
	if _, err = os.Stat(partPath); !errorsIsNotExist(err) {
		t.Fatalf("download part remained after publish: %v", err)
	}
}

func TestCloudUploadIsSequentialRetriesAndNeverForwardsAuthorization(t *testing.T) {
	source := filepath.Join(t.TempDir(), "diagnostic.bin")
	content := bytes.Repeat([]byte("0123456789abcdef"), 160)
	if err := os.WriteFile(source, content, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	partSize := uint64(1024)
	partCount := 3
	var partMu sync.Mutex
	partBodies := make(map[int][]byte)
	partAttempts := make(map[int]int)
	artifact := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("part upload carried Authorization: %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "" {
			t.Fatalf("part upload added Content-Type: %q", got)
		}
		partNumber, parseErr := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/part/"))
		if parseErr != nil {
			http.Error(w, "bad part", http.StatusBadRequest)
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		partMu.Lock()
		partAttempts[partNumber]++
		attempt := partAttempts[partNumber]
		partMu.Unlock()
		if partNumber == 1 && attempt == 1 {
			http.Error(w, "retry", http.StatusInternalServerError)
			return
		}
		partMu.Lock()
		partBodies[partNumber] = append([]byte(nil), body...)
		partMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer artifact.Close()

	parts := func() []cloudUploadPart {
		items := make([]cloudUploadPart, 0, partCount)
		for number := 1; number <= partCount; number++ {
			items = append(items, cloudUploadPart{PartNumber: number, UploadURL: fmt.Sprintf("%s/part/%d?signature=part-token", artifact.URL, number)})
		}
		return items
	}
	var reported []int
	var completedHash string
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+cloudTransferTestToken() {
			t.Fatalf("API Authorization = %q", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/transfer":
			writeCloudTransferEnvelope(t, w, cloudTransferPlan{Schema: cloudTransferSchema, TransferID: cloudTransferTestID, Direction: cloudTransferUpload, SourcePath: source, SizeBytes: int64(len(content))})
		case r.Method == http.MethodPost && r.URL.Path == "/transfer/upload-session":
			writeCloudTransferEnvelope(t, w, cloudUploadSessionResponse{Session: cloudUploadSession{
				SessionID: "upload-session", OperationID: "87654321-4321-4321-4321-ba0987654321", Status: "uploading",
				FileName: filepath.Base(source), SizeBytes: uint64(len(content)), ModifiedAt: uint64(info.ModTime().UnixMilli()),
				PartSize: partSize, PartCount: uint(partCount),
			}, Parts: parts()})
		case r.Method == http.MethodPost && r.URL.Path == "/transfer/upload-session/parts/refresh":
			writeCloudTransferEnvelope(t, w, struct {
				Parts []cloudUploadPart `json:"parts"`
			}{Parts: parts()})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/transfer/upload-session/parts/"):
			number, parseErr := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/transfer/upload-session/parts/"))
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			reported = append(reported, number)
			writeCloudTransferEnvelope(t, w, struct{}{})
		case r.Method == http.MethodPost && r.URL.Path == "/transfer/upload-session/complete":
			var request map[string]string
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			completedHash = request["content_hash"]
			writeCloudTransferEnvelope(t, w, struct{}{})
		case r.Method == http.MethodPost && r.URL.Path == "/transfer/progress":
			writeCloudTransferEnvelope(t, w, struct{}{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()

	if err = executeCloudTransfer(context.Background(), api.URL+"/transfer", cloudTransferTestToken(), cloudTransferTestID); err != nil {
		t.Fatal(err)
	}
	partMu.Lock()
	defer partMu.Unlock()
	if partAttempts[1] != 2 || partAttempts[2] != 1 || partAttempts[3] != 1 {
		t.Fatalf("part attempts = %#v", partAttempts)
	}
	if fmt.Sprint(reported) != "[1 2 3]" {
		t.Fatalf("reported parts = %#v", reported)
	}
	assembled := append(append(append([]byte(nil), partBodies[1]...), partBodies[2]...), partBodies[3]...)
	if !bytes.Equal(assembled, content) {
		t.Fatal("uploaded part bytes differ")
	}
	digest := sha1.Sum(content)
	if completedHash != hex.EncodeToString(digest[:]) {
		t.Fatalf("completed hash = %q", completedHash)
	}
}

func TestCloudTransferDataClientHasNoWholeTransferTimeout(t *testing.T) {
	client := cloudTransferDataClient(false)
	if client.Timeout != 0 {
		t.Fatalf("data client timeout = %s, want no whole-transfer timeout", client.Timeout)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("data client transport = %T", client.Transport)
	}
	if transport.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("response header timeout = %s", transport.ResponseHeaderTimeout)
	}
}

func TestValidateCloudContentRange(t *testing.T) {
	if err := validateCloudContentRange("bytes 8192-9999/10000", 8192, 10000); err != nil {
		t.Fatalf("valid Content-Range rejected: %v", err)
	}
	for _, value := range []string{
		"",
		"bytes 0-9999/10000",
		"bytes 8192-10000/10000",
		"bytes 8192-9999/*",
	} {
		if err := validateCloudContentRange(value, 8192, 10000); err == nil {
			t.Fatalf("invalid Content-Range accepted: %q", value)
		}
	}
}

func writeCloudTransferEnvelope(t *testing.T, w http.ResponseWriter, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"code": 0, "message": "ok", "data": data, "traceId": "rdev-cloud-transfer-test-trace",
	}); err != nil {
		t.Fatal(err)
	}
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
