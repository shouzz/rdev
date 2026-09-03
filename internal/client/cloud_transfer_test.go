package client

import (
	"bytes"
	"context"
	"crypto/sha1"
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
)

const cloudTransferTestID = "12345678-1234-1234-1234-1234567890ab"

func cloudTransferTestToken() string {
	return "fdtx_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
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
	if err := json.NewEncoder(w).Encode(map[string]any{"code": 0, "message": "ok", "data": data}); err != nil {
		t.Fatal(err)
	}
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
