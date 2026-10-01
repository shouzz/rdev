package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

type updateTestTransport func(*http.Request) (*http.Response, error)

func (f updateTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCheckAndApplyIntegrityAndPendingRestart(t *testing.T) {
	original := http.DefaultTransport
	defer func() { http.DefaultTransport = original; updatePending = false }()
	t.Setenv("RDEV_UPDATE_PROXY", "")
	binary := []byte("fixture release bytes")
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(binary))
	tamper := true
	http.DefaultTransport = updateTestTransport(func(r *http.Request) (*http.Response, error) {
		var body string
		if r.URL.Host == "api.github.com" {
			body = fmt.Sprintf(`{"tag_name":"v2.0.0","assets":[{"name":%q,"browser_download_url":"https://github.com/icepie/rdev/releases/download/v2.0.0/client","digest":%q}]}`, releaseAssetName("client"), digest)
		} else {
			body = string(binary)
			if tamper {
				body = "corrupt release bytes"
			}
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	applies := 0
	apply := func(data []byte) error {
		applies++
		if !bytes.Equal(data, binary) {
			t.Fatal("corrupt bytes reached executable replacement")
		}
		return nil
	}
	cfg := Config{App: "client", Version: "1.0.0"}
	if updated, err := checkAndApply(context.Background(), cfg, apply); updated || err == nil || applies != 0 {
		t.Fatal("corrupt release was not rejected before apply")
	}
	tamper = false
	if updated, err := checkAndApply(context.Background(), cfg, apply); !updated || err != nil || applies != 1 {
		t.Fatalf("verified release was not applied: updated=%v err=%v applies=%d", updated, err, applies)
	}
	if updated, err := checkAndApply(context.Background(), cfg, apply); updated || err == nil || applies != 1 {
		t.Fatal("second update applied while awaiting restart")
	}
}

func TestReleaseAssetDigestRequired(t *testing.T) {
	data := []byte("release binary fixture")
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	if err := verifyAssetDigest(data, digest); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", "sha256:00", strings.TrimPrefix(digest, "sha256:"), strings.Replace(digest, "sha256:", "sha512:", 1)} {
		if verifyAssetDigest(data, invalid) == nil {
			t.Fatal("invalid or missing digest accepted")
		}
	}
	if verifyAssetDigest([]byte("tampered"), digest) == nil {
		t.Fatal("tampered release binary accepted")
	}
}

func TestNewerVersion(t *testing.T) {
	tests := []struct {
		latest  string
		current string
		want    bool
	}{
		{"0.2.43", "0.2.42", true},
		{"0.3.0", "0.2.99", true},
		{"1.0.0", "0.9.9", true},
		{"0.2.42", "0.2.42", false},
		{"0.2.41", "0.2.42", false},
	}
	for _, tt := range tests {
		if got := newerVersion(tt.latest, tt.current); got != tt.want {
			t.Fatalf("newerVersion(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	if got := normalizeVersion("v0.2.43"); got != "0.2.43" {
		t.Fatalf("normalize tag = %q", got)
	}
	if got := normalizeVersion("main"); got != "dev" {
		t.Fatalf("normalize branch = %q", got)
	}
	if got := normalizeVersion("0.2.43-dirty"); got != "0.2.43" {
		t.Fatalf("normalize dirty = %q", got)
	}
}

func TestReleaseAssetName(t *testing.T) {
	name := releaseAssetName("client")
	expected := "rdev-client-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		expected += ".exe"
	}
	if name != expected {
		t.Fatalf("releaseAssetName = %q, want %q", name, expected)
	}
}

func TestLooksLikeHTML(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}}
	if !looksLikeHTML(resp, []byte("ok")) {
		t.Fatal("content-type html was not detected")
	}
	resp = &http.Response{Header: http.Header{"Content-Type": []string{"application/octet-stream"}}}
	if !looksLikeHTML(resp, []byte("  <!doctype html><html></html>")) {
		t.Fatal("html body was not detected")
	}
	if looksLikeHTML(resp, []byte("MZ"+strings.Repeat("x", 1024))) {
		t.Fatal("binary body was detected as html")
	}
}

func TestUpdateFailureLoggerSuppressesRepeats(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	failureLog := updateFailureLogger{summaryEvery: 15 * time.Minute}
	now := time.Unix(1000, 0)

	failureLog.record(logger, errors.New("dns failed"), now)
	failureLog.record(logger, errors.New("dns failed"), now.Add(time.Minute))
	failureLog.record(logger, errors.New("dns failed"), now.Add(2*time.Minute))
	if got := strings.Count(buf.String(), "auto-update check failed"); got != 1 {
		t.Fatalf("initial repeated failures logged %d times, want 1\n%s", got, buf.String())
	}
	if strings.Contains(buf.String(), "still failing") {
		t.Fatalf("summary logged too early:\n%s", buf.String())
	}

	failureLog.record(logger, errors.New("dns failed"), now.Add(16*time.Minute))
	if !strings.Contains(buf.String(), "suppressed 3 repeated failures") {
		t.Fatalf("missing periodic summary:\n%s", buf.String())
	}
}

func TestUpdateFailureLoggerRecovered(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	failureLog := updateFailureLogger{summaryEvery: 15 * time.Minute}
	now := time.Unix(1000, 0)

	failureLog.record(logger, errors.New("dns failed"), now)
	failureLog.record(logger, errors.New("dns failed"), now.Add(time.Minute))
	failureLog.recovered(logger)
	if !strings.Contains(buf.String(), "recovered; suppressed 1 repeated failures") {
		t.Fatalf("missing recovery summary:\n%s", buf.String())
	}
}

func TestProxiedURL(t *testing.T) {
	target := "https://github.com/icepie/rdev/releases/download/v0.2.43/rdev-client-linux-amd64"
	if got := proxiedURL("", target); got != target {
		t.Fatalf("direct URL = %q", got)
	}
	if got := proxiedURL("https://gh-proxy.com/", target); got != "https://gh-proxy.com/"+target {
		t.Fatalf("proxy prefix URL = %q", got)
	}
	if got := proxiedURL("http://proxy/?url=${url}", target); got != "http://proxy/?url="+target {
		t.Fatalf("proxy template URL = %q", got)
	}
}

func TestDownloadWithProxiesRetriesTransientStatus(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("payload"))
	}))
	defer server.Close()

	data, err := downloadWithProxies(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatalf("downloadWithProxies returned error: %v", err)
	}
	if string(data) != "payload" {
		t.Fatalf("download body = %q, want payload", data)
	}
	if attempts != 2 {
		t.Fatalf("request attempts = %d, want 2", attempts)
	}
}

func TestReadDownloadBodyRejectsOversizeResponse(t *testing.T) {
	_, err := readDownloadBody(strings.NewReader(strings.Repeat("x", maxDownloadBytes+1)))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readDownloadBody error = %v, want size-limit error", err)
	}
}

func TestDownloadWithProxiesDoesNotRetryPermanentStatus(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusNotFound)
		cancel()
	}))
	defer server.Close()

	_, err := downloadWithProxies(ctx, server.URL, nil)
	if err == nil {
		t.Fatal("downloadWithProxies succeeded for 404")
	}
	if attempts != 1 {
		t.Fatalf("request attempts = %d, want 1", attempts)
	}
}
