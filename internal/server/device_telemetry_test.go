package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeviceTelemetryTracksRatesAndPeaks(t *testing.T) {
	connectedAt := time.Unix(1_700_000_000, 0)
	client := &ClientConn{}
	client.initializeDeviceTelemetry(connectedAt)
	client.recordDeviceUpload(1_000, connectedAt.Add(time.Second))
	client.recordDeviceDownload(2_000)
	first := client.sampleDeviceTelemetry(connectedAt.Add(2 * time.Second))
	if first.DeviceUploadBytesPerSecond != 500 || first.DeviceDownloadBytesPerSecond != 1_000 {
		t.Fatalf("first rates = upload:%d download:%d", first.DeviceUploadBytesPerSecond, first.DeviceDownloadBytesPerSecond)
	}
	client.recordDeviceUpload(4_000, connectedAt.Add(3*time.Second))
	client.recordDeviceDownload(2_000)
	second := client.sampleDeviceTelemetry(connectedAt.Add(4 * time.Second))
	if second.DeviceUploadBytesPerSecond != 2_000 || second.DeviceDownloadBytesPerSecond != 1_000 {
		t.Fatalf("second rates = upload:%d download:%d", second.DeviceUploadBytesPerSecond, second.DeviceDownloadBytesPerSecond)
	}
	if second.PeakDeviceUploadBytesPerSecond != 2_000 || second.PeakDeviceDownloadBytesPerSecond != 1_000 {
		t.Fatalf("peak rates = upload:%d download:%d", second.PeakDeviceUploadBytesPerSecond, second.PeakDeviceDownloadBytesPerSecond)
	}
	if !second.LastSeenAt.Equal(connectedAt.Add(3 * time.Second)) {
		t.Fatalf("last seen = %s", second.LastSeenAt)
	}
}

func TestObservedWebSocketRemoteIPTrustsForwardingOnlyFromLoopback(t *testing.T) {
	if got := observedWebSocketRemoteIP("127.0.0.1:1234", "203.0.113.8, 127.0.0.1"); got != "203.0.113.8" {
		t.Fatalf("loopback proxy IP = %q", got)
	}
	if got := observedWebSocketRemoteIP("198.51.100.7:1234", "203.0.113.8"); got != "198.51.100.7" {
		t.Fatalf("direct peer IP = %q", got)
	}
	if got := observedWebSocketRemoteIP("[2001:db8::1]:1234", ""); got != "2001:db8::1" {
		t.Fatalf("IPv6 peer IP = %q", got)
	}
}

func TestDeviceNetworkResolverValidatesAndCachesResponse(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/203.0.113.9" {
			t.Fatalf("lookup path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ip":"203.0.113.9","success":true,"country":"China","country_code":"CN","region":"Beijing","city":"Beijing","connection":{"asn":64500,"org":"Example Org","isp":"Example ISP"}}`))
	}))
	defer server.Close()

	resolver := &deviceNetworkResolver{
		endpoint: server.URL + "/",
		client:   server.Client(),
		cache:    make(map[string]deviceNetworkCacheEntry),
	}
	now := time.Unix(1_700_000_000, 0)
	first := resolver.resolve(context.Background(), "203.0.113.9", now)
	second := resolver.resolve(context.Background(), "203.0.113.9", now.Add(time.Hour))
	if first.LookupStatus != "resolved" || first.ISP != "Example ISP" || first.Organization != "Example Org" || first.ASN != 64500 {
		t.Fatalf("resolved network = %#v", first)
	}
	if second != first || requests.Load() != 1 {
		t.Fatalf("cache result = %#v, requests = %d", second, requests.Load())
	}
}

func TestDeviceNetworkResolverRejectsMismatchedIP(t *testing.T) {
	reader := strings.NewReader(`{"ip":"203.0.113.10","success":true,"country_code":"CN"}`)
	if _, err := decodeDeviceNetworkLookup(reader, "203.0.113.9", time.Now()); err == nil {
		t.Fatal("mismatched network identity was accepted")
	}
}

func TestPrepareClientNetworkDoesNotResolvePrivateAddress(t *testing.T) {
	server := NewServer()
	client := &ClientConn{RemoteIP: "192.168.3.109"}
	if server.prepareClientNetwork(client) {
		t.Fatal("private address was scheduled for public lookup")
	}
	if client.Network == nil || client.Network.LookupStatus != "private" {
		t.Fatalf("private network status = %#v", client.Network)
	}
}
