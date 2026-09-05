package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	deviceTelemetryInterval   = 5 * time.Second
	deviceNetworkLookupSource = "ipwho.is"
	deviceNetworkLookupURL    = "https://ipwho.is/"
)

type deviceTelemetry struct {
	lastSeenAt                       time.Time
	lastSampleAt                     time.Time
	deviceUploadBytes                uint64
	deviceDownloadBytes              uint64
	lastDeviceUploadBytes            uint64
	lastDeviceDownloadBytes          uint64
	deviceUploadBytesPerSecond       uint64
	deviceDownloadBytesPerSecond     uint64
	peakDeviceUploadBytesPerSecond   uint64
	peakDeviceDownloadBytesPerSecond uint64
}

type deviceTelemetrySnapshot struct {
	LastSeenAt                       time.Time
	DeviceUploadBytes                uint64
	DeviceDownloadBytes              uint64
	DeviceUploadBytesPerSecond       uint64
	DeviceDownloadBytesPerSecond     uint64
	PeakDeviceUploadBytesPerSecond   uint64
	PeakDeviceDownloadBytesPerSecond uint64
}

type deviceNetworkInfo struct {
	LookupStatus string `json:"lookupStatus"`
	LookupSource string `json:"lookupSource,omitempty"`
	Country      string `json:"country,omitempty"`
	CountryCode  string `json:"countryCode,omitempty"`
	Region       string `json:"region,omitempty"`
	City         string `json:"city,omitempty"`
	ISP          string `json:"isp,omitempty"`
	Organization string `json:"organization,omitempty"`
	ASN          uint64 `json:"asn,omitempty"`
	ResolvedAt   string `json:"resolvedAt,omitempty"`
}

type deviceNetworkCacheEntry struct {
	info      deviceNetworkInfo
	expiresAt time.Time
}

type deviceNetworkResolver struct {
	endpoint string
	client   *http.Client
	mu       sync.Mutex
	cache    map[string]deviceNetworkCacheEntry
}

func newDeviceNetworkResolver() *deviceNetworkResolver {
	return &deviceNetworkResolver{
		endpoint: deviceNetworkLookupURL,
		client:   &http.Client{Timeout: 5 * time.Second},
		cache:    make(map[string]deviceNetworkCacheEntry),
	}
}

func (c *ClientConn) initializeDeviceTelemetry(now time.Time) {
	c.telemetryMu.Lock()
	c.telemetry.lastSeenAt = now
	c.telemetry.lastSampleAt = now
	c.telemetryMu.Unlock()
}

func (c *ClientConn) markDeviceSeen(now time.Time) {
	c.telemetryMu.Lock()
	if now.After(c.telemetry.lastSeenAt) {
		c.telemetry.lastSeenAt = now
	}
	c.telemetryMu.Unlock()
}

func (c *ClientConn) recordDeviceUpload(bytes uint64, now time.Time) {
	c.telemetryMu.Lock()
	c.telemetry.deviceUploadBytes += bytes
	if now.After(c.telemetry.lastSeenAt) {
		c.telemetry.lastSeenAt = now
	}
	c.telemetryMu.Unlock()
}

func (c *ClientConn) recordDeviceDownload(bytes uint64) {
	c.telemetryMu.Lock()
	c.telemetry.deviceDownloadBytes += bytes
	c.telemetryMu.Unlock()
}

func (c *ClientConn) sampleDeviceTelemetry(now time.Time) deviceTelemetrySnapshot {
	c.telemetryMu.Lock()
	defer c.telemetryMu.Unlock()
	elapsed := now.Sub(c.telemetry.lastSampleAt)
	if elapsed > 0 {
		c.telemetry.deviceUploadBytesPerSecond = bytesPerSecond(
			c.telemetry.deviceUploadBytes-c.telemetry.lastDeviceUploadBytes,
			elapsed,
		)
		c.telemetry.deviceDownloadBytesPerSecond = bytesPerSecond(
			c.telemetry.deviceDownloadBytes-c.telemetry.lastDeviceDownloadBytes,
			elapsed,
		)
		if c.telemetry.deviceUploadBytesPerSecond > c.telemetry.peakDeviceUploadBytesPerSecond {
			c.telemetry.peakDeviceUploadBytesPerSecond = c.telemetry.deviceUploadBytesPerSecond
		}
		if c.telemetry.deviceDownloadBytesPerSecond > c.telemetry.peakDeviceDownloadBytesPerSecond {
			c.telemetry.peakDeviceDownloadBytesPerSecond = c.telemetry.deviceDownloadBytesPerSecond
		}
		c.telemetry.lastDeviceUploadBytes = c.telemetry.deviceUploadBytes
		c.telemetry.lastDeviceDownloadBytes = c.telemetry.deviceDownloadBytes
		c.telemetry.lastSampleAt = now
	}
	return c.deviceTelemetrySnapshotLocked()
}

func (c *ClientConn) deviceTelemetrySnapshot() deviceTelemetrySnapshot {
	c.telemetryMu.Lock()
	defer c.telemetryMu.Unlock()
	return c.deviceTelemetrySnapshotLocked()
}

func (c *ClientConn) deviceTelemetrySnapshotLocked() deviceTelemetrySnapshot {
	return deviceTelemetrySnapshot{
		LastSeenAt:                       c.telemetry.lastSeenAt,
		DeviceUploadBytes:                c.telemetry.deviceUploadBytes,
		DeviceDownloadBytes:              c.telemetry.deviceDownloadBytes,
		DeviceUploadBytesPerSecond:       c.telemetry.deviceUploadBytesPerSecond,
		DeviceDownloadBytesPerSecond:     c.telemetry.deviceDownloadBytesPerSecond,
		PeakDeviceUploadBytesPerSecond:   c.telemetry.peakDeviceUploadBytesPerSecond,
		PeakDeviceDownloadBytesPerSecond: c.telemetry.peakDeviceDownloadBytesPerSecond,
	}
}

func bytesPerSecond(bytes uint64, elapsed time.Duration) uint64 {
	if bytes == 0 || elapsed <= 0 {
		return 0
	}
	return uint64(float64(bytes) / elapsed.Seconds())
}

func cloneDeviceNetworkInfo(info *deviceNetworkInfo) *deviceNetworkInfo {
	if info == nil {
		return nil
	}
	clone := *info
	return &clone
}

func (s *Server) prepareClientNetwork(client *ClientConn) bool {
	ip := net.ParseIP(client.RemoteIP)
	if ip == nil {
		return false
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		client.Network = &deviceNetworkInfo{LookupStatus: "private"}
		return false
	}
	client.Network = &deviceNetworkInfo{LookupStatus: "pending", LookupSource: deviceNetworkLookupSource}
	return true
}

func (s *Server) resolveClientNetwork(client *ClientConn) {
	if !s.prepareClientNetwork(client) {
		return
	}
	s.resolvePreparedClientNetwork(client)
}

func (s *Server) resolvePreparedClientNetwork(client *ClientConn) {
	if s.deviceNetworkResolver == nil {
		return
	}
	client.mu.Lock()
	ready := client.Network != nil && client.Network.LookupStatus == "pending"
	client.mu.Unlock()
	if !ready {
		return
	}
	go func() {
		info := s.deviceNetworkResolver.resolve(context.Background(), client.RemoteIP, time.Now())
		if current := s.clientByID(client.ID); current != client {
			return
		}
		client.mu.Lock()
		client.Network = &info
		client.mu.Unlock()
		s.publishDeviceEvent("device.updated", client, "", "", "")
	}()
}

func (r *deviceNetworkResolver) resolve(ctx context.Context, ip string, now time.Time) deviceNetworkInfo {
	r.mu.Lock()
	entry, ok := r.cache[ip]
	r.mu.Unlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.info
	}

	info := deviceNetworkInfo{LookupStatus: "failed", LookupSource: deviceNetworkLookupSource}
	expiresAt := now.Add(15 * time.Minute)
	requestURL := r.endpoint + url.PathEscape(ip)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err == nil {
		request.Header.Set("Accept", "application/json")
		request.Header.Set("User-Agent", "rdev-server")
		var response *http.Response
		response, err = r.client.Do(request)
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				err = errors.New("network lookup returned non-200 status")
			} else {
				info, err = decodeDeviceNetworkLookup(io.LimitReader(response.Body, 64*1024), ip, now)
				if err == nil {
					expiresAt = now.Add(24 * time.Hour)
				}
			}
		}
	}
	if err != nil {
		info = deviceNetworkInfo{LookupStatus: "failed", LookupSource: deviceNetworkLookupSource}
	}
	r.mu.Lock()
	r.cache[ip] = deviceNetworkCacheEntry{info: info, expiresAt: expiresAt}
	r.mu.Unlock()
	return info
}

func decodeDeviceNetworkLookup(reader io.Reader, expectedIP string, now time.Time) (deviceNetworkInfo, error) {
	var response struct {
		IP          string `json:"ip"`
		Success     bool   `json:"success"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Region      string `json:"region"`
		City        string `json:"city"`
		Connection  struct {
			ASN uint64 `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if err := json.NewDecoder(reader).Decode(&response); err != nil {
		return deviceNetworkInfo{}, err
	}
	parsed := net.ParseIP(response.IP)
	if !response.Success || parsed == nil || parsed.String() != expectedIP {
		return deviceNetworkInfo{}, errors.New("network lookup identity mismatch")
	}
	if response.CountryCode != "" && len(response.CountryCode) != 2 {
		return deviceNetworkInfo{}, errors.New("network lookup country code is invalid")
	}
	return deviceNetworkInfo{
		LookupStatus: "resolved", LookupSource: deviceNetworkLookupSource,
		Country: response.Country, CountryCode: strings.ToUpper(response.CountryCode),
		Region: response.Region, City: response.City, ISP: response.Connection.ISP,
		Organization: response.Connection.Org, ASN: response.Connection.ASN,
		ResolvedAt: now.UTC().Format(time.RFC3339),
	}, nil
}

func remoteIPFromAddress(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func observedWebSocketRemoteIP(remoteAddress, forwardedFor string) string {
	directIP := remoteIPFromAddress(remoteAddress)
	parsedDirect := net.ParseIP(directIP)
	if parsedDirect == nil || !parsedDirect.IsLoopback() {
		return directIP
	}
	for _, value := range strings.Split(forwardedFor, ",") {
		if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
			return ip.String()
		}
	}
	return directIP
}

func validDevicePlatform(value string) bool {
	switch value {
	case "android", "darwin", "dragonfly", "freebsd", "illumos", "ios", "js", "linux", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows":
		return true
	default:
		return false
	}
}

func validDeviceArchitecture(value string) bool {
	switch value {
	case "386", "amd64", "arm", "arm64", "loong64", "mips", "mips64", "mips64le", "mipsle", "ppc64", "ppc64le", "riscv64", "s390x", "wasm":
		return true
	default:
		return false
	}
}

func validateRegistrationRuntime(msgPlatform, msgArchitecture string) (string, string) {
	if !validDevicePlatform(msgPlatform) {
		msgPlatform = ""
	}
	if !validDeviceArchitecture(msgArchitecture) {
		msgArchitecture = ""
	}
	return msgPlatform, msgArchitecture
}
