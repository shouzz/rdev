package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"rdev/internal/protocol"
)

const (
	deviceEventHistoryLimit = 1024
	deviceEventKeepalive    = 15 * time.Second
)

type deviceInfo struct {
	ID                               string                        `json:"id"`
	RequestedID                      string                        `json:"requestedId,omitempty"`
	InstanceID                       string                        `json:"instanceId,omitempty"`
	Version                          string                        `json:"version,omitempty"`
	Platform                         string                        `json:"platform,omitempty"`
	Architecture                     string                        `json:"architecture,omitempty"`
	Transport                        string                        `json:"transport,omitempty"`
	RemoteIP                         string                        `json:"remoteIp,omitempty"`
	ConnectedAt                      string                        `json:"connectedAt"`
	LastSeenAt                       string                        `json:"lastSeenAt"`
	Sessions                         int                           `json:"sessions"`
	Forwards                         int                           `json:"forwards"`
	DeviceUploadBytes                uint64                        `json:"deviceUploadBytes"`
	DeviceDownloadBytes              uint64                        `json:"deviceDownloadBytes"`
	DeviceUploadBytesPerSecond       uint64                        `json:"deviceUploadBytesPerSecond"`
	DeviceDownloadBytesPerSecond     uint64                        `json:"deviceDownloadBytesPerSecond"`
	PeakDeviceUploadBytesPerSecond   uint64                        `json:"peakDeviceUploadBytesPerSecond"`
	PeakDeviceDownloadBytesPerSecond uint64                        `json:"peakDeviceDownloadBytesPerSecond"`
	HasPassword                      bool                          `json:"hasPassword"`
	Desktop                          *protocol.DesktopCapabilities `json:"desktop,omitempty"`
	GPUDesktop                       bool                          `json:"gpuDesktop,omitempty"`
	LogSupported                     bool                          `json:"logSupported,omitempty"`
	CloudTransferV1                  bool                          `json:"cloudTransferV1,omitempty"`
	PeripheralV1                     bool                          `json:"peripheralV1,omitempty"`
	OwnerSubject                     string                        `json:"ownerSubject,omitempty"`
	Network                          *deviceNetworkInfo            `json:"network,omitempty"`
}

type deviceEvent struct {
	ServerID     string       `json:"serverId"`
	Sequence     uint64       `json:"sequence"`
	Type         string       `json:"type"`
	OccurredAt   string       `json:"occurredAt"`
	Device       *deviceInfo  `json:"device,omitempty"`
	DeviceID     string       `json:"deviceId,omitempty"`
	Devices      []deviceInfo `json:"devices,omitempty"`
	EnrollmentID string       `json:"enrollmentId,omitempty"`
	OwnerSubject string       `json:"ownerSubject,omitempty"`
}

func newDeviceEventServerID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(value[:])
}

func (s *Server) deviceInfo(client *ClientConn) deviceInfo {
	client.mu.Lock()
	sessions := len(client.Sessions)
	forwards := len(client.Forwards)
	network := cloneDeviceNetworkInfo(client.Network)
	client.mu.Unlock()
	telemetry := client.deviceTelemetrySnapshot()
	return deviceInfo{
		ID:                               client.ID,
		RequestedID:                      client.RequestedID,
		InstanceID:                       client.InstanceID,
		Version:                          client.Version,
		Platform:                         client.Platform,
		Architecture:                     client.Architecture,
		Transport:                        client.TransportName,
		RemoteIP:                         client.RemoteIP,
		ConnectedAt:                      client.ConnectedAt.Format(time.RFC3339),
		LastSeenAt:                       telemetry.LastSeenAt.UTC().Format(time.RFC3339Nano),
		Sessions:                         sessions,
		Forwards:                         forwards,
		DeviceUploadBytes:                telemetry.DeviceUploadBytes,
		DeviceDownloadBytes:              telemetry.DeviceDownloadBytes,
		DeviceUploadBytesPerSecond:       telemetry.DeviceUploadBytesPerSecond,
		DeviceDownloadBytesPerSecond:     telemetry.DeviceDownloadBytesPerSecond,
		PeakDeviceUploadBytesPerSecond:   telemetry.PeakDeviceUploadBytesPerSecond,
		PeakDeviceDownloadBytesPerSecond: telemetry.PeakDeviceDownloadBytesPerSecond,
		HasPassword:                      client.Password != "",
		Desktop:                          publicDesktopCapabilities(client.Desktop),
		GPUDesktop:                       s.clientGPUDesktopAvailable(client),
		LogSupported:                     client.LogSupported,
		CloudTransferV1:                  client.CloudTransferV1,
		PeripheralV1:                     client.PeripheralV1,
		OwnerSubject:                     client.OwnerSubject,
		Network:                          network,
	}
}

func (s *Server) snapshotDevices() []deviceInfo {
	s.mu.RLock()
	clients := make([]*ClientConn, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}
	s.mu.RUnlock()

	devices := make([]deviceInfo, 0, len(clients))
	for _, client := range clients {
		devices = append(devices, s.deviceInfo(client))
	}
	sort.Slice(devices, func(i, j int) bool {
		if devices[i].ID != devices[j].ID {
			return devices[i].ID < devices[j].ID
		}
		return devices[i].ConnectedAt < devices[j].ConnectedAt
	})
	return devices
}

func (s *Server) publishDeviceEvent(eventType string, client *ClientConn, deviceID, enrollmentID, ownerSubject string) {
	event := deviceEvent{
		ServerID:     s.deviceEventServerID,
		Type:         eventType,
		OccurredAt:   time.Now().UTC().Format(time.RFC3339Nano),
		DeviceID:     deviceID,
		EnrollmentID: enrollmentID,
		OwnerSubject: ownerSubject,
	}
	if client != nil {
		info := s.deviceInfo(client)
		event.Device = &info
		event.DeviceID = info.ID
		event.OwnerSubject = info.OwnerSubject
	}

	s.deviceEventMu.Lock()
	s.deviceEventSequence++
	event.Sequence = s.deviceEventSequence
	s.deviceEvents = append(s.deviceEvents, event)
	if len(s.deviceEvents) > deviceEventHistoryLimit {
		s.deviceEvents = append([]deviceEvent(nil), s.deviceEvents[len(s.deviceEvents)-deviceEventHistoryLimit:]...)
	}
	for _, watcher := range s.deviceEventWatchers {
		select {
		case watcher <- struct{}{}:
		default:
		}
	}
	s.deviceEventMu.Unlock()
}

func (s *Server) subscribeDeviceEvents(after uint64) ([]deviceEvent, bool, uint64, uint64, <-chan struct{}, func()) {
	s.deviceEventMu.Lock()
	defer s.deviceEventMu.Unlock()

	current := s.deviceEventSequence
	reset := after == 0 || after > current
	if !reset && len(s.deviceEvents) > 0 && after+1 < s.deviceEvents[0].Sequence {
		reset = true
	}
	events := make([]deviceEvent, 0)
	if !reset {
		for _, event := range s.deviceEvents {
			if event.Sequence > after {
				events = append(events, event)
			}
		}
	}
	s.deviceEventWatcherID++
	watcherID := s.deviceEventWatcherID
	watcher := make(chan struct{}, 1)
	s.deviceEventWatchers[watcherID] = watcher
	cancel := func() {
		s.deviceEventMu.Lock()
		delete(s.deviceEventWatchers, watcherID)
		s.deviceEventMu.Unlock()
	}
	return events, reset, current, watcherID, watcher, cancel
}

func (s *Server) deviceEventsAfter(after uint64) ([]deviceEvent, bool, uint64) {
	s.deviceEventMu.Lock()
	defer s.deviceEventMu.Unlock()
	current := s.deviceEventSequence
	reset := after > current
	if !reset && len(s.deviceEvents) > 0 && after+1 < s.deviceEvents[0].Sequence {
		reset = true
	}
	if reset {
		return nil, true, current
	}
	events := make([]deviceEvent, 0)
	for _, event := range s.deviceEvents {
		if event.Sequence > after {
			events = append(events, event)
		}
	}
	return events, false, current
}

func writeDeviceSSE(w http.ResponseWriter, event deviceEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Sequence, event.Type, payload); err != nil {
		return err
	}
	return nil
}

func (s *Server) writeDeviceSnapshot(w http.ResponseWriter, sequence uint64) error {
	return writeDeviceSSE(w, deviceEvent{
		ServerID:   s.deviceEventServerID,
		Sequence:   sequence,
		Type:       "device.snapshot",
		OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
		Devices:    s.snapshotDevices(),
	})
}

// HandleDeviceEventsAPI streams backend-only device lifecycle events. A stale
// sequence receives a full snapshot before live events resume.
func (s *Server) HandleDeviceEventsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.controlAuthOK(r) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	afterText := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	var after uint64
	if afterText != "" {
		value, err := strconv.ParseUint(afterText, 10, 64)
		if err != nil {
			http.Error(w, "invalid Last-Event-ID", http.StatusBadRequest)
			return
		}
		after = value
	}

	events, reset, current, _, watcher, cancel := s.subscribeDeviceEvents(after)
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	if reset {
		if err := s.writeDeviceSnapshot(w, current); err != nil {
			return
		}
		after = current
	} else {
		for _, event := range events {
			if err := writeDeviceSSE(w, event); err != nil {
				return
			}
			after = event.Sequence
		}
	}
	flusher.Flush()

	keepalive := time.NewTicker(deviceEventKeepalive)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-watcher:
			pending, needsSnapshot, sequence := s.deviceEventsAfter(after)
			if needsSnapshot {
				if err := s.writeDeviceSnapshot(w, sequence); err != nil {
					return
				}
				after = sequence
			} else {
				for _, event := range pending {
					if err := writeDeviceSSE(w, event); err != nil {
						return
					}
					after = event.Sequence
				}
			}
			flusher.Flush()
		}
	}
}
