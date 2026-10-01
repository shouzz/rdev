package server

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"rdev/internal/protocol"
)

// Results are bounded, in-memory observations, never a durable command queue.
// A server restart cannot replay a destructive operation.
type deviceAction struct {
	RequestID      string `json:"requestId"`
	DeviceID       string `json:"deviceId"`
	InstanceID     string `json:"instanceId"`
	Action         string `json:"action"`
	DeleteIdentity bool   `json:"deleteIdentity,omitempty"`
	State          string `json:"state"`
	ErrorCode      string `json:"errorCode,omitempty"`
	subject        string
	client         *ClientConn
	created        time.Time
}

type deviceManagement struct {
	mu      sync.Mutex
	actions map[string]*deviceAction
}

func validDisplayName(name string) bool {
	if !utf8.ValidString(name) || len(name) > 256 || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s *Server) displayName(id string) string {
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	return s.managedDevices[id].DisplayName
}

func managementPath(r *http.Request, suffix string) (string, bool) {
	path := r.URL.EscapedPath()
	if !strings.HasPrefix(path, "/api/control/devices/") || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	raw := strings.TrimSuffix(strings.TrimPrefix(path, "/api/control/devices/"), suffix)
	id, err := url.PathUnescape(raw)
	return id, err == nil && utf8.ValidString(id) && !strings.Contains(raw, "/") && validateManagedDeviceID(id) == nil
}

func (s *Server) handleDeviceName(w http.ResponseWriter, r *http.Request) {
	id, ok := managementPath(r, "/name")
	if !ok {
		http.NotFound(w, r)
		return
	}
	var input struct {
		Subject     string  `json:"subject"`
		DisplayName *string `json:"displayName"`
	}
	switch r.Method {
	case http.MethodGet:
		input.Subject = r.URL.Query().Get("subject")
	case http.MethodPatch:
		if !decodeEnrollmentJSON(w, r, &input) {
			return
		}
		if input.DisplayName == nil || !validDisplayName(*input.DisplayName) {
			http.Error(w, "invalid displayName (maximum 256 UTF-8 bytes)", http.StatusBadRequest)
			return
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.enrollmentMu.Lock()
	device, exists := s.managedDevices[id]
	if !exists || !device.RevokedAt.IsZero() || !managedDeviceSubjectAllowed(device.OwnerSubject, input.Subject) {
		s.enrollmentMu.Unlock()
		http.Error(w, "device access denied", http.StatusForbidden)
		return
	}
	if input.DisplayName != nil {
		original := device
		device.DisplayName = *input.DisplayName
		device.UpdatedAt = s.enrollmentCurrentTime().UTC().Truncate(time.Second)
		s.managedDevices[id] = device
		if err := s.persistManagedDeviceRegistryLocked(); err != nil {
			s.managedDevices[id] = original
			s.enrollmentMu.Unlock()
			http.Error(w, "device name persistence failed", http.StatusInternalServerError)
			return
		}
	}
	s.enrollmentMu.Unlock()
	if r.Method == http.MethodPatch {
		if client, connected := s.GetClient(id); connected {
			s.publishDeviceEvent("device.updated", client, id, "", device.OwnerSubject)
		}
	}
	writeEnrollmentJSON(w, map[string]string{"deviceId": id, "displayName": device.DisplayName})
}

func (s *Server) handleDeviceActions(w http.ResponseWriter, r *http.Request) {
	id, ok := managementPath(r, "/actions")
	if !ok {
		http.NotFound(w, r)
		return
	}
	var input struct {
		Subject        string `json:"subject"`
		RequestID      string `json:"requestId"`
		InstanceID     string `json:"instanceId"`
		Action         string `json:"action"`
		Confirm        bool   `json:"confirm"`
		DeleteIdentity bool   `json:"deleteIdentity"`
	}
	if r.Method == http.MethodGet {
		input.Subject = r.URL.Query().Get("subject")
		input.RequestID = r.URL.Query().Get("requestId")
	} else if r.Method == http.MethodPost {
		if !decodeEnrollmentJSON(w, r, &input) {
			return
		}
		if input.InstanceID == "" || len(input.InstanceID) > 128 ||
			(input.Action != "upgrade" && input.Action != "stop" && input.Action != "uninstall") ||
			(input.Action == "uninstall" && !input.Confirm) ||
			(input.DeleteIdentity && input.Action != "uninstall") {
			http.Error(w, "invalid action or missing uninstall confirmation", http.StatusBadRequest)
			return
		}
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validCloudTransferRequestID(input.RequestID) {
		http.Error(w, "requestId must be 32 lowercase hexadecimal characters", http.StatusBadRequest)
		return
	}
	// Lock order matches registration. Authorization and connection cannot change
	// between this check and dispatch; a later revocation cannot undo dispatched work.
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	device, exists := s.managedDevices[id]
	if !exists || !device.RevokedAt.IsZero() || !managedDeviceSubjectAllowed(device.OwnerSubject, input.Subject) {
		http.Error(w, "device access denied", http.StatusForbidden)
		return
	}
	m := &s.management
	m.mu.Lock()
	if m.actions == nil {
		m.actions = make(map[string]*deviceAction)
	}
	// Expiration bounds memory; callers must never reuse request IDs.
	for key, op := range m.actions {
		if time.Since(op.created) > 24*time.Hour {
			delete(m.actions, key)
		} else if op.State == "dispatched" && time.Since(op.created) > 15*time.Minute {
			op.State = "unknown"
		}
	}
	if op := m.actions[input.RequestID]; op != nil {
		if op.DeviceID != id || op.subject != input.Subject ||
			(r.Method == http.MethodPost && (op.Action != input.Action || op.InstanceID != input.InstanceID || op.DeleteIdentity != input.DeleteIdentity)) {
			m.mu.Unlock()
			http.Error(w, "requestId conflicts with an existing action", http.StatusConflict)
			return
		}
		if op.State == "dispatched" && time.Since(op.created) > 15*time.Minute {
			op.State = "unknown"
		}
		result := *op
		m.mu.Unlock()
		writeEnrollmentJSON(w, result)
		return
	}
	if r.Method == http.MethodGet {
		m.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if len(m.actions) >= 1024 {
		m.mu.Unlock()
		http.Error(w, "action history full", http.StatusServiceUnavailable)
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	client := s.clients[id]
	if client == nil || client.InstanceID != input.InstanceID || !client.Managed || !client.DeviceManagementV1 {
		m.mu.Unlock()
		http.Error(w, "device offline, instance changed, or capability unavailable", http.StatusConflict)
		return
	}
	for _, op := range m.actions {
		if op.DeviceID == id && op.State == "dispatched" {
			m.mu.Unlock()
			http.Error(w, "device action is already in progress", http.StatusConflict)
			return
		}
	}
	op := &deviceAction{
		RequestID: input.RequestID, DeviceID: id, InstanceID: input.InstanceID, Action: input.Action,
		DeleteIdentity: input.DeleteIdentity, State: "dispatched", subject: input.Subject, client: client, created: time.Now(),
	}
	m.actions[op.RequestID] = op
	m.mu.Unlock()
	err := client.Send(&protocol.Message{
		Type: protocol.MsgDeviceAction, ClientID: id, InstanceID: client.InstanceID,
		RequestID: op.RequestID, Action: op.Action, DeleteIdentity: op.DeleteIdentity,
	})
	m.mu.Lock()
	if err != nil && op.State == "dispatched" {
		// A failed write may have delivered bytes. Never retry automatically.
		op.State, op.ErrorCode = "unknown", "dispatch_failed"
	}
	result := *op
	m.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	writeEnrollmentJSON(w, result)
}

func (s *Server) handleDeviceActionResult(client *ClientConn, msg *protocol.Message) {
	m := &s.management
	m.mu.Lock()
	defer m.mu.Unlock()
	op := m.actions[msg.RequestID]
	if op == nil || op.client != client || msg.ClientID != op.DeviceID || msg.InstanceID != op.InstanceID || msg.Action != op.Action {
		return
	}
	if op.State != "dispatched" && op.State != "unknown" && op.State != "applied_restart_pending" &&
		!((op.State == "stopping" || op.State == "uninstalled_stopping") && msg.ActionState == "failed") {
		return
	}
	switch msg.ActionState {
	case "failed":
		op.State, op.ErrorCode = "failed", "client_action_failed"
	case "up_to_date", "applied_restart_pending":
		if op.Action == "upgrade" {
			op.State = msg.ActionState
		}
	case "stopping":
		if op.Action == "stop" {
			op.State = msg.ActionState
		}
	case "uninstalled_stopping":
		if op.Action == "uninstall" {
			op.State = msg.ActionState
		}
	}
}
