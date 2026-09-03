package server

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"rdev/internal/protocol"
)

const (
	cloudTransferTokenPrefix = "fdtx_"
	cloudTransferTokenBytes  = 32
	cloudTransferBodyLimit   = 16 * 1024
)

type cloudTransferDispatchRequest struct {
	DeviceID     string `json:"deviceId"`
	Subject      string `json:"subject"`
	TransferID   string `json:"transferId"`
	BootstrapURL string `json:"bootstrapUrl"`
	Token        string `json:"transferToken"`
}

type cloudTransferDispatchResponse struct {
	Accepted   bool   `json:"accepted"`
	DeviceID   string `json:"deviceId"`
	TransferID string `json:"transferId"`
}

// HandleCloudTransferDispatchAPI delivers one short-lived Feidu transfer task
// to an already connected device. RDev never stores the transfer credential.
func (s *Server) HandleCloudTransferDispatchAPI(w http.ResponseWriter, r *http.Request) {
	if !s.secureControlEnabled() {
		http.Error(w, "cloud transfer control is unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.controlAuthOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, cloudTransferBodyLimit)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input cloudTransferDispatchRequest
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if input.DeviceID == "" || strings.TrimSpace(input.DeviceID) != input.DeviceID ||
		input.Subject == "" || strings.TrimSpace(input.Subject) != input.Subject || len(input.Subject) > 128 ||
		!validCanonicalTransferID(input.TransferID) || !validCloudTransferToken(input.Token) ||
		!validCloudTransferBootstrapURL(input.BootstrapURL) {
		http.Error(w, "invalid cloud transfer dispatch", http.StatusBadRequest)
		return
	}
	client, ok := s.GetClient(input.DeviceID)
	if !ok {
		http.Error(w, "device is not connected", http.StatusNotFound)
		return
	}
	if !s.managedDeviceOwnerMatches(input.DeviceID, input.Subject) {
		http.Error(w, "device is not owned by subject", http.StatusForbidden)
		return
	}
	if err := client.Send(&protocol.Message{
		Type: protocol.MsgCloudTransferStart, TransferID: input.TransferID,
		BootstrapURL: input.BootstrapURL, TransferToken: input.Token,
	}); err != nil {
		http.Error(w, "device dispatch failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(cloudTransferDispatchResponse{Accepted: true, DeviceID: input.DeviceID, TransferID: input.TransferID})
}

func validCanonicalTransferID(value string) bool {
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 {
		return false
	}
	_, err := hex.DecodeString(compact)
	return err == nil
}

func validCloudTransferToken(value string) bool {
	if !strings.HasPrefix(value, cloudTransferTokenPrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, cloudTransferTokenPrefix))
	return err == nil && len(decoded) == cloudTransferTokenBytes && subtle.ConstantTimeCompare(decoded, make([]byte, len(decoded))) == 0
}

func validCloudTransferBootstrapURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}
