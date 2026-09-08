package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	enrollmentCodePrefix      = "rdeve_"
	deviceSecretPrefix        = "rdevd_"
	enrollmentSecretBytes     = 32
	enrollmentMinLifetime     = time.Minute
	enrollmentMaxLifetime     = 15 * time.Minute
	enrollmentRequestMaxBytes = 16 * 1024
	managedDeviceIDMaxBytes   = 128
	managedDeviceRegistryV2   = "rdev-device-registry.v2"
	managedDeviceRegistryV3   = "rdev-device-registry.v3"
)

var (
	errEnrollmentConsumed   = errors.New("consumed enrollment cannot be revoked")
	errManagedDeviceRevoked = errors.New("managed device is revoked")
)

type enrollmentInvite struct {
	ID             string
	Subject        string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	ConsumedAt     time.Time
	RevokedAt      time.Time
	IssuedDeviceID string
}

type managedDevice struct {
	ID                string
	OwnerSubject      string
	SecretHash        string
	CredentialVersion uint64
	CreatedAt         time.Time
	UpdatedAt         time.Time
	RevokedAt         time.Time
}

type managedDeviceRegistry struct {
	Schema      string                        `json:"schema"`
	Devices     []managedDeviceRegistryRecord `json:"devices"`
	Enrollments []enrollmentRegistryRecord    `json:"enrollments"`
}

type managedDeviceRegistryRecord struct {
	ID                string `json:"id"`
	OwnerSubject      string `json:"owner_subject"`
	SecretHash        string `json:"secret_hash"`
	CredentialVersion uint64 `json:"credential_version,omitempty"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
	RevokedAt         string `json:"revoked_at,omitempty"`
}

type enrollmentRegistryRecord struct {
	ID             string `json:"id"`
	Subject        string `json:"subject"`
	CodeHash       string `json:"code_hash"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"`
	ConsumedAt     string `json:"consumed_at,omitempty"`
	RevokedAt      string `json:"revoked_at,omitempty"`
	IssuedDeviceID string `json:"issued_device_id,omitempty"`
}

type enrollmentCreateRequest struct {
	Subject         string `json:"subject"`
	ExpiresInSecond int64  `json:"expiresInSeconds"`
}

type enrollmentCreateResponse struct {
	EnrollmentID string `json:"enrollmentId"`
	Code         string `json:"code"`
	JoinURL      string `json:"joinUrl"`
	ExpiresAt    string `json:"expiresAt"`
	ExpiresAtMs  int64  `json:"expiresAtMs"`
}

type enrollmentRedeemRequest struct {
	Code            string `json:"code"`
	DeviceID        string `json:"deviceId"`
	ReplaceExisting bool   `json:"replaceExisting"`
}

type enrollmentRedeemResponse struct {
	DeviceID     string `json:"deviceId"`
	DeviceSecret string `json:"deviceSecret"`
	ServerURL    string `json:"serverUrl"`
}

type enrollmentStatusResponse struct {
	EnrollmentID   string `json:"enrollmentId"`
	Subject        string `json:"subject"`
	State          string `json:"state"`
	CreatedAt      string `json:"createdAt"`
	ExpiresAt      string `json:"expiresAt"`
	ExpiresAtMs    int64  `json:"expiresAtMs"`
	ConsumedAt     string `json:"consumedAt,omitempty"`
	RevokedAt      string `json:"revokedAt,omitempty"`
	IssuedDeviceID string `json:"issuedDeviceId,omitempty"`
}

type deviceSecretRotateResponse struct {
	DeviceID     string `json:"deviceId"`
	DeviceSecret string `json:"deviceSecret"`
	RotatedAt    string `json:"rotatedAt"`
	RotatedAtMs  int64  `json:"rotatedAtMs"`
}

func (s *Server) ConfigureEnrollmentStore(registryPath, publicURL string) error {
	if registryPath == "" || !filepath.IsAbs(registryPath) {
		return errors.New("managed device registry path must be absolute")
	}
	var normalizedPublicURL string
	if publicURL != "" {
		parsed, err := url.Parse(publicURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
			parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" ||
			(parsed.Path != "" && parsed.Path != "/") {
			return errors.New("public URL must contain only an HTTPS scheme and host")
		}
		normalizedPublicURL = strings.TrimRight(parsed.String(), "/")
	}
	if err := os.MkdirAll(filepath.Dir(registryPath), 0700); err != nil {
		return fmt.Errorf("create managed device registry directory: %w", err)
	}

	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	s.enrollmentRegistryPath = registryPath
	s.enrollmentPublicURL = normalizedPublicURL
	if err := s.loadManagedDeviceRegistryLocked(); err != nil {
		return err
	}
	return nil
}

func (s *Server) HandleEnrollmentCreateAPI(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrollmentControl(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input enrollmentCreateRequest
	if !decodeEnrollmentJSON(w, r, &input) {
		return
	}
	if input.Subject == "" || strings.TrimSpace(input.Subject) != input.Subject || len(input.Subject) > 128 {
		http.Error(w, "subject is required and must not exceed 128 bytes", http.StatusBadRequest)
		return
	}
	lifetime := time.Duration(input.ExpiresInSecond) * time.Second
	if lifetime < enrollmentMinLifetime || lifetime > enrollmentMaxLifetime {
		http.Error(w, "expiresInSeconds must be between 60 and 900", http.StatusBadRequest)
		return
	}
	code, enrollmentID, err := newEnrollmentValue()
	if err != nil {
		http.Error(w, "enrollment generation failed", http.StatusInternalServerError)
		return
	}
	now := s.enrollmentCurrentTime()
	expiresAt := now.Add(lifetime).UTC().Truncate(time.Second)
	hash := sha256.Sum256([]byte(code))

	s.enrollmentMu.Lock()
	if s.enrollmentPublicURL == "" {
		s.enrollmentMu.Unlock()
		http.Error(w, "enrollment is unavailable", http.StatusServiceUnavailable)
		return
	}
	s.enrollments[hash] = enrollmentInvite{
		ID: enrollmentID, Subject: input.Subject, CreatedAt: now.UTC().Truncate(time.Second), ExpiresAt: expiresAt,
	}
	if err = s.persistManagedDeviceRegistryLocked(); err != nil {
		delete(s.enrollments, hash)
		s.enrollmentMu.Unlock()
		http.Error(w, "enrollment registry write failed", http.StatusInternalServerError)
		return
	}
	joinURL := s.enrollmentPublicURL + "/join#" + code
	s.enrollmentMu.Unlock()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrollmentCreateResponse{
		EnrollmentID: enrollmentID,
		Code:         code,
		JoinURL:      joinURL,
		ExpiresAt:    expiresAt.Format(time.RFC3339),
		ExpiresAtMs:  expiresAt.UnixMilli(),
	})
}

func (s *Server) HandleEnrollmentLifecycleAPI(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrollmentControl(w, r) {
		return
	}
	enrollmentID, ok := exactPathIdentifier(r, "/api/control/enrollments/", false)
	if !ok || !validEnrollmentID(enrollmentID) {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.enrollmentMu.Lock()
		invite, found := s.enrollmentByIDLocked(enrollmentID)
		s.enrollmentMu.Unlock()
		if !found {
			http.NotFound(w, r)
			return
		}
		writeEnrollmentJSON(w, enrollmentStatusFor(invite, s.enrollmentCurrentTime()))
	case http.MethodDelete:
		if err := s.revokeEnrollment(enrollmentID); errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		} else if errors.Is(err, errEnrollmentConsumed) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		} else if err != nil {
			http.Error(w, "enrollment revocation failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) HandleManagedDeviceLifecycleAPI(w http.ResponseWriter, r *http.Request) {
	if !s.requireEnrollmentControl(w, r) {
		return
	}
	rotate := strings.HasSuffix(r.URL.EscapedPath(), "/rotate-secret")
	deviceID, ok := exactPathIdentifier(r, "/api/control/devices/", rotate)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if rotate {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		secret, rotatedAt, err := s.rotateManagedDeviceSecret(deviceID)
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
			return
		}
		if errors.Is(err, errManagedDeviceRevoked) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(w, "device secret rotation failed", http.StatusInternalServerError)
			return
		}
		s.disconnectManagedDevice(deviceID, "device secret rotated")
		writeEnrollmentJSON(w, deviceSecretRotateResponse{
			DeviceID: deviceID, DeviceSecret: secret,
			RotatedAt: rotatedAt.Format(time.RFC3339), RotatedAtMs: rotatedAt.UnixMilli(),
		})
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.revokeManagedDevice(deviceID); errors.Is(err, os.ErrNotExist) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "device revocation failed", http.StatusInternalServerError)
		return
	}
	s.disconnectManagedDevice(deviceID, "device revoked")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) HandleEnrollmentRedeemAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input enrollmentRedeemRequest
	if !decodeEnrollmentJSON(w, r, &input) {
		return
	}
	if !validEnrollmentCode(input.Code) {
		http.Error(w, "invalid or expired enrollment", http.StatusUnauthorized)
		return
	}
	if err := validateManagedDeviceID(input.DeviceID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	hash := sha256.Sum256([]byte(input.Code))
	now := s.enrollmentCurrentTime()
	s.enrollmentMu.Lock()
	invite, ok := s.enrollments[hash]
	if !ok || !invite.ExpiresAt.After(now) || !invite.ConsumedAt.IsZero() || !invite.RevokedAt.IsZero() {
		s.enrollmentMu.Unlock()
		http.Error(w, "invalid or expired enrollment", http.StatusUnauthorized)
		return
	}
	secret, err := newDeviceSecret()
	if err != nil {
		s.enrollmentMu.Unlock()
		http.Error(w, "device secret generation failed", http.StatusInternalServerError)
		return
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		s.enrollmentMu.Unlock()
		http.Error(w, "device secret hash failed", http.StatusInternalServerError)
		return
	}
	assignedID := input.DeviceID
	originalDevice, deviceExists := s.managedDevices[input.DeviceID]
	replacing := false
	type replacedConnection struct {
		id     string
		client *ClientConn
	}
	replacedConnections := make([]replacedConnection, 0, 1)
	if input.ReplaceExisting {
		if deviceExists {
			if originalDevice.OwnerSubject != invite.Subject {
				s.enrollmentMu.Unlock()
				http.Error(w, "managed device replacement is not allowed", http.StatusConflict)
				return
			}
			if !originalDevice.RevokedAt.IsZero() {
				s.enrollmentMu.Unlock()
				http.Error(w, errManagedDeviceRevoked.Error(), http.StatusConflict)
				return
			}
			replacing = true
			s.mu.RLock()
			for id, client := range s.clients {
				if client.RequestedID == input.DeviceID || (client.RequestedID == "" && client.ID == input.DeviceID) {
					replacedConnections = append(replacedConnections, replacedConnection{id: id, client: client})
				}
			}
			s.mu.RUnlock()
		} else if s.clientByID(input.DeviceID) != nil {
			s.enrollmentMu.Unlock()
			http.Error(w, "managed device replacement is not allowed", http.StatusConflict)
			return
		}
	} else {
		assignedID = s.nextManagedDeviceIDLocked(input.DeviceID)
	}
	storedAt := now.UTC().Truncate(time.Second)
	updatedDevice := managedDevice{
		ID: assignedID, OwnerSubject: invite.Subject, SecretHash: string(passwordHash), CredentialVersion: 1,
		CreatedAt: storedAt, UpdatedAt: storedAt,
	}
	if replacing {
		updatedDevice.CreatedAt = originalDevice.CreatedAt
		updatedDevice.CredentialVersion, err = nextManagedDeviceCredentialVersion(originalDevice.CredentialVersion)
		if err != nil {
			s.enrollmentMu.Unlock()
			http.Error(w, "managed device credential version exhausted", http.StatusConflict)
			return
		}
	}
	s.managedDevices[assignedID] = updatedDevice
	invite.ConsumedAt = storedAt
	invite.IssuedDeviceID = assignedID
	s.enrollments[hash] = invite
	if err = s.persistManagedDeviceRegistryLocked(); err != nil {
		if replacing {
			s.managedDevices[assignedID] = originalDevice
		} else {
			delete(s.managedDevices, assignedID)
		}
		invite.ConsumedAt = time.Time{}
		invite.IssuedDeviceID = ""
		s.enrollments[hash] = invite
		s.enrollmentMu.Unlock()
		http.Error(w, "managed device registry write failed", http.StatusInternalServerError)
		return
	}
	if replacing {
		s.mu.Lock()
		for _, connected := range replacedConnections {
			if s.clients[connected.id] == connected.client {
				delete(s.clients, connected.id)
			}
		}
		s.mu.Unlock()
	}
	s.enrollmentMu.Unlock()
	if replacing {
		for _, connected := range replacedConnections {
			s.publishDeviceEvent("device.offline", connected.client, connected.id, "", "")
		}
		s.invalidateAccessTicketConnectionsForDevice(input.DeviceID)
		for _, connected := range replacedConnections {
			closeClientResources(s, connected.client)
			if connected.client.Transport != nil {
				_ = connected.client.Transport.Close("managed device replaced")
			}
		}
	}
	s.publishDeviceEvent("enrollment.consumed", nil, assignedID, invite.ID, invite.Subject)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrollmentRedeemResponse{
		DeviceID:     assignedID,
		DeviceSecret: secret,
		ServerURL:    s.enrollmentPublicURL,
	})
}

func decodeEnrollmentJSON(w http.ResponseWriter, r *http.Request, output any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, enrollmentRequestMaxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) requireEnrollmentControl(w http.ResponseWriter, r *http.Request) bool {
	if !s.secureControlEnabled() {
		http.Error(w, "device enrollment requires an enabled control credential", http.StatusServiceUnavailable)
		return false
	}
	if !s.controlAuthOK(r) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func validEnrollmentID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
}

func exactPathIdentifier(r *http.Request, prefix string, trimRotateSuffix bool) (string, bool) {
	escaped := strings.TrimPrefix(r.URL.EscapedPath(), prefix)
	if escaped == r.URL.EscapedPath() {
		return "", false
	}
	if trimRotateSuffix {
		const suffix = "/rotate-secret"
		if !strings.HasSuffix(escaped, suffix) {
			return "", false
		}
		escaped = strings.TrimSuffix(escaped, suffix)
	}
	if escaped == "" || strings.Contains(escaped, "/") {
		return "", false
	}
	value, err := url.PathUnescape(escaped)
	if err != nil || validateManagedDeviceID(value) != nil {
		return "", false
	}
	return value, true
}

func (s *Server) enrollmentByIDLocked(enrollmentID string) (enrollmentInvite, bool) {
	for _, invite := range s.enrollments {
		if invite.ID == enrollmentID {
			return invite, true
		}
	}
	return enrollmentInvite{}, false
}

func enrollmentStatusFor(invite enrollmentInvite, now time.Time) enrollmentStatusResponse {
	state := "active"
	switch {
	case !invite.RevokedAt.IsZero():
		state = "revoked"
	case !invite.ConsumedAt.IsZero():
		state = "consumed"
	case !invite.ExpiresAt.After(now):
		state = "expired"
	}
	response := enrollmentStatusResponse{
		EnrollmentID: invite.ID, Subject: invite.Subject, State: state,
		CreatedAt: invite.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt: invite.ExpiresAt.UTC().Format(time.RFC3339), ExpiresAtMs: invite.ExpiresAt.UnixMilli(),
		IssuedDeviceID: invite.IssuedDeviceID,
	}
	if !invite.ConsumedAt.IsZero() {
		response.ConsumedAt = invite.ConsumedAt.UTC().Format(time.RFC3339)
	}
	if !invite.RevokedAt.IsZero() {
		response.RevokedAt = invite.RevokedAt.UTC().Format(time.RFC3339)
	}
	return response
}

func writeEnrollmentJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func (s *Server) revokeEnrollment(enrollmentID string) error {
	now := s.enrollmentCurrentTime().UTC().Truncate(time.Second)
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	for codeHash, invite := range s.enrollments {
		if invite.ID != enrollmentID {
			continue
		}
		if !invite.ConsumedAt.IsZero() {
			return errEnrollmentConsumed
		}
		if !invite.RevokedAt.IsZero() {
			return nil
		}
		original := invite
		invite.RevokedAt = now
		s.enrollments[codeHash] = invite
		if err := s.persistManagedDeviceRegistryLocked(); err != nil {
			s.enrollments[codeHash] = original
			return err
		}
		return nil
	}
	return os.ErrNotExist
}

func (s *Server) rotateManagedDeviceSecret(deviceID string) (string, time.Time, error) {
	secret, err := newDeviceSecret()
	if err != nil {
		return "", time.Time{}, err
	}
	secretHash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", time.Time{}, err
	}
	now := s.enrollmentCurrentTime().UTC().Truncate(time.Second)
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	device, ok := s.managedDevices[deviceID]
	if !ok {
		return "", time.Time{}, os.ErrNotExist
	}
	if !device.RevokedAt.IsZero() {
		return "", time.Time{}, errManagedDeviceRevoked
	}
	original := device
	device.SecretHash = string(secretHash)
	device.CredentialVersion, err = nextManagedDeviceCredentialVersion(device.CredentialVersion)
	if err != nil {
		return "", time.Time{}, err
	}
	device.UpdatedAt = now
	s.managedDevices[deviceID] = device
	if err = s.persistManagedDeviceRegistryLocked(); err != nil {
		s.managedDevices[deviceID] = original
		return "", time.Time{}, err
	}
	return secret, now, nil
}

func (s *Server) revokeManagedDevice(deviceID string) error {
	now := s.enrollmentCurrentTime().UTC().Truncate(time.Second)
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	device, ok := s.managedDevices[deviceID]
	if !ok {
		return os.ErrNotExist
	}
	if !device.RevokedAt.IsZero() {
		return nil
	}
	original := device
	var err error
	device.CredentialVersion, err = nextManagedDeviceCredentialVersion(device.CredentialVersion)
	if err != nil {
		return err
	}
	device.RevokedAt = now
	device.UpdatedAt = now
	s.managedDevices[deviceID] = device
	if err := s.persistManagedDeviceRegistryLocked(); err != nil {
		s.managedDevices[deviceID] = original
		return err
	}
	return nil
}

func (s *Server) disconnectManagedDevice(deviceID, reason string) {
	type connectedTransport struct {
		client *ClientConn
	}
	s.mu.Lock()
	connected := make([]connectedTransport, 0, 1)
	for id, client := range s.clients {
		if client.RequestedID == deviceID || (client.RequestedID == "" && client.ID == deviceID) {
			connected = append(connected, connectedTransport{client: client})
			delete(s.clients, id)
		}
	}
	s.mu.Unlock()
	s.invalidateAccessTicketConnectionsForDevice(deviceID)
	if len(connected) == 0 {
		return
	}
	for _, connectedClient := range connected {
		s.publishDeviceEvent("device.offline", connectedClient.client, deviceID, "", "")
		closeClientResources(s, connectedClient.client)
		if connectedClient.client.Transport != nil {
			_ = connectedClient.client.Transport.Close(reason)
		}
	}
}

func nextManagedDeviceCredentialVersion(current uint64) (uint64, error) {
	if current == 0 || current == math.MaxUint64 {
		return 0, errors.New("managed device credential version is invalid")
	}
	return current + 1, nil
}

func (s *Server) authorizeManagedRegistration(deviceID, secret string) (bool, bool) {
	s.enrollmentMu.Lock()
	device, managed := s.managedDevices[deviceID]
	s.enrollmentMu.Unlock()
	if !managed {
		return false, false
	}
	if !device.RevokedAt.IsZero() {
		return false, true
	}
	return bcrypt.CompareHashAndPassword([]byte(device.SecretHash), []byte(secret)) == nil, true
}

func (s *Server) managedDeviceAccessAllowed(deviceID, subject string) bool {
	s.enrollmentMu.Lock()
	device, managed := s.managedDevices[deviceID]
	s.enrollmentMu.Unlock()
	if !managed {
		return false
	}
	if !device.RevokedAt.IsZero() {
		return false
	}
	return managedDeviceSubjectAllowed(device.OwnerSubject, subject)
}

// The authenticated control plane supplies the actual operator, never the owner
// on their behalf. Feidu devices are shared across valid Feidu account subjects.
func managedDeviceSubjectAllowed(ownerSubject, subject string) bool {
	if strings.HasPrefix(ownerSubject, "feidu-user:") {
		return isFeiduAccountSubject(ownerSubject, "feidu-user:") &&
			(isFeiduAccountSubject(subject, "feidu-user:") || isFeiduAccountSubject(subject, "feidu-browser:"))
	}
	return ownerSubject != "" && ownerSubject == subject
}

func isFeiduAccountSubject(subject, prefix string) bool {
	if !strings.HasPrefix(subject, prefix) {
		return false
	}
	accountID := strings.TrimPrefix(subject, prefix)
	id, err := strconv.ParseUint(accountID, 10, 64)
	if err == nil && id > 0 && strconv.FormatUint(id, 10) == accountID {
		return true
	}
	return false
}

func (s *Server) managedDeviceOwner(deviceID string) string {
	s.enrollmentMu.Lock()
	device, managed := s.managedDevices[deviceID]
	s.enrollmentMu.Unlock()
	if !managed || !device.RevokedAt.IsZero() {
		return ""
	}
	return device.OwnerSubject
}

func (s *Server) nextManagedDeviceIDLocked(base string) string {
	if _, exists := s.managedDevices[base]; !exists && s.clientByID(base) == nil {
		return base
	}
	for suffix := 2; ; suffix++ {
		availableID := fmt.Sprintf("%s-%d", base, suffix)
		if _, exists := s.managedDevices[availableID]; exists {
			continue
		}
		if s.clientByID(availableID) == nil {
			return availableID
		}
	}
}

func (s *Server) enrollmentCurrentTime() time.Time {
	if s.enrollmentNow != nil {
		return s.enrollmentNow()
	}
	return time.Now()
}

func validateManagedDeviceID(value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return errors.New("deviceId is required without surrounding whitespace")
	}
	if len(value) > managedDeviceIDMaxBytes {
		return errors.New("deviceId must not exceed 128 bytes")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return errors.New("deviceId must not contain control characters")
		}
	}
	return nil
}

func validEnrollmentCode(value string) bool {
	if !strings.HasPrefix(value, enrollmentCodePrefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, enrollmentCodePrefix))
	return err == nil && len(decoded) == enrollmentSecretBytes
}

func newEnrollmentValue() (string, string, error) {
	secret := make([]byte, enrollmentSecretBytes)
	id := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(id); err != nil {
		return "", "", err
	}
	return enrollmentCodePrefix + base64.RawURLEncoding.EncodeToString(secret), hex.EncodeToString(id), nil
}

func newDeviceSecret() (string, error) {
	secret := make([]byte, enrollmentSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return deviceSecretPrefix + base64.RawURLEncoding.EncodeToString(secret), nil
}

func (s *Server) loadManagedDeviceRegistryLocked() error {
	s.managedDevices = make(map[string]managedDevice)
	s.enrollments = make(map[[32]byte]enrollmentInvite)
	data, err := os.ReadFile(s.enrollmentRegistryPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read managed device registry: %w", err)
	}
	var registry managedDeviceRegistry
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&registry); err != nil {
		return fmt.Errorf("decode managed device registry: %w", err)
	}
	var trailing json.RawMessage
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("decode managed device registry: trailing data")
	}
	if registry.Schema != managedDeviceRegistryV2 && registry.Schema != managedDeviceRegistryV3 {
		return errors.New("managed device registry schema is invalid")
	}
	for _, record := range registry.Devices {
		if err = validateManagedDeviceID(record.ID); err != nil {
			return fmt.Errorf("managed device registry id: %w", err)
		}
		if record.OwnerSubject == "" || strings.TrimSpace(record.OwnerSubject) != record.OwnerSubject || len(record.OwnerSubject) > 128 {
			return errors.New("managed device registry owner_subject is invalid")
		}
		if _, hashErr := bcrypt.Cost([]byte(record.SecretHash)); hashErr != nil {
			return errors.New("managed device registry secret hash is invalid")
		}
		credentialVersion := record.CredentialVersion
		if registry.Schema == managedDeviceRegistryV2 {
			credentialVersion = 1
		}
		if credentialVersion == 0 {
			return errors.New("managed device registry credential_version is invalid")
		}
		createdAt, parseErr := parseRegistryTime(record.CreatedAt, true)
		if parseErr != nil {
			return errors.New("managed device registry created_at is invalid")
		}
		updatedAt, parseErr := parseRegistryTime(record.UpdatedAt, true)
		if parseErr != nil || updatedAt.Before(createdAt) {
			return errors.New("managed device registry updated_at is invalid")
		}
		revokedAt, parseErr := parseRegistryTime(record.RevokedAt, false)
		if parseErr != nil || (!revokedAt.IsZero() && revokedAt.Before(createdAt)) {
			return errors.New("managed device registry revoked_at is invalid")
		}
		if !revokedAt.IsZero() && updatedAt.Before(revokedAt) {
			return errors.New("managed device registry revoked_at exceeds updated_at")
		}
		if _, duplicate := s.managedDevices[record.ID]; duplicate {
			return errors.New("managed device registry contains duplicate ids")
		}
		s.managedDevices[record.ID] = managedDevice{
			ID: record.ID, OwnerSubject: record.OwnerSubject, SecretHash: record.SecretHash,
			CredentialVersion: credentialVersion, CreatedAt: createdAt, UpdatedAt: updatedAt, RevokedAt: revokedAt,
		}
	}
	seenEnrollmentIDs := make(map[string]struct{}, len(registry.Enrollments))
	for _, record := range registry.Enrollments {
		decodedHash, decodeErr := hex.DecodeString(record.CodeHash)
		if decodeErr != nil || len(decodedHash) != sha256.Size || hex.EncodeToString(decodedHash) != record.CodeHash {
			return errors.New("enrollment registry code_hash is invalid")
		}
		var codeHash [sha256.Size]byte
		copy(codeHash[:], decodedHash)
		if _, duplicate := s.enrollments[codeHash]; duplicate {
			return errors.New("enrollment registry contains duplicate code hashes")
		}
		if !validEnrollmentID(record.ID) || record.Subject == "" || strings.TrimSpace(record.Subject) != record.Subject || len(record.Subject) > 128 {
			return errors.New("enrollment registry identity is invalid")
		}
		if _, duplicate := seenEnrollmentIDs[record.ID]; duplicate {
			return errors.New("enrollment registry contains duplicate ids")
		}
		seenEnrollmentIDs[record.ID] = struct{}{}
		createdAt, parseErr := parseRegistryTime(record.CreatedAt, true)
		if parseErr != nil {
			return errors.New("enrollment registry created_at is invalid")
		}
		expiresAt, parseErr := parseRegistryTime(record.ExpiresAt, true)
		if parseErr != nil || !expiresAt.After(createdAt) {
			return errors.New("enrollment registry expires_at is invalid")
		}
		consumedAt, parseErr := parseRegistryTime(record.ConsumedAt, false)
		if parseErr != nil || (!consumedAt.IsZero() && (consumedAt.Before(createdAt) || !consumedAt.Before(expiresAt))) {
			return errors.New("enrollment registry consumed_at is invalid")
		}
		revokedAt, parseErr := parseRegistryTime(record.RevokedAt, false)
		if parseErr != nil || (!revokedAt.IsZero() && revokedAt.Before(createdAt)) || (!consumedAt.IsZero() && !revokedAt.IsZero()) {
			return errors.New("enrollment registry revoked_at is invalid")
		}
		if consumedAt.IsZero() != (record.IssuedDeviceID == "") {
			return errors.New("enrollment registry issued device state is invalid")
		}
		if record.IssuedDeviceID != "" {
			device, exists := s.managedDevices[record.IssuedDeviceID]
			if !exists || device.OwnerSubject != record.Subject {
				return errors.New("enrollment registry issued device identity is invalid")
			}
		}
		s.enrollments[codeHash] = enrollmentInvite{
			ID: record.ID, Subject: record.Subject, CreatedAt: createdAt, ExpiresAt: expiresAt,
			ConsumedAt: consumedAt, RevokedAt: revokedAt, IssuedDeviceID: record.IssuedDeviceID,
		}
	}
	return nil
}

func parseRegistryTime(value string, required bool) (time.Time, error) {
	if value == "" && !required {
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return parsed, nil
}

func (s *Server) persistManagedDeviceRegistryLocked() error {
	if s.enrollmentRegistryPath == "" {
		return errors.New("managed device registry is unavailable")
	}
	ids := make([]string, 0, len(s.managedDevices))
	for id := range s.managedDevices {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	registry := managedDeviceRegistry{
		Schema: managedDeviceRegistryV3, Devices: make([]managedDeviceRegistryRecord, 0, len(ids)),
		Enrollments: make([]enrollmentRegistryRecord, 0, len(s.enrollments)),
	}
	for _, id := range ids {
		device := s.managedDevices[id]
		record := managedDeviceRegistryRecord{
			ID: id, OwnerSubject: device.OwnerSubject, SecretHash: device.SecretHash,
			CredentialVersion: device.CredentialVersion,
			CreatedAt:         device.CreatedAt.UTC().Format(time.RFC3339), UpdatedAt: device.UpdatedAt.UTC().Format(time.RFC3339),
		}
		if !device.RevokedAt.IsZero() {
			record.RevokedAt = device.RevokedAt.UTC().Format(time.RFC3339)
		}
		registry.Devices = append(registry.Devices, record)
	}
	enrollmentHashes := make([][sha256.Size]byte, 0, len(s.enrollments))
	for codeHash := range s.enrollments {
		enrollmentHashes = append(enrollmentHashes, codeHash)
	}
	sort.Slice(enrollmentHashes, func(i, j int) bool {
		return hex.EncodeToString(enrollmentHashes[i][:]) < hex.EncodeToString(enrollmentHashes[j][:])
	})
	for _, codeHash := range enrollmentHashes {
		invite := s.enrollments[codeHash]
		record := enrollmentRegistryRecord{
			ID: invite.ID, Subject: invite.Subject, CodeHash: hex.EncodeToString(codeHash[:]),
			CreatedAt: invite.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: invite.ExpiresAt.UTC().Format(time.RFC3339),
			IssuedDeviceID: invite.IssuedDeviceID,
		}
		if !invite.ConsumedAt.IsZero() {
			record.ConsumedAt = invite.ConsumedAt.UTC().Format(time.RFC3339)
		}
		if !invite.RevokedAt.IsZero() {
			record.RevokedAt = invite.RevokedAt.UTC().Format(time.RFC3339)
		}
		registry.Enrollments = append(registry.Enrollments, record)
	}
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(s.enrollmentRegistryPath), ".managed-devices-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, s.enrollmentRegistryPath)
}
