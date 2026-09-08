package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lxzan/gws"
)

const (
	accessTicketPrefix           = "rdvat_"
	browserSocketProtocol        = "rdev-browser-v1"
	browserTicketProtocol        = "rdev-access-ticket."
	browserTicketSubject         = "feidu-browser:"
	accessTicketSecretBytes      = 32
	accessTicketMinLifetime      = time.Minute
	accessTicketMaxLifetime      = 8 * time.Hour
	accessTicketRegistryV1       = "rdev-access-ticket-registry.v1"
	accessTicketRegistryV2       = "rdev-access-ticket-registry.v2"
	accessTicketRegistryV3       = "rdev-access-ticket-registry.v3"
	browserCapabilityTerminal    = "terminal"
	browserCapabilityFiles       = "files"
	browserCapabilityDesktop     = "desktop"
	browserCapabilityPeripherals = "peripherals"
	browserTicketSessionKey      = "browserAccessTicketID"
	browserSubjectSessionKey     = "browserAccessSubject"
)

var browserCapabilityByPath = map[string]string{
	"/terminal":    browserCapabilityTerminal,
	"/files":       browserCapabilityFiles,
	"/desktop":     browserCapabilityDesktop,
	"/peripherals": browserCapabilityPeripherals,
}

type accessTicket struct {
	ID                      string
	DeviceID                string
	DeviceCredentialVersion uint64
	InstanceID              string
	PasswordFingerprint     string
	Subject                 string
	Capabilities            []string
	ExpiresAt               time.Time
}

type accessTicketRegistry struct {
	Schema  string                       `json:"schema"`
	Tickets []accessTicketRegistryRecord `json:"tickets"`
}

type accessTicketRegistryRecord struct {
	TicketHash              string   `json:"ticket_hash"`
	ID                      string   `json:"id"`
	DeviceID                string   `json:"device_id"`
	DeviceCredentialVersion uint64   `json:"device_credential_version,omitempty"`
	InstanceID              string   `json:"instance_id"`
	PasswordFingerprint     string   `json:"password_fingerprint"`
	Subject                 string   `json:"subject"`
	Capabilities            []string `json:"capabilities,omitempty"`
	ExpiresAt               string   `json:"expires_at"`
}

type deviceAuthorization struct {
	DeviceID                string
	DeviceCredentialVersion uint64
	InstanceID              string
	PasswordFingerprint     string
	TicketID                string
	TicketExpiresAt         time.Time
}

type accessTicketCreateRequest struct {
	DeviceID        string   `json:"deviceId"`
	Subject         string   `json:"subject"`
	ExpiresInSecond int64    `json:"expiresInSeconds"`
	Capabilities    []string `json:"capabilities,omitempty"`
}

type accessTicketCreateResponse struct {
	Ticket      string `json:"ticket"`
	TicketID    string `json:"ticketId"`
	DeviceID    string `json:"deviceId"`
	ExpiresAt   string `json:"expiresAt"`
	ExpiresAtMs int64  `json:"expiresAtMs"`
}

type accessTicketRevokeRequest struct {
	TicketID string `json:"ticketId"`
}

type accessTicketRenewRequest struct {
	TicketID    string `json:"ticketId"`
	ExpiresAtMs int64  `json:"expiresAtMs"`
}

type accessTicketRenewResponse struct {
	TicketID    string `json:"ticketId"`
	DeviceID    string `json:"deviceId"`
	ExpiresAt   string `json:"expiresAt"`
	ExpiresAtMs int64  `json:"expiresAtMs"`
}

func (s *Server) ConfigureAccessTicketStore(storePath string) error {
	if storePath == "" || !filepath.IsAbs(storePath) {
		return errors.New("access ticket store path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(storePath), 0700); err != nil {
		return fmt.Errorf("create access ticket store directory: %w", err)
	}
	s.accessTicketMu.Lock()
	defer s.accessTicketMu.Unlock()
	s.accessTicketStorePath = storePath
	return s.loadAccessTicketsLocked()
}

func (s *Server) loadAccessTicketsLocked() error {
	s.accessTickets = make(map[[sha256.Size]byte]accessTicket)
	data, err := os.ReadFile(s.accessTicketStorePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read access ticket store: %w", err)
	}
	var registry accessTicketRegistry
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&registry); err != nil {
		return fmt.Errorf("decode access ticket store: %w", err)
	}
	var trailing json.RawMessage
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("decode access ticket store: trailing data")
	}
	if registry.Schema != accessTicketRegistryV1 && registry.Schema != accessTicketRegistryV2 && registry.Schema != accessTicketRegistryV3 {
		return errors.New("access ticket store schema is invalid")
	}
	now := s.accessTicketCurrentTime()
	seenIDs := make(map[string]struct{}, len(registry.Tickets))
	for _, record := range registry.Tickets {
		decodedHash, decodeErr := hex.DecodeString(record.TicketHash)
		if decodeErr != nil || len(decodedHash) != sha256.Size || hex.EncodeToString(decodedHash) != record.TicketHash {
			return errors.New("access ticket store ticket_hash is invalid")
		}
		decodedID, decodeErr := hex.DecodeString(record.ID)
		if decodeErr != nil || len(decodedID) != 16 || hex.EncodeToString(decodedID) != record.ID {
			return errors.New("access ticket store id is invalid")
		}
		if _, duplicate := seenIDs[record.ID]; duplicate {
			return errors.New("access ticket store contains duplicate ids")
		}
		seenIDs[record.ID] = struct{}{}
		if err = validateManagedDeviceID(record.DeviceID); err != nil {
			return fmt.Errorf("access ticket store device_id: %w", err)
		}
		if strings.TrimSpace(record.InstanceID) != record.InstanceID {
			return errors.New("access ticket store instance_id is invalid")
		}
		decodedFingerprint, decodeErr := hex.DecodeString(record.PasswordFingerprint)
		if decodeErr != nil || len(decodedFingerprint) != sha256.Size || hex.EncodeToString(decodedFingerprint) != record.PasswordFingerprint {
			return errors.New("access ticket store password_fingerprint is invalid")
		}
		if record.Subject == "" || strings.TrimSpace(record.Subject) != record.Subject || len(record.Subject) > 128 {
			return errors.New("access ticket store subject is invalid")
		}
		capabilities := record.Capabilities
		if registry.Schema != accessTicketRegistryV3 {
			capabilities = legacyBrowserCapabilities(record.Subject)
		} else if strings.HasPrefix(record.Subject, browserTicketSubject) && capabilities == nil {
			return errors.New("access ticket store browser capabilities are missing")
		}
		capabilities, err = normalizeAccessTicketCapabilities(record.Subject, capabilities)
		if err != nil {
			return fmt.Errorf("access ticket store capabilities: %w", err)
		}
		expiresAt, parseErr := time.Parse(time.RFC3339, record.ExpiresAt)
		if parseErr != nil || expiresAt.UTC().Format(time.RFC3339) != record.ExpiresAt {
			return errors.New("access ticket store expires_at is invalid")
		}
		if !expiresAt.After(now) {
			continue
		}
		var ticketHash [sha256.Size]byte
		copy(ticketHash[:], decodedHash)
		if _, duplicate := s.accessTickets[ticketHash]; duplicate {
			return errors.New("access ticket store contains duplicate ticket hashes")
		}
		s.accessTickets[ticketHash] = accessTicket{
			ID: record.ID, DeviceID: record.DeviceID, InstanceID: record.InstanceID,
			DeviceCredentialVersion: record.DeviceCredentialVersion,
			PasswordFingerprint:     record.PasswordFingerprint, Subject: record.Subject,
			Capabilities: capabilities, ExpiresAt: expiresAt,
		}
	}
	return nil
}

func (s *Server) persistAccessTicketsLocked() error {
	if s.accessTicketStorePath == "" {
		return nil
	}
	hashes := make([][sha256.Size]byte, 0, len(s.accessTickets))
	for hash := range s.accessTickets {
		hashes = append(hashes, hash)
	}
	sort.Slice(hashes, func(i, j int) bool {
		return hex.EncodeToString(hashes[i][:]) < hex.EncodeToString(hashes[j][:])
	})
	registry := accessTicketRegistry{Schema: accessTicketRegistryV3, Tickets: make([]accessTicketRegistryRecord, 0, len(hashes))}
	for _, hash := range hashes {
		ticket := s.accessTickets[hash]
		registry.Tickets = append(registry.Tickets, accessTicketRegistryRecord{
			TicketHash: hex.EncodeToString(hash[:]), ID: ticket.ID, DeviceID: ticket.DeviceID,
			DeviceCredentialVersion: ticket.DeviceCredentialVersion,
			InstanceID:              ticket.InstanceID, PasswordFingerprint: ticket.PasswordFingerprint,
			Subject: ticket.Subject, Capabilities: append([]string(nil), ticket.Capabilities...),
			ExpiresAt: ticket.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(s.accessTicketStorePath), ".access-tickets-*.tmp")
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
	return os.Rename(temporaryPath, s.accessTicketStorePath)
}

func (s *Server) secureControlEnabled() bool {
	return s.ControlToken != ""
}

func (s *Server) controlAuthOK(r *http.Request) bool {
	if !s.secureControlEnabled() {
		return true
	}
	if r == nil {
		return false
	}
	want := sha256.Sum256([]byte(s.ControlToken))
	got := sha256.Sum256([]byte(r.Header.Get("X-RDev-Control-Token")))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

func legacyBrowserCapabilities(subject string) []string {
	if !strings.HasPrefix(subject, browserTicketSubject) {
		return nil
	}
	return []string{browserCapabilityDesktop, browserCapabilityFiles, browserCapabilityTerminal}
}

func normalizeAccessTicketCapabilities(subject string, capabilities []string) ([]string, error) {
	if !strings.HasPrefix(subject, browserTicketSubject) {
		if len(capabilities) != 0 {
			return nil, errors.New("capabilities are supported only for browser tickets")
		}
		return nil, nil
	}
	if capabilities == nil {
		capabilities = legacyBrowserCapabilities(subject)
	}
	if len(capabilities) == 0 || len(capabilities) > len(browserCapabilityByPath) {
		return nil, errors.New("browser ticket capabilities must contain between 1 and 4 entries")
	}
	seen := make(map[string]struct{}, len(capabilities))
	normalized := make([]string, 0, len(capabilities))
	for _, capability := range capabilities {
		switch capability {
		case browserCapabilityTerminal, browserCapabilityFiles, browserCapabilityDesktop, browserCapabilityPeripherals:
		default:
			return nil, errors.New("browser ticket capability is invalid")
		}
		if _, exists := seen[capability]; exists {
			return nil, errors.New("browser ticket capabilities contain a duplicate")
		}
		seen[capability] = struct{}{}
		normalized = append(normalized, capability)
	}
	sort.Strings(normalized)
	return normalized, nil
}

func accessTicketHasCapability(ticket accessTicket, capability string) bool {
	index := sort.SearchStrings(ticket.Capabilities, capability)
	return index < len(ticket.Capabilities) && ticket.Capabilities[index] == capability
}

func (s *Server) browserSocketAuthOK(r *http.Request) bool {
	if !s.secureControlEnabled() || r == nil || r.Method != http.MethodGet ||
		!headerContainsToken(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	capability, allowedPath := browserCapabilityByPath[r.URL.Path]
	if !allowedPath {
		return false
	}
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(value, ",") {
			protocol = strings.TrimSpace(protocol)
			if !strings.HasPrefix(protocol, browserTicketProtocol) {
				continue
			}
			value := strings.TrimPrefix(protocol, browserTicketProtocol)
			if s.browserAccessTicketValid(value, r.URL.Query().Get("device"), capability) {
				return true
			}
		}
	}
	return false
}

func (s *Server) browserSocketTicket(r *http.Request) (accessTicket, bool) {
	if r == nil {
		return accessTicket{}, false
	}
	capability, allowedPath := browserCapabilityByPath[r.URL.Path]
	if !allowedPath {
		return accessTicket{}, false
	}
	requestedDeviceID := r.URL.Query().Get("device")
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocolValue := range strings.Split(value, ",") {
			protocolValue = strings.TrimSpace(protocolValue)
			if !strings.HasPrefix(protocolValue, browserTicketProtocol) {
				continue
			}
			ticketValue := strings.TrimPrefix(protocolValue, browserTicketProtocol)
			if !strings.HasPrefix(ticketValue, accessTicketPrefix) {
				continue
			}
			hash := sha256.Sum256([]byte(ticketValue))
			now := s.accessTicketCurrentTime()
			s.enrollmentMu.Lock()
			s.accessTicketMu.Lock()
			ticket, ok := s.accessTickets[hash]
			device, managed := s.managedDevices[ticket.DeviceID]
			valid := ok && strings.HasPrefix(ticket.Subject, browserTicketSubject) &&
				ticket.ExpiresAt.After(now) && accessTicketHasCapability(ticket, capability) &&
				(requestedDeviceID == "" || requestedDeviceID == ticket.DeviceID) && managed &&
				device.RevokedAt.IsZero() &&
				accessTicketCredentialVersionMatches(ticket.DeviceCredentialVersion, device.CredentialVersion)
			s.accessTicketMu.Unlock()
			s.enrollmentMu.Unlock()
			if valid {
				return ticket, true
			}
		}
	}
	return accessTicket{}, false
}

func (s *Server) authorizeBrowserUpgrade(r *http.Request, session interface{ Store(string, any) }, deviceID string) bool {
	if s.controlAuthOK(r) {
		return true
	}
	ticket, ok := s.browserSocketTicket(r)
	if !ok || (deviceID != "" && ticket.DeviceID != deviceID) {
		return false
	}
	session.Store(browserTicketSessionKey, ticket.ID)
	session.Store(browserSubjectSessionKey, ticket.Subject)
	return true
}

func headerContainsToken(header http.Header, name, want string) bool {
	for _, value := range header.Values(name) {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func (s *Server) browserAccessTicketValid(value, requestedDeviceID, capability string) bool {
	if !strings.HasPrefix(value, accessTicketPrefix) {
		return false
	}
	hash := sha256.Sum256([]byte(value))
	now := s.accessTicketCurrentTime()
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	s.accessTicketMu.Lock()
	defer s.accessTicketMu.Unlock()
	for key, ticket := range s.accessTickets {
		if !ticket.ExpiresAt.After(now) {
			delete(s.accessTickets, key)
		}
	}
	ticket, ok := s.accessTickets[hash]
	if !ok || !strings.HasPrefix(ticket.Subject, browserTicketSubject) || !ticket.ExpiresAt.After(now) ||
		!accessTicketHasCapability(ticket, capability) {
		return false
	}
	device, managed := s.managedDevices[ticket.DeviceID]
	if !managed || !device.RevokedAt.IsZero() ||
		!accessTicketCredentialVersionMatches(ticket.DeviceCredentialVersion, device.CredentialVersion) {
		return false
	}
	return requestedDeviceID == "" || requestedDeviceID == ticket.DeviceID
}

func (s *Server) requiresDeviceCredential(client *ClientConn) bool {
	return s.secureControlEnabled() || (client != nil && client.Password != "")
}

func (s *Server) authorizeDeviceCredential(client *ClientConn, credential string) bool {
	_, ok := s.authorizeDeviceCredentialBinding(client, credential)
	return ok
}

func (s *Server) authorizeDeviceCredentialBinding(client *ClientConn, credential string) (deviceAuthorization, bool) {
	if client == nil {
		return deviceAuthorization{}, false
	}
	if credential != "" {
		if ticket, ok := s.accessTicketForCredential(client, credential); ok {
			authorization := deviceAuthorizationFor(client)
			authorization.TicketID = ticket.ID
			authorization.TicketExpiresAt = ticket.ExpiresAt
			authorization.DeviceCredentialVersion = ticket.DeviceCredentialVersion
			return authorization, true
		}
	}
	if client.Password != "" {
		return deviceAuthorizationFor(client), constantTimeEqual(client.Password, credential)
	}
	return deviceAuthorizationFor(client), !s.secureControlEnabled()
}

func (s *Server) accessTicketValid(client *ClientConn, value string) bool {
	_, ok := s.accessTicketForCredential(client, value)
	return ok
}

func (s *Server) accessTicketForCredential(client *ClientConn, value string) (accessTicket, bool) {
	ticket, valid := s.accessTicketForClient(client, value)
	return ticket, valid && !strings.HasPrefix(ticket.Subject, browserTicketSubject)
}

func (s *Server) accessTicketForBrowserCredential(client *ClientConn, value, capability string) (accessTicket, bool) {
	ticket, valid := s.accessTicketForClient(client, value)
	return ticket, valid && strings.HasPrefix(ticket.Subject, browserTicketSubject) && accessTicketHasCapability(ticket, capability)
}

func (s *Server) accessTicketForClient(client *ClientConn, value string) (accessTicket, bool) {
	if client == nil {
		return accessTicket{}, false
	}
	if !strings.HasPrefix(value, accessTicketPrefix) {
		return accessTicket{}, false
	}
	hash := sha256.Sum256([]byte(value))
	now := s.accessTicketCurrentTime()
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	device, managed := s.managedDevices[client.ID]
	if !managed || !device.RevokedAt.IsZero() {
		return accessTicket{}, false
	}
	s.accessTicketMu.Lock()
	defer s.accessTicketMu.Unlock()
	for key, ticket := range s.accessTickets {
		if !ticket.ExpiresAt.After(now) {
			delete(s.accessTickets, key)
		}
	}
	ticket, ok := s.accessTickets[hash]
	valid := ok && ticket.DeviceID == client.ID &&
		accessTicketCredentialVersionMatches(ticket.DeviceCredentialVersion, device.CredentialVersion) &&
		ticket.InstanceID == client.InstanceID &&
		constantTimeEqual(ticket.PasswordFingerprint, passwordFingerprint(client.Password)) &&
		ticket.ExpiresAt.After(now)
	return ticket, valid
}

func (s *Server) authorizeBrowserDeviceCredentialBinding(client *ClientConn, credential, capability string) (deviceAuthorization, bool) {
	ticket, ok := s.accessTicketForBrowserCredential(client, credential, capability)
	if !ok {
		return deviceAuthorization{}, false
	}
	authorization := deviceAuthorizationFor(client)
	authorization.TicketID = ticket.ID
	authorization.TicketExpiresAt = ticket.ExpiresAt
	authorization.DeviceCredentialVersion = ticket.DeviceCredentialVersion
	return authorization, true
}

func deviceAuthorizationFor(client *ClientConn) deviceAuthorization {
	if client == nil {
		return deviceAuthorization{}
	}
	return deviceAuthorization{
		DeviceID:            client.ID,
		InstanceID:          client.InstanceID,
		PasswordFingerprint: passwordFingerprint(client.Password),
	}
}

func (authorization deviceAuthorization) validFor(client *ClientConn) bool {
	if client == nil {
		return false
	}
	return authorization.DeviceID == client.ID &&
		authorization.InstanceID == client.InstanceID &&
		constantTimeEqual(authorization.PasswordFingerprint, passwordFingerprint(client.Password))
}

func (s *Server) deviceAuthorizationValid(authorization deviceAuthorization, client *ClientConn) bool {
	if !authorization.validFor(client) {
		return false
	}
	if authorization.TicketID == "" {
		return true
	}
	now := s.accessTicketCurrentTime()
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	device, managed := s.managedDevices[authorization.DeviceID]
	if !managed || !device.RevokedAt.IsZero() ||
		!accessTicketCredentialVersionMatches(authorization.DeviceCredentialVersion, device.CredentialVersion) {
		return false
	}
	s.accessTicketMu.Lock()
	defer s.accessTicketMu.Unlock()
	for hash, ticket := range s.accessTickets {
		if !ticket.ExpiresAt.After(now) {
			delete(s.accessTickets, hash)
			continue
		}
		if ticket.ID == authorization.TicketID &&
			accessTicketCredentialVersionMatches(ticket.DeviceCredentialVersion, device.CredentialVersion) {
			return true
		}
	}
	return false
}

func (s *Server) accessTicketCurrentTime() time.Time {
	if s.accessTicketNow != nil {
		return s.accessTicketNow()
	}
	return time.Now()
}

func (s *Server) accessTicketExpiration(ticketID string) (time.Time, bool) {
	now := s.accessTicketCurrentTime()
	s.accessTicketMu.Lock()
	defer s.accessTicketMu.Unlock()
	for hash, ticket := range s.accessTickets {
		if !ticket.ExpiresAt.After(now) {
			delete(s.accessTickets, hash)
			continue
		}
		if ticket.ID == ticketID {
			return ticket.ExpiresAt, true
		}
	}
	return time.Time{}, false
}

func (s *Server) trackBrowserTicketConnection(socket *gws.Conn) (<-chan struct{}, bool) {
	if socket == nil {
		return nil, false
	}
	raw, _ := socket.Session().Load(browserTicketSessionKey)
	ticketID, _ := raw.(string)
	if ticketID == "" {
		return nil, true
	}
	done := make(chan struct{})
	s.enrollmentMu.Lock()
	s.accessTicketMu.Lock()
	now := s.accessTicketCurrentTime()
	valid := false
	for hash, ticket := range s.accessTickets {
		if !ticket.ExpiresAt.After(now) {
			delete(s.accessTickets, hash)
			continue
		}
		if ticket.ID != ticketID || !strings.HasPrefix(ticket.Subject, browserTicketSubject) {
			continue
		}
		device, managed := s.managedDevices[ticket.DeviceID]
		valid = managed && device.RevokedAt.IsZero() &&
			accessTicketCredentialVersionMatches(ticket.DeviceCredentialVersion, device.CredentialVersion)
		break
	}
	if !valid {
		s.accessTicketMu.Unlock()
		s.enrollmentMu.Unlock()
		return nil, false
	}
	s.browserTicketMu.Lock()
	if s.browserTicketConnections[ticketID] == nil {
		s.browserTicketConnections[ticketID] = make(map[*gws.Conn]chan struct{})
	}
	s.browserTicketConnections[ticketID][socket] = done
	s.browserTicketMu.Unlock()
	s.accessTicketMu.Unlock()
	s.enrollmentMu.Unlock()
	go s.watchBrowserTicketConnection(ticketID, done)
	return done, true
}

func (s *Server) untrackBrowserTicketConnection(socket *gws.Conn) {
	if socket == nil {
		return
	}
	raw, _ := socket.Session().Load(browserTicketSessionKey)
	ticketID, _ := raw.(string)
	if ticketID == "" {
		return
	}
	s.browserTicketMu.Lock()
	connections := s.browserTicketConnections[ticketID]
	done, exists := connections[socket]
	if exists {
		delete(connections, socket)
		close(done)
	}
	if len(connections) == 0 {
		delete(s.browserTicketConnections, ticketID)
	}
	s.browserTicketMu.Unlock()
}

func (s *Server) watchBrowserTicketConnection(ticketID string, done <-chan struct{}) {
	for {
		expiresAt, ok := s.accessTicketExpiration(ticketID)
		if !ok {
			s.closeBrowserTicketConnections(ticketID, "browser access expired")
			return
		}
		delay := expiresAt.Sub(s.accessTicketCurrentTime())
		if delay <= 0 {
			s.closeBrowserTicketConnections(ticketID, "browser access expired")
			return
		}
		timer := time.NewTimer(delay)
		select {
		case <-done:
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

func (s *Server) closeBrowserTicketConnections(ticketID, reason string) {
	s.browserTicketMu.Lock()
	connections := s.browserTicketConnections[ticketID]
	delete(s.browserTicketConnections, ticketID)
	s.browserTicketMu.Unlock()
	for socket, done := range connections {
		close(done)
		_ = socket.WriteClose(4003, []byte(reason))
	}
}

func (s *Server) authorizeBrowserDeviceRequest(client *ClientConn, r *http.Request) bool {
	if client == nil || r == nil {
		return false
	}
	if credential := r.Header.Get("X-RDev-Device-Credential"); credential != "" {
		return s.authorizeDeviceCredential(client, credential)
	}
	password := r.URL.Query().Get("password")
	if strings.HasPrefix(password, accessTicketPrefix) {
		return false
	}
	return s.authorizeDeviceCredential(client, password)
}

func (s *Server) HandleAccessTicketsAPI(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	if r.Method == http.MethodDelete {
		s.handleAccessTicketRevoke(w, r)
		return
	}
	if r.Method == http.MethodPatch {
		s.handleAccessTicketRenew(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input accessTicketCreateRequest
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(input.DeviceID) != input.DeviceID || input.DeviceID == "" {
		http.Error(w, "deviceId is required without surrounding whitespace", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(input.Subject) != input.Subject || input.Subject == "" || len(input.Subject) > 128 {
		http.Error(w, "subject is required and must not exceed 128 bytes", http.StatusBadRequest)
		return
	}
	capabilities, err := normalizeAccessTicketCapabilities(input.Subject, input.Capabilities)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if input.ExpiresInSecond < int64(accessTicketMinLifetime/time.Second) ||
		input.ExpiresInSecond > int64(accessTicketMaxLifetime/time.Second) {
		http.Error(w, "expiresInSeconds must be between 60 and 28800", http.StatusBadRequest)
		return
	}
	lifetime := time.Duration(input.ExpiresInSecond) * time.Second
	client, ok := s.GetClient(input.DeviceID)
	if !ok {
		http.Error(w, "device is not connected", http.StatusNotFound)
		return
	}
	ticketValue, ticketID, err := newAccessTicketValue()
	if err != nil {
		http.Error(w, "ticket generation failed", http.StatusInternalServerError)
		return
	}
	expiresAt := s.accessTicketCurrentTime().Add(lifetime).UTC().Truncate(time.Second)
	hash := sha256.Sum256([]byte(ticketValue))
	s.enrollmentMu.Lock()
	device, managed := s.managedDevices[input.DeviceID]
	if !managed || !device.RevokedAt.IsZero() || !managedDeviceSubjectAllowed(device.OwnerSubject, input.Subject) {
		s.enrollmentMu.Unlock()
		http.Error(w, "device access is not allowed for subject", http.StatusForbidden)
		return
	}
	s.accessTicketMu.Lock()
	if s.accessTickets == nil {
		s.accessTickets = make(map[[32]byte]accessTicket)
	}
	s.accessTickets[hash] = accessTicket{
		ID:                      ticketID,
		DeviceID:                client.ID,
		DeviceCredentialVersion: device.CredentialVersion,
		InstanceID:              client.InstanceID,
		PasswordFingerprint:     passwordFingerprint(client.Password),
		Subject:                 input.Subject,
		Capabilities:            capabilities,
		ExpiresAt:               expiresAt,
	}
	if err = s.persistAccessTicketsLocked(); err != nil {
		delete(s.accessTickets, hash)
		s.accessTicketMu.Unlock()
		s.enrollmentMu.Unlock()
		http.Error(w, "access ticket store write failed", http.StatusInternalServerError)
		return
	}
	s.accessTicketMu.Unlock()
	s.enrollmentMu.Unlock()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(accessTicketCreateResponse{
		Ticket: ticketValue, TicketID: ticketID, DeviceID: input.DeviceID,
		ExpiresAt: expiresAt.Format(time.RFC3339), ExpiresAtMs: expiresAt.UnixMilli(),
	})
}

func (s *Server) handleAccessTicketRenew(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input accessTicketRenewRequest
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	decoded, err := hex.DecodeString(input.TicketID)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != input.TicketID {
		http.Error(w, "ticketId is invalid", http.StatusBadRequest)
		return
	}
	now := s.accessTicketCurrentTime()
	expiresAt := time.UnixMilli(input.ExpiresAtMs).UTC()
	lifetime := expiresAt.Sub(now)
	if input.ExpiresAtMs <= 0 || !expiresAt.Equal(expiresAt.Truncate(time.Second)) ||
		lifetime < accessTicketMinLifetime || lifetime > accessTicketMaxLifetime {
		http.Error(w, "expiresAtMs must be an exact second between 60 and 28800 seconds in the future", http.StatusBadRequest)
		return
	}
	var renewed accessTicket
	changed := false
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	s.accessTicketMu.Lock()
	original := cloneAccessTickets(s.accessTickets)
	for hash, ticket := range s.accessTickets {
		if !ticket.ExpiresAt.After(now) {
			delete(s.accessTickets, hash)
			continue
		}
		if ticket.ID != input.TicketID {
			continue
		}
		device, managed := s.managedDevices[ticket.DeviceID]
		if !managed || !device.RevokedAt.IsZero() ||
			!accessTicketCredentialVersionMatches(ticket.DeviceCredentialVersion, device.CredentialVersion) {
			continue
		}
		if ticket.ExpiresAt.After(expiresAt) {
			expiresAt = ticket.ExpiresAt
		} else {
			ticket.ExpiresAt = expiresAt
			s.accessTickets[hash] = ticket
			changed = true
		}
		renewed = ticket
		break
	}
	if changed {
		if err = s.persistAccessTicketsLocked(); err != nil {
			s.accessTickets = original
			s.accessTicketMu.Unlock()
			http.Error(w, "access ticket store write failed", http.StatusInternalServerError)
			return
		}
	}
	s.accessTicketMu.Unlock()
	if renewed.ID == "" {
		http.Error(w, "ticket was not found or has expired", http.StatusNotFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(accessTicketRenewResponse{
		TicketID: renewed.ID, DeviceID: renewed.DeviceID,
		ExpiresAt: expiresAt.Format(time.RFC3339), ExpiresAtMs: expiresAt.UnixMilli(),
	})
}

func (s *Server) handleAccessTicketRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input accessTicketRevokeRequest
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	decoded, err := hex.DecodeString(input.TicketID)
	if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != input.TicketID {
		http.Error(w, "ticketId is invalid", http.StatusBadRequest)
		return
	}
	s.accessTicketMu.Lock()
	revoked := false
	var revokedHash [sha256.Size]byte
	var revokedTicket accessTicket
	for hash, ticket := range s.accessTickets {
		if ticket.ID == input.TicketID {
			delete(s.accessTickets, hash)
			revokedHash = hash
			revokedTicket = ticket
			revoked = true
			break
		}
	}
	if revoked {
		if err = s.persistAccessTicketsLocked(); err != nil {
			s.accessTickets[revokedHash] = revokedTicket
			s.accessTicketMu.Unlock()
			http.Error(w, "access ticket store write failed", http.StatusInternalServerError)
			return
		}
	}
	s.accessTicketMu.Unlock()
	if revoked {
		s.closeBrowserTicketConnections(input.TicketID, "browser access revoked")
		if s.accessTicketRevoked != nil {
			s.accessTicketRevoked(input.TicketID)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusNoContent)
}

func cloneAccessTickets(tickets map[[sha256.Size]byte]accessTicket) map[[sha256.Size]byte]accessTicket {
	cloned := make(map[[sha256.Size]byte]accessTicket, len(tickets))
	for hash, ticket := range tickets {
		cloned[hash] = ticket
	}
	return cloned
}

func (s *Server) rebindManagedAccessTickets(deviceID, instanceID, fingerprint string) error {
	s.mu.RLock()
	connected := s.clients[deviceID]
	s.mu.RUnlock()
	if connected != nil && connected.InstanceID != instanceID {
		return nil
	}
	if connected != nil {
		return nil
	}
	now := s.accessTicketCurrentTime()
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	return s.rebindManagedAccessTicketsLocked(deviceID, instanceID, fingerprint, now)
}

// rebindManagedAccessTicketsLocked requires enrollmentMu to be held. Registration
// uses it only after the managed-device secret has been checked under that lock.
func (s *Server) rebindManagedAccessTicketsLocked(deviceID, instanceID, fingerprint string, now time.Time) error {
	device, managed := s.managedDevices[deviceID]
	if !managed || !device.RevokedAt.IsZero() {
		return nil
	}
	s.accessTicketMu.Lock()
	defer s.accessTicketMu.Unlock()
	original := cloneAccessTickets(s.accessTickets)
	changed := false
	for hash, ticket := range s.accessTickets {
		if ticket.DeviceID != deviceID ||
			!accessTicketCredentialVersionMatches(ticket.DeviceCredentialVersion, device.CredentialVersion) ||
			!ticket.ExpiresAt.After(now) ||
			!constantTimeEqual(ticket.PasswordFingerprint, fingerprint) || ticket.InstanceID == instanceID {
			continue
		}
		ticket.InstanceID = instanceID
		s.accessTickets[hash] = ticket
		changed = true
	}
	if !changed {
		return nil
	}
	if err := s.persistAccessTicketsLocked(); err != nil {
		s.accessTickets = original
		return err
	}
	return nil
}

func accessTicketCredentialVersionMatches(ticketVersion, deviceVersion uint64) bool {
	if deviceVersion == 0 {
		return false
	}
	return ticketVersion == deviceVersion || (ticketVersion == 0 && deviceVersion == 1)
}

func (s *Server) invalidateAccessTicketConnectionsForDevice(deviceID string) {
	s.accessTicketMu.Lock()
	ticketIDs := make([]string, 0)
	for _, ticket := range s.accessTickets {
		if ticket.DeviceID == deviceID && ticket.ID != "" {
			ticketIDs = append(ticketIDs, ticket.ID)
		}
	}
	s.accessTicketMu.Unlock()
	for _, ticketID := range ticketIDs {
		s.closeBrowserTicketConnections(ticketID, "device authorization changed")
		if s.accessTicketRevoked != nil {
			s.accessTicketRevoked(ticketID)
		}
	}
}

func newAccessTicketValue() (string, string, error) {
	secret := make([]byte, accessTicketSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", "", err
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", err
	}
	value := accessTicketPrefix + base64.RawURLEncoding.EncodeToString(secret)
	if value == accessTicketPrefix {
		return "", "", errors.New("empty access ticket")
	}
	return value, hex.EncodeToString(idBytes), nil
}
