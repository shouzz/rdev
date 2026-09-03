package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	accessTicketPrefix      = "rdvat_"
	browserTicketProtocol   = "rdev-access-ticket."
	browserTicketSubject    = "feidu-browser:"
	accessTicketSecretBytes = 32
	accessTicketMinLifetime = time.Minute
	accessTicketMaxLifetime = 8 * time.Hour
)

type accessTicket struct {
	ID                  string
	DeviceID            string
	InstanceID          string
	PasswordFingerprint string
	Subject             string
	ExpiresAt           time.Time
}

type deviceAuthorization struct {
	DeviceID            string
	InstanceID          string
	PasswordFingerprint string
}

type accessTicketCreateRequest struct {
	DeviceID        string `json:"deviceId"`
	Subject         string `json:"subject"`
	ExpiresInSecond int64  `json:"expiresInSeconds"`
}

type accessTicketCreateResponse struct {
	Ticket      string `json:"ticket"`
	TicketID    string `json:"ticketId"`
	DeviceID    string `json:"deviceId"`
	ExpiresAt   string `json:"expiresAt"`
	ExpiresAtMs int64  `json:"expiresAtMs"`
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

func (s *Server) browserSocketAuthOK(r *http.Request) bool {
	if !s.secureControlEnabled() || r == nil || r.Method != http.MethodGet ||
		!headerContainsToken(r.Header, "Connection", "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	switch r.URL.Path {
	case "/terminal", "/files", "/desktop":
	default:
		return false
	}
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(value, ",") {
			protocol = strings.TrimSpace(protocol)
			if !strings.HasPrefix(protocol, browserTicketProtocol) {
				continue
			}
			value := strings.TrimPrefix(protocol, browserTicketProtocol)
			if s.browserAccessTicketValid(value, r.URL.Query().Get("device")) {
				return true
			}
		}
	}
	return false
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

func (s *Server) browserAccessTicketValid(value, requestedDeviceID string) bool {
	if !strings.HasPrefix(value, accessTicketPrefix) {
		return false
	}
	hash := sha256.Sum256([]byte(value))
	now := s.accessTicketCurrentTime()
	s.accessTicketMu.Lock()
	defer s.accessTicketMu.Unlock()
	for key, ticket := range s.accessTickets {
		if !ticket.ExpiresAt.After(now) {
			delete(s.accessTickets, key)
		}
	}
	ticket, ok := s.accessTickets[hash]
	if !ok || !strings.HasPrefix(ticket.Subject, browserTicketSubject) || !ticket.ExpiresAt.After(now) {
		return false
	}
	return requestedDeviceID == "" || requestedDeviceID == ticket.DeviceID
}

func (s *Server) requiresDeviceCredential(client *ClientConn) bool {
	return s.secureControlEnabled() || (client != nil && client.Password != "")
}

func (s *Server) authorizeDeviceCredential(client *ClientConn, credential string) bool {
	if client == nil {
		return false
	}
	if credential != "" && s.accessTicketValid(client, credential) {
		return true
	}
	if client.Password != "" {
		return constantTimeEqual(client.Password, credential)
	}
	return !s.secureControlEnabled()
}

func (s *Server) accessTicketValid(client *ClientConn, value string) bool {
	if client == nil {
		return false
	}
	if !strings.HasPrefix(value, accessTicketPrefix) {
		return false
	}
	hash := sha256.Sum256([]byte(value))
	now := s.accessTicketCurrentTime()
	s.accessTicketMu.Lock()
	defer s.accessTicketMu.Unlock()
	for key, ticket := range s.accessTickets {
		if !ticket.ExpiresAt.After(now) {
			delete(s.accessTickets, key)
		}
	}
	ticket, ok := s.accessTickets[hash]
	return ok && ticket.DeviceID == client.ID &&
		ticket.InstanceID == client.InstanceID &&
		constantTimeEqual(ticket.PasswordFingerprint, passwordFingerprint(client.Password)) &&
		ticket.ExpiresAt.After(now)
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

func (s *Server) accessTicketCurrentTime() time.Time {
	if s.accessTicketNow != nil {
		return s.accessTicketNow()
	}
	return time.Now()
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
	s.accessTicketMu.Lock()
	if s.accessTickets == nil {
		s.accessTickets = make(map[[32]byte]accessTicket)
	}
	s.accessTickets[hash] = accessTicket{
		ID:                  ticketID,
		DeviceID:            client.ID,
		InstanceID:          client.InstanceID,
		PasswordFingerprint: passwordFingerprint(client.Password),
		Subject:             input.Subject,
		ExpiresAt:           expiresAt,
	}
	s.accessTicketMu.Unlock()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(accessTicketCreateResponse{
		Ticket: ticketValue, TicketID: ticketID, DeviceID: input.DeviceID,
		ExpiresAt: expiresAt.Format(time.RFC3339), ExpiresAtMs: expiresAt.UnixMilli(),
	})
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
