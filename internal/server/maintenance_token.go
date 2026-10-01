package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/lxzan/gws"
)

const (
	maintenanceTokenPrefix   = "fdpat_"
	maintenanceCapabilitySSH = "ssh"
	maintenanceSessionKey    = "maintenanceAuthorization"
)

// A maintenance grant belongs to a stable device. Connection authorizations
// separately bind its current instance, so reconnecting never rotates the token.
type maintenanceTokenGrant struct {
	TokenID      string   `json:"tokenId"`
	TokenHash    string   `json:"tokenHash"`
	Subject      string   `json:"subject"`
	Generation   uint64   `json:"generation"`
	Capabilities []string `json:"capabilities"`
	Revoked      bool     `json:"revoked"`
}

type maintenanceTokenStatus struct {
	DeviceID     string   `json:"deviceId"`
	TokenID      string   `json:"tokenId"`
	Subject      string   `json:"subject"`
	Generation   uint64   `json:"generation"`
	Capabilities []string `json:"capabilities"`
	Revoked      bool     `json:"revoked"`
	Persisted    bool     `json:"persisted"`
}

var errMaintenanceConflict = errors.New("maintenance token generation conflicts with stored state")

func validMaintenanceTokenID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == compact
}

func normalizeMaintenanceGrant(grant *maintenanceTokenGrant) error {
	if grant == nil || !validMaintenanceTokenID(grant.TokenID) || grant.Generation == 0 {
		return errors.New("invalid maintenance token identity or generation")
	}
	hash, err := hex.DecodeString(grant.TokenHash)
	if err != nil || len(hash) != sha256.Size || hex.EncodeToString(hash) != grant.TokenHash {
		return errors.New("invalid maintenance token digest")
	}
	const prefix = "feidu-user:"
	if !strings.HasPrefix(grant.Subject, prefix) {
		return errors.New("invalid maintenance subject")
	}
	user := strings.TrimPrefix(grant.Subject, prefix)
	id, err := strconv.ParseUint(user, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != user {
		return errors.New("invalid maintenance subject")
	}
	if len(grant.Capabilities) == 0 || len(grant.Capabilities) > 5 {
		return errors.New("invalid maintenance capabilities")
	}
	grant.Capabilities = slices.Clone(grant.Capabilities)
	sort.Strings(grant.Capabilities)
	for i, capability := range grant.Capabilities {
		switch capability {
		case maintenanceCapabilitySSH, browserCapabilityTerminal, browserCapabilityFiles, browserCapabilityDesktop, browserCapabilityPeripherals:
		default:
			return errors.New("invalid maintenance capability")
		}
		if i > 0 && grant.Capabilities[i-1] == capability {
			return errors.New("duplicate maintenance capability")
		}
	}
	return nil
}

func (grant maintenanceTokenGrant) same(other maintenanceTokenGrant) bool {
	return grant.TokenID == other.TokenID && grant.TokenHash == other.TokenHash &&
		grant.Subject == other.Subject && grant.Generation == other.Generation &&
		grant.Revoked == other.Revoked && slices.Equal(grant.Capabilities, other.Capabilities)
}

func (grant maintenanceTokenGrant) status(deviceID string) maintenanceTokenStatus {
	return maintenanceTokenStatus{DeviceID: deviceID, TokenID: grant.TokenID, Subject: grant.Subject,
		Generation: grant.Generation, Capabilities: slices.Clone(grant.Capabilities), Revoked: grant.Revoked, Persisted: true}
}

func (grant maintenanceTokenGrant) connectionKey() string {
	return "maintenance:" + grant.TokenID + ":" + strconv.FormatUint(grant.Generation, 10)
}

func (grant maintenanceTokenGrant) permits(capability string) bool {
	return !grant.Revoked && slices.Contains(grant.Capabilities, capability)
}

// Called only after the existing control-plane authentication succeeds.
func (s *Server) handleMaintenanceToken(w http.ResponseWriter, r *http.Request) {
	const prefix, suffix = "/api/control/devices/", "/maintenance-token"
	escaped := strings.TrimSuffix(strings.TrimPrefix(r.URL.EscapedPath(), prefix), suffix)
	deviceID, err := url.PathUnescape(escaped)
	if err != nil || escaped == "" || strings.Contains(escaped, "/") || validateManagedDeviceID(deviceID) != nil {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		s.enrollmentMu.Lock()
		device, exists := s.managedDevices[deviceID]
		var response maintenanceTokenStatus
		if exists && device.MaintenanceToken != nil {
			response = device.MaintenanceToken.status(deviceID)
		}
		s.enrollmentMu.Unlock()
		if response.TokenID == "" {
			http.NotFound(w, r)
			return
		}
		writeEnrollmentJSON(w, response)
		return
	}
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var grant maintenanceTokenGrant
	if !decodeEnrollmentJSON(w, r, &grant) {
		return
	}
	if normalizeMaintenanceGrant(&grant) != nil {
		http.Error(w, "invalid maintenance token request", http.StatusBadRequest)
		return
	}
	if err = s.installMaintenanceToken(deviceID, grant); err != nil {
		switch {
		case err == os.ErrNotExist:
			http.NotFound(w, r)
		case errors.Is(err, errMaintenanceConflict), errors.Is(err, errManagedDeviceRevoked):
			http.Error(w, "maintenance token conflicts with stored device state", http.StatusConflict)
		default:
			http.Error(w, "maintenance token persistence failed", http.StatusInternalServerError)
		}
		return
	}
	writeEnrollmentJSON(w, grant.status(deviceID))
}

func (s *Server) installMaintenanceToken(deviceID string, grant maintenanceTokenGrant) error {
	s.enrollmentMu.Lock()
	device, exists := s.managedDevices[deviceID]
	if !exists {
		s.enrollmentMu.Unlock()
		return os.ErrNotExist
	}
	if !device.RevokedAt.IsZero() && !grant.Revoked {
		s.enrollmentMu.Unlock()
		return errManagedDeviceRevoked
	}
	previous := device.MaintenanceToken
	if previous != nil && previous.Subject != grant.Subject {
		s.enrollmentMu.Unlock()
		return errMaintenanceConflict
	}
	if previous != nil && grant.Generation <= previous.Generation {
		s.enrollmentMu.Unlock()
		if grant.same(*previous) {
			return nil
		}
		return errMaintenanceConflict
	}
	for id, other := range s.managedDevices {
		if id != deviceID && other.MaintenanceToken != nil &&
			(other.MaintenanceToken.TokenID == grant.TokenID || other.MaintenanceToken.TokenHash == grant.TokenHash) {
			s.enrollmentMu.Unlock()
			return errMaintenanceConflict
		}
	}
	original := device
	device.MaintenanceToken = &grant
	s.managedDevices[deviceID] = device
	if err := s.persistManagedDeviceRegistryLocked(); err != nil {
		s.managedDevices[deviceID] = original
		s.enrollmentMu.Unlock()
		return err
	}
	s.enrollmentMu.Unlock()
	if previous != nil {
		key := previous.connectionKey()
		s.closeBrowserTicketConnections(key, "device authorization changed")
		if s.accessTicketRevoked != nil {
			s.accessTicketRevoked(key)
		}
	}
	return nil
}

func maintenanceCredentialHash(value string) (string, bool) {
	if !strings.HasPrefix(value, maintenanceTokenPrefix) {
		return "", false
	}
	encoded := strings.TrimPrefix(value, maintenanceTokenPrefix)
	secret, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != encoded {
		return "", false
	}
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:]), true
}

func (s *Server) maintenanceGrantForCredential(value, requestedDeviceID, capability string) (string, maintenanceTokenGrant, bool) {
	hash, ok := maintenanceCredentialHash(value)
	if !ok {
		return "", maintenanceTokenGrant{}, false
	}
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	for id, device := range s.managedDevices {
		if requestedDeviceID != "" && requestedDeviceID != id {
			continue
		}
		grant := device.MaintenanceToken
		if device.RevokedAt.IsZero() && grant != nil && grant.permits(capability) && constantTimeEqual(grant.TokenHash, hash) {
			return id, *grant, true
		}
	}
	return "", maintenanceTokenGrant{}, false
}

func (s *Server) maintenanceAuthorization(client *ClientConn, value, capability string) (deviceAuthorization, bool) {
	if client == nil {
		return deviceAuthorization{}, false
	}
	_, grant, ok := s.maintenanceGrantForCredential(value, client.ID, capability)
	if !ok {
		return deviceAuthorization{}, false
	}
	auth := deviceAuthorizationFor(client)
	auth.MaintenanceTokenID, auth.MaintenanceGeneration, auth.MaintenanceCapability = grant.TokenID, grant.Generation, capability
	return auth, true
}

// Caller holds enrollmentMu. Token validity deliberately has no time condition.
func (s *Server) maintenanceAuthorizationValidLocked(auth deviceAuthorization) bool {
	device, exists := s.managedDevices[auth.DeviceID]
	grant := device.MaintenanceToken
	return exists && device.RevokedAt.IsZero() && grant != nil && grant.TokenID == auth.MaintenanceTokenID &&
		grant.Generation == auth.MaintenanceGeneration && grant.permits(auth.MaintenanceCapability)
}

func (s *Server) maintenanceBrowserAuthorization(r *http.Request) (deviceAuthorization, string, bool) {
	if r == nil {
		return deviceAuthorization{}, "", false
	}
	capability, allowed := browserCapabilityByPath[r.URL.Path]
	if !allowed {
		return deviceAuthorization{}, "", false
	}
	for _, value := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, protocol := range strings.Split(value, ",") {
			protocol = strings.TrimSpace(protocol)
			if !strings.HasPrefix(protocol, browserTicketProtocol) {
				continue
			}
			deviceID, grant, ok := s.maintenanceGrantForCredential(strings.TrimPrefix(protocol, browserTicketProtocol), r.URL.Query().Get("device"), capability)
			if ok {
				return deviceAuthorization{DeviceID: deviceID, MaintenanceTokenID: grant.TokenID,
					MaintenanceGeneration: grant.Generation, MaintenanceCapability: capability}, grant.Subject, true
			}
		}
	}
	return deviceAuthorization{}, "", false
}

func (auth deviceAuthorization) connectionKey() string {
	if auth.MaintenanceTokenID != "" {
		return (maintenanceTokenGrant{TokenID: auth.MaintenanceTokenID, Generation: auth.MaintenanceGeneration}).connectionKey()
	}
	return auth.TicketID
}

func (s *Server) trackMaintenanceBrowserConnection(socket *gws.Conn, auth deviceAuthorization) (<-chan struct{}, bool) {
	s.enrollmentMu.Lock()
	defer s.enrollmentMu.Unlock()
	if !s.maintenanceAuthorizationValidLocked(auth) {
		return nil, false
	}
	key := auth.connectionKey()
	done := make(chan struct{})
	s.browserTicketMu.Lock()
	if s.browserTicketConnections == nil {
		s.browserTicketConnections = make(map[string]map[*gws.Conn]chan struct{})
	}
	if s.browserTicketConnections[key] == nil {
		s.browserTicketConnections[key] = make(map[*gws.Conn]chan struct{})
	}
	s.browserTicketConnections[key][socket] = done
	s.browserTicketMu.Unlock()
	return done, true
}

func (s *Server) authorizeBrowserOrDeviceCredentialBinding(socket *gws.Conn, client *ClientConn, credential, capability string) (deviceAuthorization, bool) {
	if strings.HasPrefix(credential, maintenanceTokenPrefix) {
		auth, ok := s.maintenanceAuthorization(client, credential, capability)
		if ok && socket != nil {
			raw, exists := socket.Session().Load(maintenanceSessionKey)
			bound, valid := raw.(deviceAuthorization)
			// The handshake installs the revocation tracker. Mixing a legacy
			// handshake with fixed-token message auth would leave it untracked.
			ok = exists && valid && auth.DeviceID == bound.DeviceID && auth.connectionKey() == bound.connectionKey()
		}
		return auth, ok
	}
	if socket != nil {
		if _, bound := socket.Session().Load(maintenanceSessionKey); bound {
			return deviceAuthorization{}, false
		}
	}
	if auth, ok := s.authorizeBrowserDeviceCredentialBinding(client, credential, capability); ok {
		return auth, true
	}
	return s.authorizeDeviceCredentialBinding(client, credential)
}

func (s *Server) closeDeviceMaintenanceConnections(deviceID, reason string) {
	s.enrollmentMu.Lock()
	device := s.managedDevices[deviceID]
	grant := device.MaintenanceToken
	s.enrollmentMu.Unlock()
	if grant != nil {
		key := grant.connectionKey()
		s.closeBrowserTicketConnections(key, reason)
		if s.accessTicketRevoked != nil {
			s.accessTicketRevoked(key)
		}
	}
}
