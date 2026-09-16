package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaintenanceTokenRegressionStaleSSHConnectionPreservesReconnectedSession(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
	deviceID := maintenanceTestDevice(t, s, "reconnect-isolation")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, deviceID, grant)
	sshServer := &SSHServer{srv: s}
	s.accessTicketRevoked = sshServer.closeTicketConnections
	s.clients[deviceID] = &ClientConn{ID: deviceID, InstanceID: "before-reconnect"}
	stale := newSSHAuthTestContext(deviceID)
	if !sshServer.handlePassword(stale, token) {
		t.Fatal("initial SSH authentication failed")
	}
	s.clients[deviceID] = &ClientConn{ID: deviceID, InstanceID: "after-reconnect"}
	fresh := newSSHAuthTestContext(deviceID)
	if !sshServer.handlePassword(fresh, token) {
		t.Fatal("same token did not authenticate after device reconnect")
	}
	freshAuth := fresh.Value(sshDeviceAuthorizationKey).(deviceAuthorization)
	connection := &sshTestCloser{}
	if !sshServer.trackTicketConnection(freshAuth.connectionKey(), "fresh-connection", connection) {
		t.Fatal("could not track the new connection")
	}
	// A stale ControlMaster opening another channel must fail without closing
	// a different connection authenticated after the device reconnected.
	if _, ok := sshServer.authorizedTicketConnection(stale); ok {
		t.Fatal("stale instance authorization was accepted")
	}
	if connection.closeCount != 0 {
		t.Fatal("stale SSH context closed the healthy reconnected session")
	}
	if _, ok := sshServer.authorizedTicketConnection(fresh); !ok {
		t.Fatal("healthy reconnected session lost its authorization")
	}
	// The isolation fix must retain explicit revocation of the entire grant.
	grant.Generation++
	grant.Revoked = true
	maintenanceTestInstall(t, s, deviceID, grant)
	if connection.closeCount != 1 {
		t.Fatal("explicit grant revocation did not close the new connection")
	}
}

func TestMaintenanceTokenRegressionRejectsLegacyHandshakeWithFixedMessage(t *testing.T) {
	for _, capability := range []string{"terminal", "files", "desktop"} {
		t.Run(capability, func(t *testing.T) {
			s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "managed.json"))
			client, _ := maintenanceOnlineClient(t, s, "mixed-handshake")
			token, grant := maintenanceTestRandom(t)
			maintenanceTestInstall(t, s, client.ID, grant)
			body, err := json.Marshal(accessTicketCreateRequest{
				DeviceID: client.ID, Subject: "feidu-browser:42", ExpiresInSecond: 60,
				Capabilities: []string{capability},
			})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/control/access-tickets", bytes.NewReader(body))
			request.Header.Set("X-RDev-Control-Token", s.ControlToken)
			response := httptest.NewRecorder()
			s.HandleAccessTicketsAPI(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("legacy ticket creation status = %d", response.Code)
			}
			var ticket accessTicketCreateResponse
			if err = json.Unmarshal(response.Body.Bytes(), &ticket); err != nil {
				t.Fatal(err)
			}
			handler := s.HandleTerminalWS
			var auth any = terminalMsg{Op: "auth", Password: token}
			switch capability {
			case "files":
				handler = s.HandleFilesWS
				auth = fileMsg{Op: "auth", DeviceID: client.ID, Password: token}
			case "desktop":
				handler = s.HandleDesktopWS
				auth = desktopMsg{Op: "auth", Pass: token}
			}
			httpServer := httptest.NewServer(http.HandlerFunc(handler))
			defer httpServer.Close()
			browser, capture := maintenanceBrowserConnect(t, "ws"+strings.TrimPrefix(httpServer.URL, "http")+"/"+capability+"?device="+url.QueryEscape(client.ID), ticket.Ticket)
			if capability != "files" {
				maintenanceBrowserWait(t, capture, "auth")
			}
			maintenanceBrowserWrite(t, browser, auth)
			maintenanceBrowserWait(t, capture, "auth_fail")
		})
	}
}
