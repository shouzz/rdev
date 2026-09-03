package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rdev/internal/server"
)

const managedRegistrationControlToken = "test-control-token-with-at-least-32-bytes"

type managedRegistrationCredentials struct {
	DeviceID     string `json:"deviceId"`
	DeviceSecret string `json:"deviceSecret"`
}

type managedEnrollmentResponse struct {
	Code string `json:"code"`
}

func TestManagedRegistrationAcrossTransportsAndRestart(t *testing.T) {
	for _, transport := range []string{"ws", "tcp", "kcp"} {
		t.Run(transport, func(t *testing.T) {
			registryPath := filepath.Join(t.TempDir(), "managed_devices.json")
			firstServer := configuredManagedRegistrationServer(t, registryPath)
			firstHTTP := managedRegistrationHTTPServer(firstServer)
			credentials := enrollManagedRegistrationDevice(t, firstHTTP.URL, "feidu-user:42", "workstation")

			firstEndpoint, closeFirstTransport := managedRegistrationEndpoint(t, firstServer, firstHTTP, transport)
			badClient := NewClient(firstEndpoint, credentials.DeviceID, "ssh-password", "")
			badClient.SetDeviceSecret("rdevd_invalid")
			badClient.registerWait = 2 * time.Second
			if err := badClient.connect(); err == nil || !strings.Contains(err.Error(), "managed device credential rejected") {
				t.Fatalf("wrong device secret error = %v", err)
			}

			firstClient := connectManagedRegistrationClient(t, firstEndpoint, credentials)
			assertManagedRegistration(t, firstServer, credentials.DeviceID, "feidu-user:42")
			closeManagedRegistrationClient(firstClient)
			closeFirstTransport()
			firstHTTP.Close()

			restartedServer := configuredManagedRegistrationServer(t, registryPath)
			restartedHTTP := managedRegistrationHTTPServer(restartedServer)
			restartedEndpoint, closeRestartedTransport := managedRegistrationEndpoint(t, restartedServer, restartedHTTP, transport)
			restartedClient := connectManagedRegistrationClient(t, restartedEndpoint, credentials)
			assertManagedRegistration(t, restartedServer, credentials.DeviceID, "feidu-user:42")
			if restartedClient.ClientID() != credentials.DeviceID {
				t.Fatalf("client ID after restart = %q, want %q", restartedClient.ClientID(), credentials.DeviceID)
			}
			closeManagedRegistrationClient(restartedClient)
			closeRestartedTransport()
			restartedHTTP.Close()
		})
	}
}

func configuredManagedRegistrationServer(t *testing.T, registryPath string) *server.Server {
	t.Helper()
	srv := server.NewServer()
	srv.ControlToken = managedRegistrationControlToken
	if err := srv.ConfigureEnrollmentStore(registryPath, "https://rdev.example.com"); err != nil {
		t.Fatalf("configure enrollment store: %v", err)
	}
	return srv
}

func managedRegistrationHTTPServer(srv *server.Server) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", srv.HandleWS)
	mux.HandleFunc("/api/control/enrollments", srv.HandleEnrollmentCreateAPI)
	mux.HandleFunc("/api/enrollments/redeem", srv.HandleEnrollmentRedeemAPI)
	return httptest.NewServer(mux)
}

func enrollManagedRegistrationDevice(t *testing.T, baseURL, subject, requestedDeviceID string) managedRegistrationCredentials {
	t.Helper()
	createBody, err := json.Marshal(map[string]any{"subject": subject, "expiresInSeconds": 300})
	if err != nil {
		t.Fatal(err)
	}
	createRequest, err := http.NewRequest(http.MethodPost, baseURL+"/api/control/enrollments", bytes.NewReader(createBody))
	if err != nil {
		t.Fatal(err)
	}
	createRequest.Header.Set("Content-Type", "application/json")
	createRequest.Header.Set("X-RDev-Control-Token", managedRegistrationControlToken)
	createResponse, err := http.DefaultClient.Do(createRequest)
	if err != nil {
		t.Fatalf("create enrollment: %v", err)
	}
	defer createResponse.Body.Close()
	if createResponse.StatusCode != http.StatusOK {
		t.Fatalf("create enrollment status = %d", createResponse.StatusCode)
	}
	var enrollment managedEnrollmentResponse
	if err = json.NewDecoder(createResponse.Body).Decode(&enrollment); err != nil {
		t.Fatalf("decode enrollment: %v", err)
	}
	if enrollment.Code == "" {
		t.Fatal("enrollment response did not contain code")
	}

	redeemBody, err := json.Marshal(map[string]string{"code": enrollment.Code, "deviceId": requestedDeviceID})
	if err != nil {
		t.Fatal(err)
	}
	redeemResponse, err := http.Post(baseURL+"/api/enrollments/redeem", "application/json", bytes.NewReader(redeemBody))
	if err != nil {
		t.Fatalf("redeem enrollment: %v", err)
	}
	defer redeemResponse.Body.Close()
	if redeemResponse.StatusCode != http.StatusOK {
		t.Fatalf("redeem enrollment status = %d", redeemResponse.StatusCode)
	}
	var credentials managedRegistrationCredentials
	if err = json.NewDecoder(redeemResponse.Body).Decode(&credentials); err != nil {
		t.Fatalf("decode enrollment credentials: %v", err)
	}
	if credentials.DeviceID != requestedDeviceID || credentials.DeviceSecret == "" {
		t.Fatalf("redeemed device identity is invalid: deviceId=%q secretPresent=%v", credentials.DeviceID, credentials.DeviceSecret != "")
	}
	return credentials
}

func managedRegistrationEndpoint(t *testing.T, srv *server.Server, httpServer *httptest.Server, transport string) (string, func()) {
	t.Helper()
	switch transport {
	case "ws":
		return "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/ws", func() {}
	case "tcp":
		listener, err := srv.ServeTCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("start TCP transport: %v", err)
		}
		return "tcp://" + listener.Addr().String(), func() { _ = listener.Close() }
	case "kcp":
		listener, err := srv.ServeKCP("127.0.0.1:0")
		if err != nil {
			t.Fatalf("start KCP transport: %v", err)
		}
		return "kcp://" + listener.Addr().String(), func() { _ = listener.Close() }
	default:
		t.Fatalf("unsupported test transport %q", transport)
		return "", func() {}
	}
}

func connectManagedRegistrationClient(t *testing.T, endpoint string, credentials managedRegistrationCredentials) *Client {
	t.Helper()
	connected := NewClient(endpoint, credentials.DeviceID, "ssh-password", "")
	connected.SetDeviceSecret(credentials.DeviceSecret)
	connected.registerWait = 3 * time.Second
	if err := connected.connect(); err != nil {
		t.Fatalf("connect managed client to %s: %v", endpoint, err)
	}
	return connected
}

func assertManagedRegistration(t *testing.T, srv *server.Server, deviceID, ownerSubject string) {
	t.Helper()
	connected, ok := srv.GetClient(deviceID)
	if !ok {
		t.Fatalf("server does not contain connected device %q", deviceID)
	}
	if connected.ID != deviceID || connected.RequestedID != deviceID || connected.OwnerSubject != ownerSubject {
		t.Fatalf("connected identity = id:%q requested:%q owner:%q", connected.ID, connected.RequestedID, connected.OwnerSubject)
	}
}

func closeManagedRegistrationClient(connected *Client) {
	connected.mu.Lock()
	transport := connected.transport
	connected.mu.Unlock()
	if transport != nil {
		_ = transport.Close(fmt.Sprintf("test complete for %s", connected.ClientID()))
	}
}
