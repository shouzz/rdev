package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"rdev/internal/protocol"
)

type cloudTransferCaptureTransport struct {
	message []byte
}

func (t *cloudTransferCaptureTransport) WriteJSON(data []byte) error {
	t.message = append([]byte(nil), data...)
	return nil
}
func (*cloudTransferCaptureTransport) WriteBinary([]byte) error { return nil }
func (*cloudTransferCaptureTransport) WritePing([]byte) error   { return nil }
func (*cloudTransferCaptureTransport) Close(string) error       { return nil }
func (*cloudTransferCaptureTransport) RemoteAddr() string       { return "127.0.0.1:12345" }

func TestCloudTransferDispatchDeliversSecretOnlyToExactDevice(t *testing.T) {
	srv := NewServer()
	srv.ControlToken = "test-control-token-with-at-least-32-bytes"
	transport := &cloudTransferCaptureTransport{}
	srv.managedDevices["device-one"] = managedDevice{ID: "device-one", OwnerSubject: "feidu-user:42"}
	srv.clients["device-one"] = &ClientConn{ID: "device-one", InstanceID: "instance-one", Transport: transport}
	token := "fdtx_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	body := []byte(`{"deviceId":"device-one","subject":"feidu-user:42","transferId":"12345678-1234-1234-1234-1234567890ab","bootstrapUrl":"https://pan.feidu.fit/device/v1/rdev-transfers/12345678-1234-1234-1234-1234567890ab","transferToken":"` + token + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/control/cloud-transfers", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", srv.ControlToken)
	response := httptest.NewRecorder()

	srv.HandleCloudTransferDispatchAPI(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), token) {
		t.Fatal("dispatch response exposed the transfer token")
	}
	message, err := protocol.Decode(transport.message)
	if err != nil {
		t.Fatalf("decode dispatched message: %v", err)
	}
	if message.Type != protocol.MsgCloudTransferStart || message.TransferID != "12345678-1234-1234-1234-1234567890ab" ||
		message.BootstrapURL != "https://pan.feidu.fit/device/v1/rdev-transfers/12345678-1234-1234-1234-1234567890ab" || message.TransferToken != token {
		t.Fatalf("dispatched message is inconsistent: %#v", message)
	}
}

func TestCloudTransferDispatchRejectsDifferentManagedDeviceOwner(t *testing.T) {
	srv := NewServer()
	srv.ControlToken = "test-control-token-with-at-least-32-bytes"
	transport := &cloudTransferCaptureTransport{}
	srv.managedDevices["device-one"] = managedDevice{ID: "device-one", OwnerSubject: "feidu-user:7"}
	srv.clients["device-one"] = &ClientConn{ID: "device-one", InstanceID: "instance-one", Transport: transport}
	token := "fdtx_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	body := []byte(`{"deviceId":"device-one","subject":"feidu-user:42","transferId":"12345678-1234-1234-1234-1234567890ab","bootstrapUrl":"https://pan.feidu.fit/device/v1/rdev-transfers/12345678-1234-1234-1234-1234567890ab","transferToken":"` + token + `"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/control/cloud-transfers", bytes.NewReader(body))
	request.Header.Set("X-RDev-Control-Token", srv.ControlToken)
	response := httptest.NewRecorder()

	srv.HandleCloudTransferDispatchAPI(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if len(transport.message) != 0 {
		t.Fatal("cloud transfer secret was delivered to a device owned by another subject")
	}
}

func TestCloudTransferDispatchRejectsUnsafeOrUnauthorizedRequests(t *testing.T) {
	token := "fdtx_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	validBody := `{"deviceId":"device-one","subject":"feidu-user:42","transferId":"12345678-1234-1234-1234-1234567890ab","bootstrapUrl":"https://pan.feidu.fit/device/v1/rdev-transfers/12345678-1234-1234-1234-1234567890ab","transferToken":"` + token + `"}`
	tests := []struct {
		name         string
		controlToken string
		headerToken  string
		body         string
		wantStatus   int
	}{
		{name: "control disabled", body: validBody, wantStatus: http.StatusServiceUnavailable},
		{name: "wrong control token", controlToken: "control-secret", headerToken: "wrong", body: validBody, wantStatus: http.StatusUnauthorized},
		{name: "external plaintext URL", controlToken: "control-secret", headerToken: "control-secret", body: strings.Replace(validBody, "https://pan.feidu.fit", "http://pan.feidu.fit", 1), wantStatus: http.StatusBadRequest},
		{name: "trailing JSON", controlToken: "control-secret", headerToken: "control-secret", body: validBody + `{}`, wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := NewServer()
			srv.ControlToken = test.controlToken
			srv.clients["device-one"] = &ClientConn{ID: "device-one", InstanceID: "instance-one", Transport: &cloudTransferCaptureTransport{}}
			request := httptest.NewRequest(http.MethodPost, "/api/control/cloud-transfers", strings.NewReader(test.body))
			request.Header.Set("X-RDev-Control-Token", test.headerToken)
			response := httptest.NewRecorder()
			srv.HandleCloudTransferDispatchAPI(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}

func TestCloudTransferDispatchResponseSchema(t *testing.T) {
	response := cloudTransferDispatchResponse{Accepted: true, DeviceID: "device", TransferID: "12345678-1234-1234-1234-1234567890ab"}
	data, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"transferToken", "bootstrapUrl", "subject"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("dispatch response contains forbidden field %q", forbidden)
		}
	}
}
