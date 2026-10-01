package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"rdev/internal/protocol"
)

func TestDeviceActionsAcrossAuthenticatedTransports(t *testing.T) {
	for _, transport := range []string{"ws", "tcp", "kcp"} {
		t.Run(transport, func(t *testing.T) {
			srv := configuredManagedRegistrationServer(t, filepath.Join(t.TempDir(), "registry.json"))
			enrollHTTP := managedRegistrationHTTPServer(srv)
			defer enrollHTTP.Close()
			creds := enrollManagedRegistrationDevice(t, enrollHTTP.URL, "owner", "exact")
			endpoint, closeEndpoint := managedRegistrationEndpoint(t, srv, enrollHTTP, transport)
			defer closeEndpoint()
			c := NewClient(endpoint, creds.DeviceID, "", "")
			c.SetDeviceSecret(creds.DeviceSecret)
			var calls atomic.Int32
			after := make(chan struct{}, 1)
			c.SetDeviceActionHandler(func(context.Context, string, bool) (DeviceActionOutcome, error) {
				calls.Add(1)
				return DeviceActionOutcome{State: "up_to_date", After: func() error { after <- struct{}{}; return nil }}, nil
			})
			if err := c.connect(); err != nil {
				t.Fatal(err)
			}
			defer closeManagedRegistrationClient(c)
			control := httptest.NewServer(http.HandlerFunc(srv.HandleManagedDeviceLifecycleAPI))
			defer control.Close()
			request := func(method, suffix, body string) map[string]any {
				t.Helper()
				r, _ := http.NewRequest(method, control.URL+"/api/control/devices/exact"+suffix, strings.NewReader(body))
				r.Header.Set("X-RDev-Control-Token", managedRegistrationControlToken)
				resp, err := http.DefaultClient.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					t.Fatalf("management status: %d", resp.StatusCode)
				}
				var result map[string]any
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			request("PATCH", "/name", `{"subject":"owner","displayName":"机房"}`)
			body := `{"subject":"owner","instanceId":"` + c.instanceID + `","requestId":"00000000000000000000000000000001","action":"upgrade"}`
			request("POST", "/actions", body)
			select {
			case <-after:
			case <-time.After(5 * time.Second):
				t.Fatal("client never handled action")
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				result := request("GET", "/actions?subject=owner&requestId=00000000000000000000000000000001", "")
				if result["state"] == "up_to_date" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("server never received client result")
				}
				time.Sleep(10 * time.Millisecond)
			}
			request("POST", "/actions", body)
			if calls.Load() != 1 || c.ClientID() != "exact" {
				t.Fatal("replayed action or changed stable device ID")
			}
		})
	}
}

func TestDeviceActionClientValidationAndSanitizedFailure(t *testing.T) {
	c := NewClient("ws://localhost", "exact", "", "")
	c.deviceSecret, c.registered = "test-secret", true
	tr := &cloudTransferMessageTransport{}
	c.transport = tr
	done := make(chan struct{})
	var calls atomic.Int32
	c.SetDeviceActionHandler(func(context.Context, string, bool) (DeviceActionOutcome, error) {
		calls.Add(1)
		close(done)
		return DeviceActionOutcome{}, errors.New("private credential-bearing URL")
	})
	msg := &protocol.Message{Type: protocol.MsgDeviceAction, ClientID: "wrong", InstanceID: c.instanceID,
		RequestID: "00000000000000000000000000000001", Action: "upgrade"}
	c.handleDeviceAction(msg)
	msg.ClientID, msg.InstanceID = "exact", "old-instance"
	c.handleDeviceAction(msg)
	if calls.Load() != 0 || len(tr.decoded(t)) != 0 {
		t.Fatal("mismatched device or instance executed")
	}
	msg.InstanceID = c.instanceID
	c.handleDeviceAction(msg)
	<-done
	deadline := time.Now().Add(time.Second)
	for {
		messages := tr.decoded(t)
		if len(messages) > 0 {
			if len(messages) != 1 || messages[0].ActionState != "failed" || messages[0].Error != "" {
				t.Fatal("failure did not use sanitized protocol response")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing failure")
		}
		time.Sleep(time.Millisecond)
	}
	c.handleDeviceAction(msg)
	if calls.Load() != 1 {
		t.Fatal("request replayed")
	}
}
