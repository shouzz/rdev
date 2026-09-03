package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrollmentHTTPBase(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "https://rdev.example.com", want: "https://rdev.example.com"},
		{input: "wss://rdev.example.com/ws", want: "https://rdev.example.com"},
		{input: "http://127.0.0.1:8080", want: "http://127.0.0.1:8080"},
		{input: "ws://127.0.0.1:8080/ws", want: "http://127.0.0.1:8080"},
	}
	for _, test := range tests {
		got, err := enrollmentHTTPBase(test.input)
		if err != nil || got != test.want {
			t.Fatalf("enrollmentHTTPBase(%q) = %q, %v; want %q", test.input, got, err, test.want)
		}
	}
	if _, err := enrollmentHTTPBase("tcp://rdev.example.com:8081"); err == nil {
		t.Fatal("TCP-only enrollment URL was accepted")
	}
}

func TestRedeemEnrollmentUsesExactResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/enrollments/redeem" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		var input map[string]string
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input["code"] != "one-time" || input["deviceId"] != "workstation" {
			t.Fatalf("request body = %#v", input)
		}
		_ = json.NewEncoder(w).Encode(enrollmentResult{DeviceID: "workstation", DeviceSecret: "device-secret", ServerURL: "https://rdev.example.com"})
	}))
	defer server.Close()

	result, err := redeemEnrollment(server.URL, "one-time", "workstation")
	if err != nil {
		t.Fatal(err)
	}
	if result.DeviceID != "workstation" || result.DeviceSecret != "device-secret" || result.ServerURL != "https://rdev.example.com" {
		t.Fatalf("result = %#v", result)
	}
}

func TestProtectedIdentityRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.bin")
	identity := clientIdentity{
		Schema: clientIdentitySchema, ServerURL: "https://rdev.example.com",
		ClientID: "workstation", DeviceID: "workstation", DeviceSecret: "device-secret",
	}
	if err := saveClientIdentity(path, identity); err != nil {
		t.Fatal(err)
	}
	got, found, err := loadClientIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !found || got != identity {
		t.Fatal("protected identity did not round-trip")
	}
}

func TestReadEnrollmentCodeRequiresOneExactLine(t *testing.T) {
	got, err := readEnrollmentCode(strings.NewReader("rdeve_value\r\n"))
	if err != nil || got != "rdeve_value" {
		t.Fatalf("readEnrollmentCode = %q, %v", got, err)
	}
	for _, input := range []string{"", " rdeve_value\n", "rdeve_value\nsecond\n"} {
		if _, err = readEnrollmentCode(strings.NewReader(input)); err == nil {
			t.Fatalf("invalid input %q was accepted", input)
		}
	}
}
