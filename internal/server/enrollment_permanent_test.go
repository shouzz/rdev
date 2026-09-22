package server

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPermanentEnrollmentSurvivesYearsAndRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	now := time.Date(2026, 9, 22, 1, 0, 0, 0, time.UTC)
	load := func() *Server {
		s := NewServer()
		s.ControlToken = "test-control"
		s.enrollmentNow = func() time.Time { return now }
		if err := s.ConfigureEnrollmentStore(path, "https://rdev.example.com"); err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := load()
	permanent := createEnrollmentForTest(t, s, "feidu-user:42", 0)
	revoked := createEnrollmentForTest(t, s, "feidu-user:42", 0)
	finite := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	if permanent.ExpiresAt != "" || permanent.ExpiresAtMs != 0 {
		t.Fatal("permanent invite has an expiry")
	}
	if err := s.revokeEnrollment(revoked.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	now = now.AddDate(10, 0, 0)
	s = load()
	for _, item := range []struct {
		invite enrollmentCreateResponse
		state  string
	}{{permanent, "active"}, {revoked, "revoked"}, {finite, "expired"}} {
		status := getEnrollmentStatusForTest(t, s, item.invite.EnrollmentID)
		if status.State != item.state {
			t.Fatalf("state=%s want %s", status.State, item.state)
		}
	}
	// A delayed client and concurrent retries still create only one device.
	statuses := make(chan int, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(enrollmentRedeemRequest{Code: permanent.Code, DeviceID: "delayed-device"})
			w := httptest.NewRecorder()
			s.HandleEnrollmentRedeemAPI(w, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
			statuses <- w.Code
		}()
	}
	wg.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		} else if status != http.StatusUnauthorized {
			t.Fatalf("redeem status=%d", status)
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d", successes)
	}
	_, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, "delayed-device", grant)
	s = load()
	if len(s.managedDevices) != 1 || s.managedDevices["delayed-device"].MaintenanceToken == nil {
		t.Fatal("restart lost device or grant")
	}
	if status := getEnrollmentStatusForTest(t, s, permanent.EnrollmentID); status.State != "consumed" || status.ExpiresAt != "" || status.ExpiresAtMs != 0 {
		t.Fatal("consumed permanent state was lost")
	}
	for _, invite := range []enrollmentCreateResponse{permanent, revoked, finite} {
		body, _ := json.Marshal(enrollmentRedeemRequest{Code: invite.Code, DeviceID: "replay"})
		w := httptest.NewRecorder()
		s.HandleEnrollmentRedeemAPI(w, httptest.NewRequest(http.MethodPost, "/api/enrollments/redeem", bytes.NewReader(body)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("invalid replay status=%d", w.Code)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(permanent.Code)) {
		t.Fatal("plaintext invitation persisted")
	}
}

func TestEnrollmentDefaultAndInvalidLifetimes(t *testing.T) {
	s := maintenanceTestServer(t, filepath.Join(t.TempDir(), "registry.json"))
	for _, seconds := range []int64{-1, 1, 59, 901, math.MaxInt64, 18446744674} {
		body, _ := json.Marshal(enrollmentCreateRequest{Subject: "feidu-user:42", ExpiresInSecond: seconds})
		r := httptest.NewRequest(http.MethodPost, "/api/control/enrollments", bytes.NewReader(body))
		r.Header.Set("X-RDev-Control-Token", s.ControlToken)
		w := httptest.NewRecorder()
		s.HandleEnrollmentCreateAPI(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("seconds=%d status=%d", seconds, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/control/enrollments", strings.NewReader(`{"subject":"feidu-user:42"}`))
	r.Header.Set("X-RDev-Control-Token", s.ControlToken)
	w := httptest.NewRecorder()
	s.HandleEnrollmentCreateAPI(w, r)
	var got enrollmentCreateResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.ExpiresAt != "" || got.ExpiresAtMs != 0 {
		t.Fatal("omitted lifetime must produce a permanent invite")
	}
}

func TestLegacyEnrollmentRegistryCannotSilentlyLoseExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	s := maintenanceTestServer(t, path)
	createEnrollmentForTest(t, s, "feidu-user:42", 600)
	data, _ := os.ReadFile(path)
	var registry managedDeviceRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		t.Fatal(err)
	}
	registry.Enrollments[0].ExpiresAt = ""
	for _, schema := range []string{managedDeviceRegistryV2, managedDeviceRegistryV3, managedDeviceRegistryV4} {
		registry.Schema = schema
		modified, _ := json.Marshal(registry)
		if err := os.WriteFile(path, modified, 0600); err != nil {
			t.Fatal(err)
		}
		if err := NewServer().ConfigureEnrollmentStore(path, "https://rdev.example.com"); err == nil {
			t.Fatalf("%s accepted missing expiry", schema)
		}
	}
}
