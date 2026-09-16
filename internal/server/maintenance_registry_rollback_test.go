package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestMaintenanceRegistryRollbackPreservesLatestStateAndLoadsV3(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("offline conversion runs on the Linux service host")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required to run the offline conversion tool")
	}
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate rollback script")
	}
	script := filepath.Join(filepath.Dir(testFile), "..", "..", "scripts", "maintenance-registry-rollback.py")
	registryPath := filepath.Join(t.TempDir(), "managed_devices.json")
	s := maintenanceTestServer(t, registryPath)
	first := redeemEnrollmentForTest(t, s, createEnrollmentForTest(t, s, "feidu-user:42", 600).Code, "before-upgrade")
	token, grant := maintenanceTestRandom(t)
	maintenanceTestInstall(t, s, first.DeviceID, grant)
	added := redeemEnrollmentForTest(t, s, createEnrollmentForTest(t, s, "feidu-user:42", 600).Code, "after-upgrade")
	rotatedSecret, _, err := s.rotateManagedDeviceSecret(added.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	revoked := redeemEnrollmentForTest(t, s, createEnrollmentForTest(t, s, "feidu-user:42", 600).Code, "revoked-after-upgrade")
	if err = s.revokeManagedDevice(revoked.DeviceID); err != nil {
		t.Fatal(err)
	}
	unused := createEnrollmentForTest(t, s, "feidu-user:42", 600)
	if err = s.revokeEnrollment(unused.EnrollmentID); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]any
	if err = json.Unmarshal(before, &expected); err != nil {
		t.Fatal(err)
	}
	expected["schema"] = managedDeviceRegistryV3
	for _, device := range expected["devices"].([]any) {
		delete(device.(map[string]any), "maintenance_token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, python, script, registryPath).CombinedOutput()
	if err != nil {
		t.Fatalf("offline conversion failed: %v", err)
	}
	var result struct {
		Changed     bool   `json:"changed"`
		Backup      string `json:"backup"`
		Devices     int    `json:"devices"`
		Enrollments int    `json:"enrollments"`
	}
	if err = json.Unmarshal(output, &result); err != nil {
		t.Fatal("conversion did not return a JSON summary")
	}
	if !result.Changed || result.Devices != 3 || result.Enrollments != 4 {
		t.Fatal("conversion summary did not retain all current records")
	}
	backup, err := os.ReadFile(result.Backup)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, backup) {
		t.Fatal("backup does not match exact pre-conversion bytes")
	}
	after, err := os.ReadFile(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]any
	if err = json.Unmarshal(after, &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, actual) {
		t.Fatal("conversion changed fields other than schema and maintenance authorization")
	}
	reloaded := maintenanceTestServer(t, registryPath)
	if len(reloaded.managedDevices) != 3 || len(reloaded.enrollments) != 4 {
		t.Fatal("v3 loader lost a current device or enrollment")
	}
	if allowed, managed := reloaded.authorizeManagedRegistration(first.DeviceID, first.DeviceSecret); !allowed || !managed {
		t.Fatal("v3 loader rejected original device identity")
	}
	if allowed, managed := reloaded.authorizeManagedRegistration(added.DeviceID, rotatedSecret); !allowed || !managed {
		t.Fatal("v3 loader lost latest rotated credential for a newly enrolled device")
	}
	if allowed, _ := reloaded.authorizeManagedRegistration(added.DeviceID, added.DeviceSecret); allowed {
		t.Fatal("rollback restored an obsolete device credential")
	}
	if allowed, _ := reloaded.authorizeManagedRegistration(revoked.DeviceID, revoked.DeviceSecret); allowed {
		t.Fatal("rollback restored a revoked device")
	}
	if status := getEnrollmentStatusForTest(t, reloaded, unused.EnrollmentID); status.State != "revoked" {
		t.Fatal("rollback lost revoked enrollment state")
	}
	if reloaded.authorizeDeviceCredential(&ClientConn{ID: first.DeviceID, InstanceID: "new"}, token) {
		t.Fatal("converted v3 registry unexpectedly retained fixed-token authorization")
	}
}
