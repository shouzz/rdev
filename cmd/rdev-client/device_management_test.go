package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"rdev/internal/updater"
)

func TestDeviceStopSubprocessPreservesIdentity(t *testing.T) {
	if os.Getenv("RDEV_TEST_STOP_CHILD") == "1" {
		handler := deviceActionHandler(updater.Config{Version: "dev"}, os.Getenv("RDEV_TEST_IDENTITY"), false, func() {})
		outcome, err := handler(context.Background(), "stop", false)
		if err != nil || outcome.State != "stopping" || outcome.After == nil {
			os.Exit(3)
		}
		_ = outcome.After()
		os.Exit(4) // a stop must never fall through into reconnect
	}
	identity := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(identity, []byte("protected-identity-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDeviceStopSubprocessPreservesIdentity$")
	cmd.Env = append(os.Environ(), "RDEV_TEST_STOP_CHILD=1", "RDEV_TEST_IDENTITY="+identity, "INVOCATION_ID=")
	err := cmd.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != intentionalStopExitCode {
		t.Fatalf("stop did not terminate once with code 75: %v", err)
	}
	data, err := os.ReadFile(identity)
	if err != nil || string(data) != "protected-identity-fixture" {
		t.Fatal("one-shot stop changed identity")
	}
}

func TestRemoteUninstallRequiresLocalOptIn(t *testing.T) {
	identity := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(identity, []byte("identity"), 0600); err != nil {
		t.Fatal(err)
	}
	handler := deviceActionHandler(updater.Config{Version: "dev"}, identity, false, func() {})
	for _, deleteIdentity := range []bool{false, true} {
		if _, err := handler(context.Background(), "uninstall", deleteIdentity); err == nil {
			t.Fatal("uninstall without local opt-in succeeded")
		}
		if data, err := os.ReadFile(identity); err != nil || string(data) != "identity" {
			t.Fatal("rejected uninstall changed identity")
		}
	}
	// This test binary is never the standard installed systemd client. Even
	// local opt-in cannot authorize arbitrary installation paths or another OS.
	optedIn := deviceActionHandler(updater.Config{Version: "dev"}, identity, true, func() {})
	if _, err := optedIn(context.Background(), "uninstall", true); err == nil {
		t.Fatal("unsupported installation uninstalled")
	}
	if data, err := os.ReadFile(identity); err != nil || string(data) != "identity" {
		t.Fatal("unsupported uninstall deleted identity")
	}
	if _, err := handler(context.Background(), "upgrade", false); err == nil {
		t.Fatal("development upgrade reported up to date")
	}
	if _, err := handler(context.Background(), "stop", true); err == nil {
		t.Fatal("stop accepted identity deletion")
	}
}
