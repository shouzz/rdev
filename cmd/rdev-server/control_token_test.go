package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeControlTokenFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control-token")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("write control token file: %v", err)
	}
	return path
}

func TestReadControlTokenFile(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	for _, suffix := range []string{"", "\n", "\r\n"} {
		path := writeControlTokenFile(t, token+suffix)
		got, err := readControlTokenFile(path)
		if err != nil {
			t.Fatalf("suffix %q: %v", suffix, err)
		}
		if got != token {
			t.Fatalf("suffix %q: token mismatch", suffix)
		}
	}
}

func TestReadControlTokenFileRejectsInvalidInput(t *testing.T) {
	if _, err := readControlTokenFile(""); err == nil {
		t.Fatal("empty path was accepted")
	}
	if _, err := readControlTokenFile("control-token"); err == nil {
		t.Fatal("relative path was accepted")
	}
	if _, err := readControlTokenFile(writeControlTokenFile(t, "too-short\n")); !errors.Is(err, errControlTokenTooShort) {
		t.Fatalf("short token error = %v", err)
	}
	if _, err := readControlTokenFile(writeControlTokenFile(t, strings.Repeat("a", controlTokenMaxBytes+1))); !errors.Is(err, errControlTokenTooLarge) {
		t.Fatalf("large token error = %v", err)
	}
	if _, err := readControlTokenFile(writeControlTokenFile(t, "0123456789abcdef\n0123456789abcdef")); err == nil {
		t.Fatal("multiline token was accepted")
	}
}

func TestReadControlTokenFileRejectsNonOwnerPermissionsOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	path := writeControlTokenFile(t, "0123456789abcdef0123456789abcdef")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod control token file: %v", err)
	}
	if _, err := readControlTokenFile(path); !errors.Is(err, errControlTokenPermissions) {
		t.Fatalf("permission error = %v", err)
	}
}
