//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const managedClientExecutable = "/usr/local/lib/rdev/rdev-client"
const managedClientUnit = "/etc/systemd/system/rdev-client.service"

func installedSystemdClient() bool {
	exe, err := os.Executable()
	if err != nil || exe != managedClientExecutable {
		return false
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasSuffix(line, "/rdev-client.service") {
			return true
		}
	}
	return false
}

func systemctl(ctx context.Context, args ...string) error {
	// Use a system executable, never a caller-controlled PATH entry.
	return exec.CommandContext(ctx, "/usr/bin/systemctl", args...).Run()
}

func prepareDeviceStop() (func() error, error) {
	if installedSystemdClient() {
		return func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			// An explicit stop suppresses Restart=always without disabling boot startup.
			return systemctl(ctx, "--no-block", "stop", "rdev-client.service")
		}, nil
	}
	if os.Getenv("INVOCATION_ID") != "" {
		return nil, errors.New("unknown systemd installation")
	}
	return func() error { return nil }, nil
}

func uninstallDevice(ctx context.Context, identityPath string, deleteIdentity bool) error {
	if !installedSystemdClient() {
		return errors.New("uninstall supports only the standard Linux systemd installation")
	}
	// Never remove a directory tree. Only fixed installation files and the exact
	// identity file configured locally may be removed.
	if deleteIdentity && (identityPath == "" || !filepath.IsAbs(identityPath) || filepath.Clean(identityPath) != identityPath) {
		return errors.New("identity path is unavailable")
	}
	if err := systemctl(ctx, "disable", "rdev-client.service"); err != nil {
		return err
	}
	if err := os.Remove(managedClientUnit); err != nil {
		return err
	}
	if err := systemctl(ctx, "daemon-reload"); err != nil {
		return err
	}
	if err := os.Remove(managedClientExecutable); err != nil {
		return err
	}
	if deleteIdentity {
		if err := os.Remove(identityPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
