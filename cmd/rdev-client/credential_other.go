//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func readProtectedFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("protected identity path is not a regular file")
	}
	if info.Mode().Perm() != 0600 {
		return "", errors.New("protected identity permissions must be 0600")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("credential file must contain exactly one non-empty line")
	}
	return value, nil
}

func writeProtectedFile(path, value string) error {
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return errors.New("credential must contain exactly one non-empty line")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return errors.New("refusing to replace a non-regular protected identity")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".rdev-identity-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write([]byte(value + "\n"))
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
