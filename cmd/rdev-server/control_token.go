package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const controlTokenMaxBytes = 4 * 1024

var (
	errControlTokenNotRegular  = errors.New("RDev control token file is not a regular file")
	errControlTokenPermissions = errors.New("RDev control token file must not grant group or other permissions")
	errControlTokenTooLarge    = errors.New("RDev control token file exceeds size limit")
	errControlTokenTooShort    = errors.New("RDev control token must contain at least 32 bytes")
)

func readControlTokenFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("RDEV_CONTROL_TOKEN_FILE is required")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("RDEV_CONTROL_TOKEN_FILE must be an absolute path")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open RDev control token file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect RDev control token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errControlTokenNotRegular
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errControlTokenPermissions
	}
	value, err := io.ReadAll(io.LimitReader(file, controlTokenMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read RDev control token file: %w", err)
	}
	if len(value) > controlTokenMaxBytes {
		return "", errControlTokenTooLarge
	}
	value = trimOneTerminalNewline(value)
	if len(value) < 32 {
		return "", errControlTokenTooShort
	}
	if bytes.ContainsAny(value, "\r\n") {
		return "", errors.New("RDev control token must contain exactly one line")
	}
	return string(value), nil
}

func trimOneTerminalNewline(value []byte) []byte {
	if len(value) == 0 || value[len(value)-1] != '\n' {
		return value
	}
	value = value[:len(value)-1]
	if len(value) > 0 && value[len(value)-1] == '\r' {
		value = value[:len(value)-1]
	}
	return value
}
