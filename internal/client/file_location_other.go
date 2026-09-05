//go:build !windows

package client

import (
	"fmt"
	"os"
	"path/filepath"
)

func desktopFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	path := filepath.Join(home, "Desktop")
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("resolve desktop directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("desktop location is not a directory")
	}
	return path, nil
}
