//go:build !linux

package main

import (
	"context"
	"errors"
)

func prepareDeviceStop() (func() error, error) {
	return func() error { return nil }, nil
}

func uninstallDevice(context.Context, string, bool) error {
	// Windows running-image deletion and task/service ownership need a dedicated
	// installer. Do not guess task names or delete a user's credential directory.
	return errors.New("remote uninstall is unsupported on this OS")
}
