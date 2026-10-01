//go:build windows

package updater

import (
	"errors"

	"golang.org/x/sys/windows"
)

func platformUpdateAllowed() error {
	if windows.RtlGetVersion().MajorVersion < 10 {
		return errors.New("legacy Windows requires an explicitly hash-pinned go-win7 build")
	}
	return nil
}
