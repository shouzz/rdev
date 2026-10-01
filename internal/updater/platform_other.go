//go:build !windows

package updater

func platformUpdateAllowed() error { return nil }
