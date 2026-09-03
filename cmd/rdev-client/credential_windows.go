//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readProtectedFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("protected identity path is not a regular file")
	}
	protected, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	plain, err := unprotectCredential(protected)
	if err != nil {
		return "", err
	}
	if len(plain) == 0 {
		return "", errors.New("protected credential is empty")
	}
	return string(plain), nil
}

func writeProtectedFile(path, value string) error {
	if value == "" {
		return errors.New("protected credential is empty")
	}
	protected, err := protectCredential([]byte(value))
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".rdev-identity-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(protected)
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
	if _, err = os.Lstat(path); err == nil {
		return errors.New("refusing to replace an existing protected identity")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func protectCredential(plain []byte) ([]byte, error) {
	input := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, 0, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...), nil
}

func unprotectCredential(protected []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, errors.New("protected credential file is empty")
	}
	input := windows.DataBlob{Size: uint32(len(protected)), Data: &protected[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, 0, &output); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, int(output.Size))...), nil
}
