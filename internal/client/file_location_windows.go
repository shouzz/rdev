//go:build windows

package client

import "golang.org/x/sys/windows"

func desktopFilePath() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_Desktop, windows.KF_FLAG_DEFAULT)
}
