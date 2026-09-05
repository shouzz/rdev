package client

import "fmt"

const (
	fileLocationHome    = "home"
	fileLocationDesktop = "desktop"
)

func resolveFileLocation(path, location string) (string, error) {
	return resolveFileLocationWith(path, location, desktopFilePath)
}

func resolveFileLocationWith(path, location string, resolveDesktop func() (string, error)) (string, error) {
	if path != "" {
		if location != "" {
			return "", fmt.Errorf("path and location cannot be used together")
		}
		return defaultFilePath(path), nil
	}
	switch location {
	case "", fileLocationHome:
		return defaultFilePath(""), nil
	case fileLocationDesktop:
		return resolveDesktop()
	default:
		return "", fmt.Errorf("unsupported file location: %s", location)
	}
}
