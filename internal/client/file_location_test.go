package client

import (
	"errors"
	"testing"
)

func TestResolveFileLocationUsesExactDesktopSemantic(t *testing.T) {
	called := 0
	path, err := resolveFileLocationWith("", fileLocationDesktop, func() (string, error) {
		called++
		return "/resolved/desktop", nil
	})
	if err != nil || path != "/resolved/desktop" || called != 1 {
		t.Fatalf("desktop resolution = path:%q calls:%d err:%v", path, called, err)
	}
}

func TestResolveFileLocationRejectsAmbiguousAndUnknownInputs(t *testing.T) {
	resolver := func() (string, error) { return "", errors.New("must not be called") }
	for _, input := range []struct {
		path     string
		location string
	}{
		{path: "/tmp/file", location: fileLocationDesktop},
		{location: "Desktop"},
		{location: "downloads"},
	} {
		if _, err := resolveFileLocationWith(input.path, input.location, resolver); err == nil {
			t.Fatalf("resolveFileLocationWith(%q, %q) succeeded", input.path, input.location)
		}
	}
}

func TestResolveFileLocationPreservesExplicitPath(t *testing.T) {
	path, err := resolveFileLocationWith("/tmp/exact", "", func() (string, error) {
		return "", errors.New("must not be called")
	})
	if err != nil || path != "/tmp/exact" {
		t.Fatalf("explicit path = %q, err=%v", path, err)
	}
}
