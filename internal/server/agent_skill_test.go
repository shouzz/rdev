package server

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEmbeddedRDevAgentSkillMatchesRepositorySource(t *testing.T) {
	for _, relativePath := range []string{
		"SKILL.md",
		filepath.Join("scripts", "rdev-agent.py"),
	} {
		sourcePath := filepath.Join("..", "..", "skills", "rdev-agent", relativePath)
		embeddedPath := filepath.Join("static", "skills", "rdev-agent", relativePath)
		source, err := os.ReadFile(sourcePath)
		if err != nil {
			t.Fatalf("read repository skill %s: %v", relativePath, err)
		}
		embedded, err := os.ReadFile(embeddedPath)
		if err != nil {
			t.Fatalf("read embedded skill %s: %v", relativePath, err)
		}
		if !bytes.Equal(source, embedded) {
			t.Fatalf("embedded skill %s differs from repository source", relativePath)
		}
	}
}
