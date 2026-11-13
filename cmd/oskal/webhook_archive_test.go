package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWebhookArchiveConfigurationRejectsConflictingRoots(t *testing.T) {
	root := t.TempDir()
	one, two := filepath.Join(root, "first"), filepath.Join(root, "second")
	if _, err := webhookArchivePath(one, two); err == nil {
		t.Fatal("distinct webhook and global archives were silently selected")
	}
	for _, path := range []string{one, two} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("configuration check created archive: %v", err)
		}
	}
	for _, pair := range [][2]string{{"", one}, {one, ""}, {one, one}, {one, filepath.Join(root, ".", "first")}} {
		resolved, err := webhookArchivePath(pair[0], pair[1])
		if err != nil || resolved == "" {
			t.Fatalf("unambiguous archive rejected: %s %v", resolved, err)
		}
	}
	empty, err := webhookArchivePath("", "")
	if err != nil || empty != "" {
		t.Fatal("unconfigured policy-only webhook acquired an archive")
	}
}
