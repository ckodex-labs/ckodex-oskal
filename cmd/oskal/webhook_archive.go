package main

import (
	"fmt"
	"path/filepath"
)

// webhookArchivePath keeps the shared archive option and webhook-specific
// option explicit. Distinct configured roots are rejected before any creation.
func webhookArchivePath(global, local string) (string, error) {
	if local == "" {
		return global, nil
	}
	if global == "" {
		return local, nil
	}
	globalPath, err := filepath.Abs(global)
	if err != nil {
		return "", err
	}
	localPath, err := filepath.Abs(local)
	if err != nil {
		return "", err
	}
	if filepath.Clean(globalPath) != filepath.Clean(localPath) {
		return "", fmt.Errorf("conflicting --evidence-dir and --webhook-evidence-dir; configure one archive or identical paths")
	}
	return local, nil
}
