package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
)

// Validate the argument before opening either a key file or a receipt. A
// 64-character argument is always a literal key, matching legacy verification.
func validateReceiptKeyInput(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("--public-key is required from trusted custody; supply Ed25519 hex or an explicit key-file path")
	}
	if len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("--public-key requires bounded hexadecimal text or a valid key-file path")
	}
	if len(value) == ed25519.PublicKeySize*2 {
		if _, err := hex.DecodeString(value); err != nil {
			return fmt.Errorf("--public-key literal must contain exactly 64 hexadecimal characters")
		}
	}
	return nil
}

func readReceiptPublicKey(value string) (ed25519.PublicKey, error) {
	if err := validateReceiptKeyInput(value); err != nil {
		return nil, err
	}
	encoded := strings.TrimSpace(value)
	if len(encoded) != ed25519.PublicKeySize*2 {
		raw, err := readBoundedFile(encoded, 4096)
		if err != nil {
			return nil, fmt.Errorf("read trusted public key; check --public-key and restore the intended key file: %w", err)
		}
		encoded = strings.TrimSpace(string(raw))
	}
	key, err := hex.DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || len(encoded) != ed25519.PublicKeySize*2 {
		return nil, fmt.Errorf("trusted public key must contain exactly 64 hexadecimal characters; restore the enrolled public key")
	}
	return ed25519.PublicKey(key), nil
}
