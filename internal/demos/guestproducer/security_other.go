//go:build !linux

package guestproducer

import "fmt"

func DropCapabilities() error {
	return fmt.Errorf("native Tetragon collection requires the static Linux source build")
}
