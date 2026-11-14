// Package quoteissuer brokers software TPM quotes outside the guest. It does
// not establish hardware-backed identity, runtime memory integrity, or key
// non-extractability. Deployment must isolate its files, credentials and TPM.
package quoteissuer

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Inspector checks an outside-owned measurement. Guest assertions are not an
// implementation of this contract. Verify runs before and after each quote.
type Inspector interface{ Verify(context.Context) error }

// PinnedFileInspector checks both a pinned read-only descriptor and its path.
// This measures file bytes, not process memory or resistance to guest/host root.
// The caller must ensure the guest cannot modify this path or its ancestors.
type PinnedFileInspector struct {
	file     *os.File
	path     string
	expected [32]byte
}

func NewPinnedFileInspector(path string, expected [32]byte) (*PinnedFileInspector, error) {
	if !filepath.IsAbs(path) || expected == ([32]byte{}) {
		return nil, fmt.Errorf("absolute outside-owned ELF path and digest required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	p := &PinnedFileInspector{file: f, path: path, expected: expected}
	if err := p.Verify(context.Background()); err != nil {
		_ = f.Close()
		return nil, err
	}
	_, err = elf.NewFile(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("measurement is not an ELF: %w", err)
	}
	// elf.NewFile does not own f; retaining f pins the same object.
	return p, nil
}
func (p *PinnedFileInspector) Close() error { return p.file.Close() }
func (p *PinnedFileInspector) Verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := p.file.Stat()
	if err != nil {
		return err
	}
	named, err := os.Lstat(p.path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 128<<20 || before.Mode().Perm()&0022 != 0 || !os.SameFile(before, named) {
		return fmt.Errorf("measurement file changed identity, mode, or bounds")
	}
	h := sha256.New()
	var offset int64
	buffer := make([]byte, 64<<10)
	for offset < before.Size() {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := p.file.ReadAt(buffer, offset)
		if n > 0 {
			_, _ = h.Write(buffer[:n])
			offset += int64(n)
		}
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	after, err := p.file.Stat()
	if err != nil {
		return err
	}
	named, err = os.Lstat(p.path)
	if err != nil {
		return err
	}
	if before.Size() != after.Size() || before.ModTime() != after.ModTime() || !os.SameFile(after, named) || after.Mode().Perm()&0022 != 0 || [32]byte(h.Sum(nil)) != p.expected {
		return fmt.Errorf("outside-owned ELF measurement mismatch")
	}
	return ctx.Err()
}
