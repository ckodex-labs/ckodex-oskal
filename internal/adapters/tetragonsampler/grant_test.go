//go:build linux || darwin

package tetragonsampler

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
	"golang.org/x/sys/unix"
)

// Actual signatures and filesystem operations prove grant admission boundaries.
// The credential strings are schema inputs, not native credential observations.
func TestSignedGrantFileBoundaries(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signedrecords.NewSigner(private)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	enrollment := assurance.ComputeStringDigest("grant schema test")
	value := ReadGrant{RoleGrant: tetragonhealth.RoleGrant{Role: "tetragon.health.read", EnrollmentDigest: enrollment, ValidUntil: now.Add(time.Minute), Credentials: tetragonhealth.Credentials{UserNamespace: "schema-only-userns", MountNamespace: "schema-only-mountns"}}}
	path := filepath.Join(t.TempDir(), "grant.dsse")
	write := func(v ReadGrant) []byte {
		t.Helper()
		payload, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := signer.Sign(t.Context(), ReadGrantPayloadType, payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	original := write(value)
	grant, raw, err := readGrant(t.Context(), path, public, enrollment, now)
	if err != nil || grant.Digest != assurance.ComputeDigest(original) || string(raw) != string(original) {
		t.Fatalf("real signed grant: %+v %v", grant, err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := readGrant(t.Context(), path, other, enrollment, now); err == nil {
		t.Fatal("outside key mismatch accepted")
	}
	if _, _, err := readGrant(t.Context(), path, public, assurance.ComputeStringDigest("other enrollment"), now); err == nil {
		t.Fatal("cross-enrollment grant accepted")
	}
	for name, edit := range map[string]func(*ReadGrant){"expired": func(v *ReadGrant) { v.RoleGrant.ValidUntil = now }, "unbounded": func(v *ReadGrant) { v.RoleGrant.ValidUntil = now.Add(6 * time.Minute) }, "self-digest": func(v *ReadGrant) { v.RoleGrant.Digest = enrollment }, "wrong-role": func(v *ReadGrant) { v.RoleGrant.Role = "tetragon.admin" }} {
		t.Run(name, func(t *testing.T) {
			v := value
			edit(&v)
			write(v)
			if _, _, err := readGrant(t.Context(), path, public, enrollment, now); err == nil {
				t.Fatal("invalid signed scope accepted")
			}
		})
	}
	write(value)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := readGrant(ctx, path, public, enrollment, now); err == nil {
		t.Fatal("canceled grant read accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readGrant(t.Context(), link, public, enrollment, now); err == nil {
		t.Fatal("symlink grant accepted")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readGrant(t.Context(), fifo, public, enrollment, now); err == nil {
		t.Fatal("nonregular grant accepted")
	}
	if err := os.WriteFile(path, make([]byte, MaxGrantBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readGrant(t.Context(), path, public, enrollment, now); err == nil {
		t.Fatal("oversized grant accepted")
	}
}
