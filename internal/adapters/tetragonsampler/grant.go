// Package tetragonsampler binds real Tetragon events and visibility measurements
// to an externally authorized native read. It does not assign control standing.
package tetragonsampler

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
	"github.com/ckodex-labs/ckodex-oskal/internal/signedrecords"
)

const ReadGrantPayloadType = "application/vnd.oskal.tetragon-read-grant.v1+json"
const MaxGrantBytes = 64 << 10
const MaxGrantRemaining = 5 * time.Minute

// ReadGrant is signed by the outside operator, never minted by this sampler.
// RoleGrant.Digest is empty inside the signed payload to avoid self-reference.
type ReadGrant struct {
	RoleGrant tetragonhealth.RoleGrant `json:"roleGrant"`
}

func readGrant(ctx context.Context, path string, key ed25519.PublicKey, enrollment string, now time.Time) (tetragonhealth.RoleGrant, []byte, error) {
	var empty tetragonhealth.RoleGrant
	if err := ctx.Err(); err != nil {
		return empty, nil, err
	}
	file, err := openGrant(path)
	if err != nil {
		return empty, nil, fmt.Errorf("open signed native read grant: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return empty, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > MaxGrantBytes {
		return empty, nil, fmt.Errorf("grant must be a bounded regular file without group/other write permission")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaxGrantBytes+1))
	if err != nil {
		return empty, nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return empty, nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return empty, nil, err
	}
	if len(raw) > MaxGrantBytes || int64(len(raw)) != info.Size() || !after.ModTime().Equal(info.ModTime()) || !os.SameFile(info, pathInfo) || !pathInfo.Mode().IsRegular() {
		return empty, nil, fmt.Errorf("grant changed during bounded read")
	}
	payload, err := signedrecords.Verify(ctx, raw, ReadGrantPayloadType, key, MaxGrantBytes)
	if err != nil {
		return empty, nil, fmt.Errorf("authenticate native read grant: %w", err)
	}
	var value ReadGrant
	if err := signedrecords.DecodeJSON(payload, &value, MaxGrantBytes); err != nil {
		return empty, nil, err
	}
	grant := value.RoleGrant
	if grant.Digest != "" || grant.Role != "tetragon.health.read" || grant.EnrollmentDigest != enrollment || !now.Before(grant.ValidUntil) || grant.ValidUntil.After(now.Add(MaxGrantRemaining)) || grant.Credentials.UserNamespace == "" || grant.Credentials.MountNamespace == "" {
		return empty, nil, fmt.Errorf("grant role, enrollment, bounded expiry or credential scope is invalid")
	}
	grant.Digest = assurance.ComputeDigest(raw)
	return grant, raw, nil
}
