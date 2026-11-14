// Package softwareroot initializes explicitly owned, fresh, disposable software
// TPM state. It never resets PCRs, clears a TPM, or provisions hardware TPMs.
package softwareroot

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/quoteissuer"
	adapter "github.com/ckodex-labs/ckodex-oskal/internal/adapters/tpm"
	"github.com/google/go-tpm/tpm2"
)

type Config struct {
	Network             string
	Address             string
	FreshStateDirectory string
	ExecutablePath      string
	// Caller attests that endpoint and private state directory belong to the
	// same newly created software TPM. Endpoint protocol cannot prove custody.
	ConfirmFreshSoftwareTPM bool
}
type Root struct {
	Enrollment     adapter.Enrollment
	ProviderConfig adapter.ProviderConfig
	Measurement    [32]byte
}

func Initialize(ctx context.Context, c Config) (*Root, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.ConfirmFreshSoftwareTPM {
		return nil, fmt.Errorf("explicit fresh software TPM ownership confirmation required")
	}
	if c.Network == "tcp" {
		host, _, err := net.SplitHostPort(c.Address)
		ip, parseErr := netip.ParseAddr(host)
		if err != nil || parseErr != nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("software TPM requires literal loopback TCP")
		}
	} else if c.Network != "unix" || !filepath.IsAbs(c.Address) {
		return nil, fmt.Errorf("software TPM requires absolute Unix socket or loopback TCP")
	}
	if !filepath.IsAbs(c.FreshStateDirectory) {
		return nil, fmt.Errorf("absolute private software TPM state directory required")
	}
	state, err := os.Lstat(c.FreshStateDirectory)
	if err != nil {
		return nil, err
	}
	if !state.IsDir() || state.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("software TPM state directory must be private and not a symlink")
	}
	file, err := os.Open(c.ExecutablePath)
	if err != nil {
		return nil, err
	}
	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !stat.Mode().IsRegular() || stat.Size() <= 0 || stat.Size() > 128<<20 {
		_ = file.Close()
		return nil, fmt.Errorf("ELF measurement exceeds bounds")
	}
	data := make([]byte, stat.Size())
	_, err = file.ReadAt(data, 0)
	_ = file.Close()
	if err != nil {
		return nil, err
	}
	measurement := sha256.Sum256(data)
	inspector, err := quoteissuer.NewPinnedFileInspector(c.ExecutablePath, measurement)
	if err != nil {
		return nil, err
	}
	defer func() { _ = inspector.Close() }()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := inspector.Verify(ctx); err != nil {
		return nil, err
	}
	// Marker remains on any failure: partial initialization requires new owned
	// state, never a silent retry/reset of an existing root.
	marker, err := os.OpenFile(filepath.Join(c.FreshStateDirectory, "oskal-provisioned"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("fresh software TPM state marker: %w", err)
	}
	if err := marker.Close(); err != nil {
		return nil, err
	}
	tr := &socketTransport{ctx: ctx, network: c.Network, address: c.Address}
	selection := tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{Hash: tpm2.TPMAlgSHA256, PCRSelect: []byte{0, 0, 1}}}}
	initial, err := (tpm2.PCRRead{PCRSelectionIn: selection}).Execute(tr)
	if err != nil {
		return nil, fmt.Errorf("read fresh PCR16: %w", err)
	}
	if !bytes.Equal(tpm2.Marshal(initial.PCRSelectionOut), tpm2.Marshal(selection)) || len(initial.PCRValues.Digests) != 1 || !bytes.Equal(initial.PCRValues.Digests[0].Buffer, make([]byte, 32)) {
		return nil, fmt.Errorf("fresh software TPM PCR16 must be zero; refusing existing root")
	}
	var auth [32]byte
	if _, err := rand.Read(auth[:]); err != nil {
		return nil, err
	}
	public := tpm2.TPMTPublic{Type: tpm2.TPMAlgECC, NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true, Restricted: true, SignEncrypt: true},
		Parameters:       tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull}, Scheme: tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgECDSA, Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256})}, CurveID: tpm2.TPMECCNistP256, KDF: tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull}}), Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{})}
	created, err := (tpm2.CreatePrimary{PrimaryHandle: tpm2.TPMRHOwner, InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{UserAuth: tpm2.TPM2BAuth{Buffer: auth[:]}}}, InPublic: tpm2.New2B(public)}).Execute(tr)
	if err != nil {
		return nil, fmt.Errorf("create restricted software TPM AK: %w", err)
	}
	root := &Root{ProviderConfig: adapter.ProviderConfig{Network: c.Network, Address: c.Address, AKHandle: uint32(created.ObjectHandle), AKName: bytes.Clone(created.Name.Buffer), AKAuth: bytes.Clone(auth[:]), PCRIndex: 16, CommandTimeout: 5 * time.Second}, Measurement: measurement}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = root.Close(context.Background())
		}
	}()
	read, err := (tpm2.ReadPublic{ObjectHandle: created.ObjectHandle}).Execute(tr)
	if err != nil {
		return nil, err
	}
	if _, err := (tpm2.PCRExtend{PCRHandle: tpm2.TPMHandle(16), Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: measurement[:]}}}}).Execute(tr); err != nil {
		return nil, err
	}
	var preimage [64]byte
	copy(preimage[32:], measurement[:])
	root.Enrollment = adapter.Enrollment{AKPublic: bytes.Clone(read.OutPublic.Bytes()), AKName: bytes.Clone(read.Name.Buffer), AKQualifiedName: bytes.Clone(read.QualifiedName.Buffer), PCRIndex: 16, ExpectedPCR: sha256.Sum256(preimage[:])}
	if err := inspector.Verify(ctx); err != nil {
		return nil, err
	}
	provider, err := adapter.NewProvider(root.ProviderConfig)
	if err != nil {
		return nil, err
	}
	verifier, err := adapter.NewVerifier(root.Enrollment)
	if err != nil {
		return nil, err
	}
	var qualification [64]byte
	if _, err := rand.Read(qualification[:]); err != nil {
		return nil, err
	}
	report, err := provider.Attest(ctx, qualification)
	if err != nil {
		return nil, err
	}
	if _, err := verifier.VerifyAttestation(ctx, report, qualification); err != nil {
		return nil, fmt.Errorf("verify fresh software TPM initialization: %w", err)
	}
	succeeded = true
	return root, nil
}

// Close flushes only this transient AK. State/PCRs and the consumed marker are
// retained; destroying the disposable container/state is the caller's action.
func (r *Root) Close(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := (tpm2.FlushContext{FlushHandle: tpm2.TPMHandle(r.ProviderConfig.AKHandle)}).Execute(&socketTransport{ctx: ctx, network: r.ProviderConfig.Network, address: r.ProviderConfig.Address})
	return err
}
