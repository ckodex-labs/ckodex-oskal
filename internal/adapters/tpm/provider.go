package tpm

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// ProviderConfig identifies an externally provisioned AK. Credentials and TPM
// command/control endpoints must remain under the trusted host's ownership.
type ProviderConfig struct {
	Network        string
	Address        string
	AKHandle       uint32
	AKName         []byte
	AKAuth         []byte
	PCRIndex       uint32
	CommandTimeout time.Duration
}

type Provider struct {
	config ProviderConfig
	gate   chan struct{}
}

func NewProvider(c ProviderConfig) (*Provider, error) {
	if c.PCRIndex > 23 || !validName(c.AKName) || len(c.AKAuth) == 0 || len(c.AKAuth) > 32 {
		return nil, fmt.Errorf("provider requires an enrolled PCR, AK name, and nonempty bounded authorization")
	}
	if c.AKHandle>>24 != 0x80 && c.AKHandle>>24 != 0x81 {
		return nil, fmt.Errorf("AK must be a transient or persistent TPM object handle")
	}
	if c.CommandTimeout <= 0 || c.CommandTimeout > 30*time.Second {
		return nil, fmt.Errorf("TPM command timeout must be positive and at most 30 seconds")
	}
	if err := validateEndpoint(c.Network, c.Address); err != nil {
		return nil, err
	}
	c.AKName = bytes.Clone(c.AKName)
	c.AKAuth = bytes.Clone(c.AKAuth)
	return &Provider{config: c, gate: make(chan struct{}, 1)}, nil
}

// Quote serializes PCR read and quote acquisition. External PCR mutation can
// still race the commands; Verify rejects mismatched values without fallback.
func (p *Provider) Quote(ctx context.Context, qualification [QualificationSize]byte) (Quote, error) {
	if p == nil || p.gate == nil {
		return Quote{}, fmt.Errorf("provider is not initialized")
	}
	ctx, cancel := context.WithTimeout(ctx, p.config.CommandTimeout)
	defer cancel()
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return Quote{}, ctx.Err()
	}
	tr := &socketTransport{ctx: ctx, network: p.config.Network, address: p.config.Address}
	public, err := (tpm2.ReadPublic{ObjectHandle: tpm2.TPMHandle(p.config.AKHandle)}).Execute(tr)
	if err != nil {
		return Quote{}, fmt.Errorf("read AK identity: %w", err)
	}
	if !bytes.Equal(public.Name.Buffer, p.config.AKName) {
		return Quote{}, fmt.Errorf("TPM handle no longer contains the enrolled AK")
	}
	read, err := (tpm2.PCRRead{PCRSelectionIn: selection(p.config.PCRIndex)}).Execute(tr)
	if err != nil {
		return Quote{}, fmt.Errorf("read PCR: %w", err)
	}
	if !matchingSelection(read.PCRSelectionOut, p.config.PCRIndex) || len(read.PCRValues.Digests) != 1 || len(read.PCRValues.Digests[0].Buffer) != 32 {
		return Quote{}, fmt.Errorf("TPM returned an unexpected PCR selection or value")
	}
	rsp, err := (tpm2.Quote{
		SignHandle:     tpm2.AuthHandle{Handle: tpm2.TPMHandle(p.config.AKHandle), Name: tpm2.TPM2BName{Buffer: p.config.AKName}, Auth: tpm2.PasswordAuth(p.config.AKAuth)},
		QualifyingData: tpm2.TPM2BData{Buffer: qualification[:]},
		InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
		PCRSelect:      selection(p.config.PCRIndex),
	}).Execute(tr)
	if err != nil {
		return Quote{}, fmt.Errorf("TPM2_Quote: %w", err)
	}
	attestation := rsp.Quoted.Bytes()
	if len(attestation) == 0 || len(attestation) > maxAttestationSize || rsp.Signature.SigAlg != tpm2.TPMAlgECDSA {
		return Quote{}, fmt.Errorf("TPM returned an empty or unsupported quote response")
	}
	signature, err := rsp.Signature.Signature.ECDSA()
	if err != nil || signature.Hash != tpm2.TPMAlgSHA256 || !p256ScalarSize(signature.SignatureR.Buffer) || !p256ScalarSize(signature.SignatureS.Buffer) {
		return Quote{}, fmt.Errorf("TPM returned an incomplete ECDSA quote signature")
	}
	return Quote{Attestation: bytes.Clone(attestation), Signature: tpm2.Marshal(rsp.Signature),
		PCRValue: [32]byte(read.PCRValues.Digests[0].Buffer), RootCode: SoftwareRootCode, RootLabel: SoftwareRootLabel}, nil
}

func validateEndpoint(network, address string) error {
	if network == "unix" && len(address) > 0 && address[0] == '/' {
		return nil
	}
	if network == "tcp" {
		host, _, err := net.SplitHostPort(address)
		if err == nil {
			ip, parseErr := netip.ParseAddr(host)
			if parseErr == nil && ip.IsLoopback() {
				return nil
			}
		}
	}
	return fmt.Errorf("TPM endpoint must be an absolute Unix socket or literal loopback TCP address")
}
