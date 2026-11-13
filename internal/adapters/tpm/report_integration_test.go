//go:build integration

package tpm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/google/go-tpm/tpm2"
)

func realProvider(t *testing.T) (*Provider, *Verifier) {
	t.Helper()
	address := os.Getenv("OSKAL_SWTPM_ADDRESS")
	if err := validateEndpoint("tcp", address); err != nil {
		t.Fatal("real swtpm endpoint is required: ", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	enrollment, config := provision(t, &socketTransport{ctx: ctx, network: "tcp", address: address}, address)
	provider, err := NewProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	return provider, verifier
}

func TestRealTPMReportPort(t *testing.T) {
	provider, verifier := realProvider(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	var qualification [64]byte
	copy(qualification[:], []byte("real quote report framing experiment"))
	raw, err := provider.Attest(ctx, qualification)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := verifier.VerifyAttestation(ctx, raw, qualification)
	if err != nil || facts != verifier.Environment() || facts.RootLabel != SoftwareRootLabel {
		t.Fatalf("verified facts=%+v err=%v", facts, err)
	}
	var decoded report
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"duplicate_version": bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		"unknown_field":     append([]byte(`{"unexpected":1,`), raw[1:]...),
		"incorrect_case":    bytes.Replace(raw, []byte(`"version"`), []byte(`"Version"`), 1),
		"nested_duplicate":  bytes.Replace(raw, []byte(`"quote":{`), []byte(`"quote":{"rootCode":"SOFTWARE_TPM",`), 1),
		"trailing_document": append(bytes.Clone(raw), []byte(`{}`)...),
		"oversized":         bytes.Repeat([]byte(" "), MaxReportBytes+1),
		"truncated":         raw[:len(raw)-1],
		"wrong_version":     bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1),
	}
	for _, size := range []int{0, 31, 33} {
		bad := decoded
		bad.Quote.PCRValue = base64.StdEncoding.EncodeToString(make([]byte, size))
		encoded, err := json.Marshal(bad)
		if err != nil {
			t.Fatal(err)
		}
		tests["PCR_length_"+strconv.Itoa(size)] = encoded
	}
	bad := decoded
	bad.Quote.Attestation += "\n"
	tests["noncanonical_base64"], err = json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			facts, err := verifier.VerifyAttestation(ctx, input, qualification)
			if err == nil || facts != (assurance.AttestedEnvironment{}) {
				t.Fatalf("invalid report returned facts=%+v err=%v", facts, err)
			}
		})
	}
	t.Run("wrong_qualification", func(t *testing.T) {
		other := qualification
		other[0] ^= 1
		facts, err := verifier.VerifyAttestation(ctx, raw, other)
		if err == nil || facts != (assurance.AttestedEnvironment{}) {
			t.Fatal("wrong qualification returned verified environment")
		}
	})
	t.Run("canceled_context", func(t *testing.T) {
		canceled, stop := context.WithCancel(ctx)
		stop()
		facts, err := verifier.VerifyAttestation(canceled, raw, qualification)
		if err == nil || facts != (assurance.AttestedEnvironment{}) {
			t.Fatal("canceled verification returned facts")
		}
	})
	t.Run("actual_scalar_equivalent_minimal_encoding", func(t *testing.T) {
		for attempt := 1; attempt <= 4096; attempt++ {
			q, err := provider.Quote(ctx, qualification)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](q.Signature)
			if err != nil {
				t.Fatal(err)
			}
			ecc, err := sig.Signature.ECDSA()
			if err != nil {
				t.Fatal(err)
			}
			if ecc.SignatureR.Buffer[0] != 0 && ecc.SignatureS.Buffer[0] != 0 {
				continue
			}
			if _, err := verifier.Verify(q, qualification); err != nil {
				t.Fatal(err)
			}
			ecc.SignatureR.Buffer = bytes.TrimLeft(ecc.SignatureR.Buffer, "\x00")
			ecc.SignatureS.Buffer = bytes.TrimLeft(ecc.SignatureS.Buffer, "\x00")
			q.Signature = tpm2.Marshal(*sig)
			if _, err := verifier.Verify(q, qualification); err != nil {
				t.Fatalf("equivalent scalar encoding rejected: %v", err)
			}
			t.Logf("VERIFIED equivalent minimal scalar encoding from real TPM signature after %d quotes; TPM emitted padded encoding", attempt)
			return
		}
		t.Log("NOT_DEMONSTRATED: bounded real signature search found no leading-zero scalar; no claim of minimal-encoding runtime coverage")
	})
}
