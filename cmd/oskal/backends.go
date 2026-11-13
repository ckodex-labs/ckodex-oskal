package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/sigstore"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/spire"
	"github.com/spf13/cobra"
)

const maxBackendDocumentBytes = 4 << 20
const maxArtifactBytes = 1 << 30

func readBoundedFile(path string, max int64) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("an explicit file path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > max {
		return nil, fmt.Errorf("%s must be a regular file containing 1 to %d bytes", path, max)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > max {
		return nil, fmt.Errorf("file exceeds permitted size or became empty")
	}
	return data, nil
}

func fileSHA256(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArtifactBytes {
		return "", fmt.Errorf("artifact must be a regular file no larger than %d bytes", maxArtifactBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, maxArtifactBytes+1))
	if err != nil {
		return "", err
	}
	if size > maxArtifactBytes {
		return "", fmt.Errorf("artifact grew beyond %d bytes", maxArtifactBytes)
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func emitBackendResult(cmd *cobra.Command, result any, code int, reason string) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return err
	}
	if code != 0 {
		return &evaluationResultError{code: code, message: reason}
	}
	return nil
}

func newIdentityCommand() *cobra.Command {
	var address, identity string
	var timeout time.Duration
	cmd := &cobra.Command{Use: "identity", Short: "Read this process's fresh verified identity from an explicit SPIRE Workload API", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		client, err := spire.NewWorkloadClient(cmd.Context(), address, identity, timeout)
		if err != nil {
			return emitBackendResult(cmd, map[string]any{"status": "ERROR", "reason": err.Error()}, 1, err.Error())
		}
		defer func() { _ = client.Close() }()
		facts, err := client.Identity(cmd.Context())
		if err != nil {
			return emitBackendResult(cmd, map[string]any{"status": "UNKNOWN", "reason": err.Error()}, 2, "workload identity could not be verified")
		}
		return emitBackendResult(cmd, map[string]any{"status": "VERIFIED", "identity": facts, "scope": "this process; not an arbitrary Kubernetes workload"}, 0, "")
	}}
	cmd.Flags().StringVar(&address, "workload-api", "", "Explicit SPIRE unix socket URI")
	cmd.Flags().StringVar(&identity, "spiffe-id", "", "Exact expected identity of this process")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "Workload API timeout, greater than zero and at most one minute")
	return cmd
}

func newVerifyCommand() *cobra.Command {
	var bundlePath, artifactPath, rootPath, rootPin, issuer, signer string
	verifyCmd := &cobra.Command{Use: "verify", Short: "Verify evidence using explicitly pinned trust and exact identity"}
	bundleCmd := &cobra.Command{Use: "bundle", Short: "Verify an actual artifact file against an offline Sigstore bundle", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		invalid := func(err error) error {
			return emitBackendResult(cmd, map[string]any{"status": "ERROR", "reason": err.Error()}, 1, err.Error())
		}
		denied := func(err error) error {
			return emitBackendResult(cmd, map[string]any{"status": "DENIED", "reason": err.Error()}, 3, "Sigstore verification denied")
		}
		if rootPin == "" || issuer == "" || signer == "" || artifactPath == "" {
			return invalid(fmt.Errorf("--artifact, --trusted-root-sha256, --issuer, and --signer are required; no trust defaults are used"))
		}
		rootBytes, err := readBoundedFile(rootPath, maxBackendDocumentBytes)
		if err != nil {
			return invalid(fmt.Errorf("trusted root: %w", err))
		}
		sum := sha256.Sum256(rootBytes)
		observedRoot := "sha256:" + hex.EncodeToString(sum[:])
		if rootPin != observedRoot {
			return denied(fmt.Errorf("trusted-root SHA-256 does not match explicit pin: observed %s", observedRoot))
		}
		raw, err := readBoundedFile(bundlePath, maxBackendDocumentBytes)
		if err != nil {
			return invalid(fmt.Errorf("sigstore bundle: %w", err))
		}
		digest, err := fileSHA256(artifactPath)
		if err != nil {
			return invalid(fmt.Errorf("artifact: %w", err))
		}
		verifier, err := sigstore.NewBundleVerifier(rootBytes, issuer, signer)
		if err != nil {
			return invalid(err)
		}
		facts, err := verifier.VerifyBundle(cmd.Context(), raw, digest)
		if err != nil {
			return denied(err)
		}
		receipt, err := facts.Receipt()
		if err != nil {
			return invalid(err)
		}
		return emitBackendResult(cmd, map[string]any{"status": "VERIFIED", "verification": json.RawMessage(receipt), "scope": "offline historical bundle verification; current root freshness and runtime artifact continuity are not established"}, 0, "")
	}}
	bundleCmd.Flags().StringVar(&bundlePath, "bundle", "", "Offline Sigstore bundle JSON, at most 4 MiB")
	bundleCmd.Flags().StringVar(&artifactPath, "artifact", "", "Actual artifact file to hash, at most 1 GiB")
	bundleCmd.Flags().StringVar(&rootPath, "trusted-root", "", "Trusted root JSON obtained through trusted custody, at most 4 MiB")
	bundleCmd.Flags().StringVar(&rootPin, "trusted-root-sha256", "", "Explicit sha256:<64 lowercase hex> pin of trusted root bytes")
	bundleCmd.Flags().StringVar(&issuer, "issuer", "", "Exact expected signing certificate issuer")
	bundleCmd.Flags().StringVar(&signer, "signer", "", "Exact expected certificate SAN identity")
	verifyCmd.AddCommand(bundleCmd)
	return verifyCmd
}
