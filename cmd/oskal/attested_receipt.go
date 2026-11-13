package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/receipts"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Root registration is explicit: receiptCmd.AddCommand(newGuestReceiptVerifyCommand()).
func newGuestReceiptVerifyCommand() *cobra.Command {
	var path, publicKey, expected string
	var outputJSON bool
	command := &cobra.Command{
		Use:          "verify-attested",
		Short:        "Verify the full v2 attested receipt signature under an explicitly pinned key",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Standalone verification must not read ambient application config.
			var inherited string
			cmd.InheritedFlags().VisitAll(func(flag *pflag.Flag) {
				if flag.Changed {
					inherited = flag.Name
				}
			})
			if inherited != "" {
				return fmt.Errorf("--%s does not apply to standalone verify-attested; use --receipt-file, --public-key, optional --expected-authority and --json", inherited)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Every flag and trust input is validated before any file is opened.
			if path == "" || len(path) > 4096 || strings.TrimSpace(path) != path || strings.ContainsAny(path, "\x00\r\n") {
				return fmt.Errorf("--receipt-file requires an explicit bounded regular-file path")
			}
			key, err := hex.DecodeString(publicKey)
			if err != nil || len(key) != ed25519.PublicKeySize || len(publicKey) != 64 {
				return fmt.Errorf("--public-key requires exactly 64 hexadecimal characters from trusted custody")
			}
			var authority *assurance.AuthorityRef
			if expected != "" {
				u, err := url.Parse(expected)
				if err != nil || u.Scheme == "" || !strings.Contains(expected, "://") {
					return fmt.Errorf("--expected-authority requires an exact authority URI claim")
				}
				a := assurance.AuthorityRef{Scheme: u.Scheme, Subject: strings.TrimPrefix(expected, u.Scheme+"://")}
				if a.Validate() != nil || a.Canonical() != expected {
					return fmt.Errorf("--expected-authority requires an exact valid authority URI claim")
				}
				authority = &a
			}
			if err := cmd.Context().Err(); err != nil {
				return err
			}
			raw, err := readBoundedFile(path, 2<<20)
			if err != nil {
				return fmt.Errorf("read attested receipt (maximum 2 MiB): %w", err)
			}
			result, err := receipts.VerifyAttestedReceipt(cmd.Context(), raw, ed25519.PublicKey(key), authority, time.Now().UTC())
			if err != nil {
				return err
			}
			if outputJSON {
				if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Signature: %s\nSigned state: %s\nEffective state: %s\nRoot: %s\nScope: %s\n", result.SignatureStatus, result.SignedState, result.EffectiveState, result.Body.Telemetry.Integrity.RootLabel, result.Scope); err != nil {
					return err
				}
			}
			switch result.EffectiveState {
			case assurance.AssuranceStateVerified, assurance.AssuranceStateAssured:
				_, err = fmt.Fprintln(cmd.ErrOrStderr(), "attested receipt signature valid; supplied assessment is currently positive")
				return err
			case assurance.AssuranceStateFailed:
				return &evaluationResultError{code: 3, message: "attested receipt signature valid; signed assessment is FAILED"}
			default:
				return &evaluationResultError{code: 2, message: "attested receipt signature valid; effective assessment is UNKNOWN or incomplete"}
			}
		},
	}
	command.Flags().StringVar(&path, "receipt-file", "", "Explicit full-body DSSE v2 receipt file, at most 2 MiB; no legacy fallback")
	command.Flags().StringVar(&publicKey, "public-key", "", "Pinned Ed25519 public key as exactly 64 hexadecimal characters")
	command.Flags().StringVar(&expected, "expected-authority", "", "Optional exact signed evaluator URI claim; does not authenticate ownership of the key")
	command.Flags().BoolVar(&outputJSON, "json", false, "Write structured signed/effective assessment and scope to stdout")
	command.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w; use --receipt-file, --public-key, optional --expected-authority and --json (see verify-attested --help)", err)
	})
	return command
}
