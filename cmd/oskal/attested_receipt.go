package main

import (
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
		Use:   "verify-attested",
		Short: "Check a saved security result using a public key you trust",
		Args: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceErrors = false
			return cobra.NoArgs(cmd, args)
		},
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
			if err := validateReceiptKeyInput(publicKey); err != nil {
				return err
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
			key, err := readReceiptPublicKey(publicKey)
			if err != nil {
				return err
			}
			raw, err := readBoundedFile(path, 2<<20)
			if err != nil {
				return fmt.Errorf("read attested receipt (maximum 2 MiB): %w", err)
			}
			result, err := receipts.VerifyAttestedReceipt(cmd.Context(), raw, key, authority, time.Now().UTC())
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
			code, message := 0, "attested receipt signature valid; supplied assessment is currently positive"
			switch result.EffectiveState {
			case assurance.AssuranceStateVerified, assurance.AssuranceStateAssured:
			case assurance.AssuranceStateFailed:
				code, message = 3, "attested receipt signature valid; signed assessment is FAILED"
			default:
				code, message = 2, "attested receipt signature valid; effective assessment is UNKNOWN or incomplete"
			}
			if _, err := fmt.Fprintln(cmd.ErrOrStderr(), message); err != nil {
				return err
			}
			if code == 0 {
				return nil
			}
			// A valid negative/incomplete assessment is not an execution error.
			cmd.SilenceErrors = true
			return &evaluationResultError{code: code, message: message}
		},
	}
	command.Flags().StringVar(&path, "receipt-file", "", "Explicit full-body DSSE v2 receipt file, at most 2 MiB; no legacy fallback")
	command.Flags().StringVar(&publicKey, "public-key", "", "Pinned Ed25519 public key hex or explicit path to a hex key file (at most 4 KiB)")
	command.Flags().StringVar(&expected, "expected-authority", "", "Optional exact signed evaluator URI claim; does not authenticate ownership of the key")
	command.Flags().BoolVar(&outputJSON, "json", false, "Write structured signed/effective assessment and scope to stdout")
	command.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		cmd.SilenceErrors = false
		return fmt.Errorf("%w; use --receipt-file, --public-key, optional --expected-authority and --json (see verify-attested --help)", err)
	})
	command.SetUsageTemplate("Usage:\n  {{.UseLine}}\n\nFlags:\n{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}\n")
	return command
}
