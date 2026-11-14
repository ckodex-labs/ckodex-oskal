package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ckodex-labs/ckodex-oskal/core/assurance"
	"github.com/ckodex-labs/ckodex-oskal/internal/adapters/tetragonhealth"
	"github.com/ckodex-labs/ckodex-oskal/internal/demos/guestproducer"
	"github.com/spf13/cobra"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	code := 1
	var path string
	var outputJSON bool
	command := &cobra.Command{Use: "oskal-sensor", Short: "Send signed security observations from this runtime", Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true}
	command.CompletionOptions.DisableDefaultCmd = true
	command.Flags().StringVar(&path, "config", "", "Explicit outside-owned source configuration (private JSON, at most 256 KiB)")
	command.Flags().BoolVar(&outputJSON, "json", false, "Write final source status as JSON on stdout")
	command.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fmt.Errorf("%w; use --config and optional --json (see --help)", err)
	})
	command.RunE = func(cmd *cobra.Command, _ []string) error {
		if path == "" {
			return fmt.Errorf("--config is required; obtain the outside supervisor's enrolled source configuration")
		}
		config, err := guestproducer.Load(path)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(cmd.ErrOrStderr(), "Connecting with configured root policy: %s. Attestation is not yet verified.\n", config.Enrollment.RootLabel); err != nil {
			return err
		}
		status, runErr := guestproducer.Run(cmd.Context(), config)
		if outputJSON {
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(status); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Source assessment: %s\nReason: %s\n", status.State, status.Reason); err != nil {
			return err
		}
		if len(status.SignedReceipt) == 0 {
			if runErr != nil {
				return fmt.Errorf("no verified receipt was received; inspect the source, signed grant and verifier: %w", runErr)
			}
			return fmt.Errorf("no verified receipt was received; inspect the source, signed grant and verifier before retrying")
		}
		switch status.State {
		case assurance.AssuranceStateVerified, assurance.AssuranceStateAssured:
			code = 0
		case assurance.AssuranceStateFailed:
			code = 3
		default:
			code = 2
		}
		if runErr != nil {
			_, _ = fmt.Fprintln(cmd.ErrOrStderr(), runErr)
		}
		return nil
	}
	command.AddCommand(&cobra.Command{Use: "credentials", Short: "Show this process's read identity after dropping capabilities", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if err := guestproducer.DropCapabilities(); err != nil {
			return err
		}
		credentials, err := tetragonhealth.CurrentCredentials()
		if err != nil {
			return err
		}
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(credentials); err != nil {
			return err
		}
		code = 0
		return nil
	}})
	if err := command.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
	if command.Flags().Changed("help") {
		return
	}
	os.Exit(code)
}
