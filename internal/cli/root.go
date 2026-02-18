package cli

import (
	"fmt"

	"github.com/ihildy/magnit-vms-cli/internal/keyring"
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	app := NewApp()

	cmd := &cobra.Command{
		Use:           "magnit",
		Short:         "Log work hours to the Pro Unlimited worker API",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := app.LoadConfig(); err != nil {
				return err
			}
			if app.Cfg.BaseURL == "" {
				return fmt.Errorf("base URL is not configured")
			}
			if err := keyring.ValidateCredentialStore(app.CredentialStore()); err != nil {
				return err
			}
			return nil
		},
	}

	cmd.PersistentFlags().BoolVar(&app.JSONOutput, "json", false, "Emit machine-readable JSON output")
	cmd.PersistentFlags().StringVar(&app.BaseURLOverride, "base-url", "", "Override API base URL")

	cmd.AddCommand(newAuthCmd(app))
	cmd.AddCommand(newEngagementCmd(app))
	cmd.AddCommand(newConfigCmd(app))
	cmd.AddCommand(newShowCmd(app))
	cmd.AddCommand(newSetCmd(app))
	cmd.AddCommand(newMarkDNWCmd(app))

	return cmd
}
