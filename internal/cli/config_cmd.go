package cli

import (
	"fmt"
	"time"

	"github.com/ihildy/magnit-vms-cli/internal/keyring"
	"github.com/ihildy/magnit-vms-cli/internal/output"

	"github.com/spf13/cobra"
)

func newConfigCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage CLI config",
	}
	cmd.AddCommand(newConfigSetDefaultEngagementCmd(app))
	cmd.AddCommand(newConfigSetTimezoneCmd(app))
	cmd.AddCommand(newConfigSetCredentialStoreCmd(app))
	return cmd
}

func newConfigSetDefaultEngagementCmd(app *App) *cobra.Command {
	var engagementID int64
	cmd := &cobra.Command{
		Use:   "set-default-engagement --id <engagement_id>",
		Short: "Set default engagement ID",
		RunE: func(cmd *cobra.Command, args []string) error {
			if engagementID <= 0 {
				return fmt.Errorf("--id must be > 0")
			}
			app.Cfg.DefaultEngagementID = engagementID
			if err := app.SaveConfig(); err != nil {
				return err
			}
			payload := map[string]any{"ok": true, "operation": "config_set_default_engagement", "default_engagement_id": engagementID, "config_path": app.CfgPath}
			human := fmt.Sprintf("Default engagement set to %d", engagementID)
			return output.Write(app.Stdout, app.JSONOutput, human, payload)
		},
	}
	cmd.Flags().Int64Var(&engagementID, "id", 0, "Engagement ID")
	_ = cmd.MarkFlagRequired("id")
	return cmd
}

func newConfigSetTimezoneCmd(app *App) *cobra.Command {
	var timezone string
	cmd := &cobra.Command{
		Use:   "set-timezone --tz <iana_timezone>",
		Short: "Set default timezone for date/week calculations",
		RunE: func(cmd *cobra.Command, args []string) error {
			if timezone == "" {
				return fmt.Errorf("--tz is required")
			}
			if _, err := time.LoadLocation(timezone); err != nil {
				return fmt.Errorf("invalid timezone %q: %w", timezone, err)
			}
			app.Cfg.Timezone = timezone
			if err := app.SaveConfig(); err != nil {
				return err
			}
			payload := map[string]any{"ok": true, "operation": "config_set_timezone", "timezone": timezone, "config_path": app.CfgPath}
			human := fmt.Sprintf("Timezone set to %s", timezone)
			return output.Write(app.Stdout, app.JSONOutput, human, payload)
		},
	}
	cmd.Flags().StringVar(&timezone, "tz", "", "IANA timezone, e.g. America/Los_Angeles")
	_ = cmd.MarkFlagRequired("tz")
	return cmd
}

func newConfigSetCredentialStoreCmd(app *App) *cobra.Command {
	var store string
	cmd := &cobra.Command{
		Use:   "set-credential-store --store <auto|keyring|file>",
		Short: "Set credential storage backend",
		RunE: func(cmd *cobra.Command, args []string) error {
			store = keyring.NormalizeCredentialStore(store)
			if err := keyring.ValidateCredentialStore(store); err != nil {
				return err
			}
			app.Cfg.CredentialStore = store
			if err := app.SaveConfig(); err != nil {
				return err
			}
			payload := map[string]any{"ok": true, "operation": "config_set_credential_store", "credential_store": store, "config_path": app.CfgPath}
			human := fmt.Sprintf("Credential store set to %s", store)
			return output.Write(app.Stdout, app.JSONOutput, human, payload)
		},
	}
	cmd.Flags().StringVar(&store, "store", keyring.StoreAuto, "Credential store backend: auto, keyring, file")
	_ = cmd.MarkFlagRequired("store")
	return cmd
}
