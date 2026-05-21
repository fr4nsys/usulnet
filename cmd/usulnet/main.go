// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/fr4nsys/usulnet/internal/app"
)

var (
	cfgFile string
	mode    string
)

var rootCmd = &cobra.Command{
	Use:   "usulnet",
	Short: "Docker Management Platform",
	Long:  `usulnet is a self-hosted Docker management platform with security scoring, centralized config, and NPM integration.`,
	// SilenceUsage stops cobra from dumping the full help text after a RunE
	// error (operators just want the error line). SilenceErrors stops cobra
	// from printing "Error: ..." itself so the main() error handler can format
	// the line on stderr without duplication.
	SilenceUsage:  true,
	SilenceErrors: true,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the usulnet server",
	Long: `Start the usulnet server in the specified mode.

Modes:
  standalone — single Docker host, all services local (default)
  master     — standalone + NATS gateway for remote agents
  agent      — connects to a master over NATS; no web UI

The server listens on the address from the loaded config (HTTP 8080,
HTTPS 7443 by default) until SIGINT/SIGTERM.`,
	Example: `  usulnet serve
  usulnet serve --mode master
  usulnet serve --config /etc/usulnet/config.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return app.Run(cfgFile, mode)
	},
}

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Apply, roll back, or inspect database migrations",
	Long: `Manage the PostgreSQL schema. The migrate subtree wraps the
goose-style migration runner used at server boot.

  up      apply every pending migration (idempotent)
  down N  roll back the last N migrations (default 1)
  status  print one line per migration with applied/pending state

Use ` + "`usulnet migrate status`" + ` to inspect a deploy before
running ` + "`up`" + `, and reach for ` + "`down`" + ` only when you have a
verified backup — rollbacks are not always reversible.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Run all pending migrations",
	Long: `Apply every migration not yet recorded in schema_migrations.

Idempotent — already-applied migrations are skipped. Safe to run on
every deploy.`,
	Example: `  usulnet migrate up
  usulnet migrate up --config /etc/usulnet/config.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return app.RunMigrations(cfgFile, "up")
	},
}

var migrateDownCmd = &cobra.Command{
	Use:   "down [N]",
	Short: "Rollback the last N migrations (default: 1)",
	Long: `Roll back the last N migrations (default 1) by running the
matching .down.sql files in reverse order.

Use with care on production — rollbacks are not always reversible
and may discard data.`,
	Example: `  usulnet migrate down
  usulnet migrate down 3`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		steps := "1"
		if len(args) > 0 {
			steps = args[0]
		}
		return app.RunMigrations(cfgFile, "down:"+steps)
	},
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show migration status",
	Long: `Print one line per migration with its current status
(applied / pending) and applied_at timestamp.

Useful for sanity-checking a deploy or diagnosing a stuck environment.`,
	Example: `  usulnet migrate status`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return app.RunMigrations(cfgFile, "status")
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long: `Print the usulnet version, build commit, build time, Go
version, and OS/Arch.

Values are populated from -ldflags at build time; a "dev" version
indicates a local go run / go build without ldflags set.`,
	Example: `  usulnet version`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return app.PrintVersion()
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Validate or inspect the resolved configuration",
	Long: `Inspect the configuration usulnet would load at startup. Useful
for diagnosing missing required fields, env-var overrides, and
secret masking before a deploy.

  check   parse the config file and fail if a required field is missing
  show    print the resolved configuration with secrets masked

Both subcommands honour the global --config flag and the same
defaults the server uses (/etc/usulnet/config.yaml, ./config.yaml).`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var configCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Validate configuration file",
	Long: `Load the configuration from --config (or the default paths:
/etc/usulnet/config.yaml, ./config.yaml) and run validation.

Exits 0 if the file parses and every required field is set;
non-zero otherwise. Use before deploying a config change.`,
	Example: `  usulnet config check
  usulnet config check --config /etc/usulnet/config.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := app.LoadConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("configuration error: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("validation error: %w", err)
		}
		infof(cmd, "Configuration is valid\n")
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration (sensitive values masked)",
	Long: `Print the resolved configuration with secrets masked.

Useful for debugging environment overrides — every USULNET_* env
var that maps to a config field is reflected in the output.`,
	Example: `  usulnet config show
  usulnet config show --config /etc/usulnet/config.yaml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := app.LoadConfig(cfgFile)
		if err != nil {
			return err
		}
		cfg.PrintMasked()
		return nil
	},
}

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Recover or manage the local admin account",
	Long: `Out-of-band administration for the local 'admin' account.
Operates directly on the database, so it works even when the web UI
cannot reach the auth backend (locked-out account, forgotten
password, or fresh install before login).

  reset-password [NEW_PASSWORD]  rotate the admin password (or create
                                 the admin user if it does not exist)

The command unlocks the account, clears any active lockout, and
disables TOTP so a recovered admin can log in without their 2FA
device.`,
	Args: cobra.NoArgs,
	Run:  func(cmd *cobra.Command, args []string) { _ = cmd.Help() },
}

var adminResetPasswordCmd = &cobra.Command{
	Use:   "reset-password [NEW_PASSWORD]",
	Short: "Reset admin user password (or create admin if missing)",
	Long: `Reset the password for the 'admin' user.

If the admin user doesn't exist it is created. The account is also
unlocked if it had been locked due to failed login attempts.

If no password is provided, defaults to 'usulnet'. Password must be
at least 8 characters.`,
	Example: `  usulnet admin reset-password
  usulnet admin reset-password 'MyNewPass123'
  docker exec usulnet-app /app/usulnet admin reset-password 'MyNewPass123'`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		password := "usulnet"
		if len(args) > 0 {
			password = args[0]
		}
		if len(password) < 8 {
			return fmt.Errorf("password must be at least 8 characters")
		}
		return app.ResetAdminPassword(cfgFile, password)
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path (default: /etc/usulnet/config.yaml or ./config.yaml)")

	// Serve flags
	serveCmd.Flags().StringVarP(&mode, "mode", "m", "standalone", "operation mode: standalone|master|agent")
	serveCmd.Flags().String("component", "", "component to run: api|gateway|scheduler (master mode only)")

	// Shell completion for the enum flags above. Errors here would only
	// surface during init at process start, so the registration calls
	// are wrapped with a panic to ensure typos in flag names are caught
	// by the leaf-contract test suite (TestCommandTree_*).
	mustRegisterFlagCompletion(serveCmd, "mode",
		cobra.FixedCompletions(completeServeModes, cobra.ShellCompDirectiveNoFileComp))
	mustRegisterFlagCompletion(serveCmd, "component",
		cobra.FixedCompletions(completeServeComponents, cobra.ShellCompDirectiveNoFileComp))

	// Build command tree
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)

	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	rootCmd.AddCommand(migrateCmd)

	configCmd.AddCommand(configCheckCmd)
	configCmd.AddCommand(configShowCmd)
	rootCmd.AddCommand(configCmd)

	adminCmd.AddCommand(adminResetPasswordCmd)
	rootCmd.AddCommand(adminCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, formatError(err))
		if code, ok := metaExitCode(err); ok {
			os.Exit(code)
		}
		os.Exit(1)
	}
}
