package cmd

import (
	"fmt"

	"github.com/YOUR_USERNAME/cerberus/internal/policy"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit a password policy against NIST SP 800-63B",
	Long:  `Evaluate your organization's password policy and score it against NIST SP 800-63B guidelines.`,
	Run: func(cmd *cobra.Command, args []string) {
		minLen, _ := cmd.Flags().GetInt("min-length")
		maxLen, _ := cmd.Flags().GetInt("max-length")
		expiry, _ := cmd.Flags().GetInt("expiry-days")
		complexity, _ := cmd.Flags().GetBool("complexity")
		hibpCheck, _ := cmd.Flags().GetBool("hibp-check")
		mfa, _ := cmd.Flags().GetBool("mfa")

		p := policy.Policy{
			MinLength:          minLen,
			MaxLength:          maxLen,
			ExpiryDays:         expiry,
			ComplexityRequired: complexity,
			HIBPCheckEnabled:   hibpCheck,
			MFAEnabled:         mfa,
		}

		result := policy.Audit(p)

		color.Cyan("\n╔══════════════════════════════════════════╗")
		color.Cyan("║     CERBERUS — NIST SP 800-63B AUDIT     ║")
		color.Cyan("╚══════════════════════════════════════════╝\n")

		for _, finding := range result.Findings {
			if finding.Pass {
				color.Green("  ✔  %s", finding.Rule)
			} else {
				color.Red("  ✘  %s", finding.Rule)
				color.Yellow("       → %s", finding.Recommendation)
				if finding.BreachStat != "" {
					color.Magenta("       ⚠  %s", finding.BreachStat)
				}
			}
		}

		fmt.Println()

		scoreColor := color.New(color.FgGreen, color.Bold)
		if result.Score < 60 {
			scoreColor = color.New(color.FgRed, color.Bold)
		} else if result.Score < 80 {
			scoreColor = color.New(color.FgYellow, color.Bold)
		}
		scoreColor.Printf("  Overall Score: %d/100\n\n", result.Score)

		if result.Score < 60 {
			color.Red("  VERDICT: This policy would not pass a security audit. Fix the flagged items.")
		} else if result.Score < 80 {
			color.Yellow("  VERDICT: Acceptable, but has gaps a compliance officer would flag.")
		} else {
			color.Green("  VERDICT: Strong policy. Well-aligned with NIST SP 800-63B.")
		}

		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(auditCmd)
	auditCmd.Flags().Int("min-length", 8, "Minimum password length required by the policy")
	auditCmd.Flags().Int("max-length", 0, "Maximum password length (0 = no limit)")
	auditCmd.Flags().Int("expiry-days", 0, "Password expiry period in days (0 = no expiry)")
	auditCmd.Flags().Bool("complexity", false, "Whether complexity rules (uppercase, symbols, etc.) are enforced")
	auditCmd.Flags().Bool("hibp-check", false, "Whether passwords are checked against breach databases")
	auditCmd.Flags().Bool("mfa", false, "Whether MFA is enforced alongside passwords")
}
