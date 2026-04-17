package cmd

import (
	"fmt"

	"github.com/YOUR_USERNAME/cerberus/internal/strength"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check [password]",
	Short: "Check the strength of a single password",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		password := args[0]
		hibp, _ := cmd.Flags().GetBool("hibp")

		result := strength.Check(password)

		color.Cyan("\n╔══════════════════════════════════════════╗")
		color.Cyan("║        CERBERUS — PASSWORD CHECK         ║")
		color.Cyan("╚══════════════════════════════════════════╝\n")

		fmt.Printf("  Password:    %s\n", password)
		fmt.Printf("  Length:      %d characters\n", len(password))
		fmt.Printf("  Entropy:     %.2f bits\n", result.Entropy)
		fmt.Printf("  Crack Time:  %s\n", result.CrackTime)
		fmt.Println()

		for _, check := range result.Checks {
			if check.Pass {
				color.Green("  ✔  %s", check.Label)
			} else {
				color.Red("  ✘  %s", check.Label)
			}
		}

		fmt.Println()

		strengthLabel := map[string]*color.Color{
			"Weak":      color.New(color.FgRed, color.Bold),
			"Fair":      color.New(color.FgYellow, color.Bold),
			"Strong":    color.New(color.FgGreen, color.Bold),
			"Excellent": color.New(color.FgCyan, color.Bold),
		}
		if c, ok := strengthLabel[result.Label]; ok {
			c.Printf("  Strength: %s\n\n", result.Label)
		}

		if hibp {
			fmt.Print("  Checking HaveIBeenPwned... ")
			count, err := strength.CheckHIBP(password)
			if err != nil {
				color.Yellow("(unavailable: %s)\n", err.Error())
			} else if count > 0 {
				color.Red("PWNED — found in %d breach records!\n", count)
			} else {
				color.Green("Not found in breach data.\n")
			}
		}

		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.Flags().Bool("hibp", false, "Check password against HaveIBeenPwned API")
}
