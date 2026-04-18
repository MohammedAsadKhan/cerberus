package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func printBanner() {
	color.Cyan(`
  ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗███████╗
 ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝
 ██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║███████╗
 ██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║╚════██║
 ╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝███████║
  ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
`)
	color.White("  Password Policy Auditor & Strength Analyzer")
	color.HiBlack("  Benchmarked against NIST SP 800-63B\n")
}

var rootCmd = &cobra.Command{
	Use:   "cerberus",
	Short: "Password Policy Auditor & Strength Analyzer",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		printBanner()
	},
	Run: func(cmd *cobra.Command, args []string) {
		color.Cyan("  Use one of the three heads:\n")
		color.Green("    cerberus audit  --min-length 12 --expiry-days 90 --complexity")
		color.Green("    cerberus check  'MyP@ssw0rd!' --hibp")
		color.Green("    cerberus bulk   passwords.csv --output report.pdf\n")
		fmt.Println("  Run cerberus --help for full usage.\n")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
