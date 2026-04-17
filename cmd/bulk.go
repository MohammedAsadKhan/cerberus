package cmd

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/YOUR_USERNAME/cerberus/internal/report"
	"github.com/YOUR_USERNAME/cerberus/internal/strength"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var bulkCmd = &cobra.Command{
	Use:   "bulk [csv-file]",
	Short: "Audit a CSV of passwords and generate a report",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		csvPath := args[0]
		output, _ := cmd.Flags().GetString("output")
		hibp, _ := cmd.Flags().GetBool("hibp")

		f, err := os.Open(csvPath)
		if err != nil {
			color.Red("\n  Error opening CSV: %s\n", err.Error())
			os.Exit(1)
		}
		defer f.Close()

		reader := csv.NewReader(f)
		records, err := reader.ReadAll()
		if err != nil {
			color.Red("\n  Error reading CSV: %s\n", err.Error())
			os.Exit(1)
		}

		color.Cyan("\n╔══════════════════════════════════════════╗")
		color.Cyan("║      CERBERUS — BULK PASSWORD AUDIT      ║")
		color.Cyan("╚══════════════════════════════════════════╝\n")

		var results []report.PasswordRow

		for i, record := range records {
			if len(record) == 0 {
				continue
			}
			password := record[0]
			result := strength.Check(password)

			pwnedCount := 0
			if hibp {
				pwnedCount, _ = strength.CheckHIBP(password)
			}

			row := report.PasswordRow{
				Index:      i + 1,
				Password:   password,
				Score:      result.Score,
				Label:      result.Label,
				CrackTime:  result.CrackTime,
				PwnedCount: pwnedCount,
			}
			results = append(results, row)

			indicator := color.GreenString("✔")
			if result.Score < 50 {
				indicator = color.RedString("✘")
			} else if result.Score < 75 {
				indicator = color.YellowString("~")
			}

			fmt.Printf("  %s  [%02d] %-30s %-10s %s\n",
				indicator, i+1, password, result.Label, result.CrackTime)
		}

		fmt.Printf("\n  Processed %d passwords.\n", len(results))

		// Summary counts
		weak, fair, strong, pwned := 0, 0, 0, 0
		for _, r := range results {
			switch r.Label {
			case "Weak":
				weak++
			case "Fair":
				fair++
			case "Strong", "Excellent":
				strong++
			}
			if r.PwnedCount > 0 {
				pwned++
			}
		}

		fmt.Println()
		color.Red("  Weak:             %d", weak)
		color.Yellow("  Fair:             %d", fair)
		color.Green("  Strong/Excellent: %d", strong)
		if hibp {
			color.Magenta("  Found in breaches: %d", pwned)
		}

		if output != "" {
			fmt.Printf("\n  Generating PDF report...")
			err := report.GeneratePDF(results, output)
			if err != nil {
				color.Red("\n  PDF error: %s\n", err.Error())
			} else {
				color.Green("\n  Report saved to: %s\n", output)
			}
		}

		fmt.Println()
	},
}

func init() {
	rootCmd.AddCommand(bulkCmd)
	bulkCmd.Flags().StringP("output", "o", "", "Output PDF file path (e.g. report.pdf)")
	bulkCmd.Flags().Bool("hibp", false, "Check each password against HaveIBeenPwned API")
}
