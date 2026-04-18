package report

import (
	"fmt"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// PasswordRow holds the audit result for a single password from a bulk run
type PasswordRow struct {
	Index      int
	Password   string
	Score      int
	Label      string
	CrackTime  string
	PwnedCount int
}

// GeneratePDF produces a professional audit report from a bulk password audit
// and writes it to the specified output path.
func GeneratePDF(rows []PasswordRow, outputPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("Cerberus Password Audit Report", false)
	pdf.SetAuthor("Cerberus CLI", false)
	pdf.SetCreator("Cerberus — NIST SP 800-63B Password Auditor", false)
	pdf.SetMargins(15, 15, 15)
	pdf.AddPage()

	// ── Cover header ─────────────────────────────────────────────────────────
	pdf.SetFillColor(18, 18, 18)
	pdf.Rect(0, 0, 210, 38, "F")

	pdf.SetFont("Arial", "B", 22)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetXY(15, 10)
	pdf.CellFormat(180, 10, "Cerberus — Password Audit Report", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(180, 180, 180)
	pdf.SetX(15)
	pdf.CellFormat(180, 6, "NIST SP 800-63B Compliance Assessment", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 8)
	pdf.SetX(15)
	pdf.CellFormat(180, 6,
		fmt.Sprintf("Generated: %s", time.Now().Format("Monday, January 2, 2006 at 15:04 UTC")),
		"", 1, "C", false, 0, "")

	pdf.SetTextColor(30, 30, 30)
	pdf.SetY(44)

	// ── Summary statistics ────────────────────────────────────────────────────
	weak, fair, strong, excellent, pwned := 0, 0, 0, 0, 0
	for _, r := range rows {
		switch r.Label {
		case "Weak":
			weak++
		case "Fair":
			fair++
		case "Strong":
			strong++
		case "Excellent":
			excellent++
		}
		if r.PwnedCount > 0 {
			pwned++
		}
	}
	total := len(rows)

	// Summary box background
	pdf.SetFillColor(245, 245, 245)
	pdf.RoundedRect(15, pdf.GetY(), 180, 42, 3, "1234", "F")

	pdf.SetFont("Arial", "B", 11)
	pdf.SetTextColor(30, 30, 30)
	pdf.SetXY(20, pdf.GetY()+4)
	pdf.CellFormat(170, 7, "Executive Summary", "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 9)
	pdf.SetX(20)
	pdf.CellFormat(170, 6,
		fmt.Sprintf("Total passwords audited: %d", total),
		"", 1, "L", false, 0, "")

	// Summary stat row
	startY := pdf.GetY() + 2
	colW := 42.0

	summaryStats := []struct {
		label string
		value string
		r, g, b int
	}{
		{"Weak", fmt.Sprintf("%d (%.0f%%)", weak, pct(weak, total)), 200, 50, 50},
		{"Fair", fmt.Sprintf("%d (%.0f%%)", fair, pct(fair, total)), 200, 140, 0},
		{"Strong", fmt.Sprintf("%d (%.0f%%)", strong, pct(strong, total)), 50, 150, 50},
		{"Excellent", fmt.Sprintf("%d (%.0f%%)", excellent, pct(excellent, total)), 30, 120, 200},
	}

	for i, stat := range summaryStats {
		x := 20.0 + float64(i)*colW
		pdf.SetXY(x, startY)
		pdf.SetFont("Arial", "B", 9)
		pdf.SetTextColor(stat.r, stat.g, stat.b)
		pdf.CellFormat(colW, 5, stat.label, "", 1, "L", false, 0, "")
		pdf.SetXY(x, startY+5)
		pdf.SetFont("Arial", "", 9)
		pdf.CellFormat(colW, 5, stat.value, "", 0, "L", false, 0, "")
	}

	if pwned > 0 {
		pdf.SetXY(20, startY+12)
		pdf.SetFont("Arial", "B", 9)
		pdf.SetTextColor(180, 30, 30)
		pdf.CellFormat(170, 5,
			fmt.Sprintf("⚠  %d password(s) found in known breach data — immediate remediation required", pwned),
			"", 1, "L", false, 0, "")
	}

	pdf.SetY(pdf.GetY() + 14)

	// ── Table header ──────────────────────────────────────────────────────────
	pdf.SetFont("Arial", "B", 8)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFillColor(18, 18, 18)

	colWidths := []float64{10, 52, 16, 22, 48, 28}
	headers := []string{"#", "Password", "Score", "Strength", "Est. Crack Time", "Breach Count"}

	for i, header := range headers {
		pdf.CellFormat(colWidths[i], 7, header, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)

	// ── Table rows ────────────────────────────────────────────────────────────
	pdf.SetFont("Arial", "", 8)

	for i, row := range rows {
		// Alternate row background
		if i%2 == 0 {
			pdf.SetFillColor(250, 250, 250)
		} else {
			pdf.SetFillColor(240, 240, 240)
		}

		// Strength color
		switch row.Label {
		case "Weak":
			pdf.SetTextColor(180, 30, 30)
		case "Fair":
			pdf.SetTextColor(180, 120, 0)
		case "Strong":
			pdf.SetTextColor(40, 130, 40)
		case "Excellent":
			pdf.SetTextColor(30, 100, 180)
		default:
			pdf.SetTextColor(30, 30, 30)
		}

		pwnedStr := "—"
		if row.PwnedCount > 0 {
			pwnedStr = fmt.Sprintf("%d", row.PwnedCount)
			pdf.SetTextColor(180, 30, 30)
		}

		// Truncate long passwords for display
		displayPwd := row.Password
		if len(displayPwd) > 28 {
			displayPwd = displayPwd[:25] + "..."
		}

		cells := []struct {
			text  string
			width float64
			align string
		}{
			{fmt.Sprintf("%d", row.Index), colWidths[0], "C"},
			{displayPwd, colWidths[1], "L"},
			{fmt.Sprintf("%d", row.Score), colWidths[2], "C"},
			{row.Label, colWidths[3], "C"},
			{row.CrackTime, colWidths[4], "L"},
			{pwnedStr, colWidths[5], "C"},
		}

		for _, cell := range cells {
			pdf.CellFormat(cell.width, 6, cell.text, "1", 0, cell.align, true, 0, "")
		}
		pdf.Ln(-1)

		// Page break if needed
		if pdf.GetY() > 270 {
			pdf.AddPage()
			pdf.SetFont("Arial", "B", 8)
			pdf.SetTextColor(255, 255, 255)
			pdf.SetFillColor(18, 18, 18)
			for i, header := range headers {
				pdf.CellFormat(colWidths[i], 7, header, "1", 0, "C", true, 0, "")
			}
			pdf.Ln(-1)
			pdf.SetFont("Arial", "", 8)
		}
	}

	// ── Recommendations section ───────────────────────────────────────────────
	pdf.Ln(8)
	pdf.SetFont("Arial", "B", 11)
	pdf.SetTextColor(30, 30, 30)
	pdf.CellFormat(180, 7, "Recommendations", "", 1, "L", false, 0, "")

	pdf.SetFont("Arial", "", 9)
	pdf.SetTextColor(60, 60, 60)

	recommendations := buildRecommendations(weak, fair, pwned, total)
	for _, rec := range recommendations {
		pdf.SetX(15)
		pdf.MultiCell(180, 5, rec, "", "L", false)
		pdf.Ln(1)
	}

	// ── Footer ────────────────────────────────────────────────────────────────
	pdf.SetY(-18)
	pdf.SetFont("Arial", "I", 7)
	pdf.SetTextColor(150, 150, 150)
	pdf.CellFormat(0, 5,
		"Cerberus CLI  |  NIST SP 800-63B Password Audit Tool  |  github.com/YOUR_USERNAME/cerberus",
		"", 1, "C", false, 0, "")
	pdf.CellFormat(0, 5,
		"This report is generated from automated analysis. Results should be reviewed by a qualified security professional.",
		"", 1, "C", false, 0, "")

	return pdf.OutputFileAndClose(outputPath)
}

// pct returns a percentage as a float64
func pct(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(part) / float64(total) * 100
}

// buildRecommendations generates contextual recommendations based on audit results
func buildRecommendations(weak, fair, pwned, total int) []string {
	var recs []string

	weakPct := pct(weak, total)
	fairPct := pct(fair, total)

	if pwned > 0 {
		recs = append(recs, fmt.Sprintf(
			"• CRITICAL: %d password(s) were found in known breach databases. These credentials must be reset immediately and users should be notified. Implement HaveIBeenPwned checks at authentication to prevent reuse of compromised passwords.",
			pwned,
		))
	}

	if weakPct > 30 {
		recs = append(recs, fmt.Sprintf(
			"• HIGH: %.0f%% of audited passwords are rated Weak. Enforce a minimum length of 15+ characters per NIST SP 800-63B §5.1.1.1. Consider deploying a password manager organization-wide to reduce reliance on user-generated passwords.",
			weakPct,
		))
	}

	if fairPct > 40 {
		recs = append(recs, fmt.Sprintf(
			"• MEDIUM: %.0f%% of passwords are rated Fair. While technically passable, these passwords represent risk under targeted or hybrid attacks. Educate users on passphrase-based approaches (e.g., correct-horse-battery-staple) which maximize entropy without complexity.",
			fairPct,
		))
	}

	if weakPct <= 10 && pwned == 0 {
		recs = append(recs, "• The audited password set is in good shape. Continue enforcing current policy and maintain breach database checks at authentication.")
	}

	recs = append(recs, "• Regardless of individual password strength, enforcing MFA across all accounts remains the single highest-impact control available. NIST AAL2 compliance requires a second factor.")

	return recs
}
