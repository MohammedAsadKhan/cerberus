package policy

import "fmt"

// Policy represents an organization's password policy configuration
type Policy struct {
	MinLength          int
	MaxLength          int  // 0 = no limit
	ExpiryDays         int  // 0 = no expiry
	ComplexityRequired bool
	HIBPCheckEnabled   bool
	MFAEnabled         bool
}

// Finding is the result of evaluating a single NIST rule
type Finding struct {
	Rule           string
	Pass           bool
	Recommendation string
	BreachStat     string
}

// AuditResult is the complete output of a policy audit
type AuditResult struct {
	Score    int
	Findings []Finding
}

// Audit evaluates a Policy against the active NIST SP 800-63B ruleset
// and returns a scored AuditResult with per-rule findings.
func Audit(p Policy) AuditResult {
	var findings []Finding
	totalWeight := 0
	earned := 0

	for _, rule := range ActiveRules {
		totalWeight += rule.Weight
		var pass bool
		var label string

		switch rule.ID {
		case "MIN_LENGTH":
			pass = p.MinLength >= 15
			if pass {
				label = fmt.Sprintf("Min length: %d chars ✓", p.MinLength)
			} else {
				label = fmt.Sprintf("Min length: %d chars (NIST requires 15+)", p.MinLength)
			}

		case "MAX_LENGTH":
			pass = p.MaxLength == 0 || p.MaxLength >= 64
			if p.MaxLength == 0 {
				label = "Max length: No limit ✓"
			} else if pass {
				label = fmt.Sprintf("Max length: %d chars ✓", p.MaxLength)
			} else {
				label = fmt.Sprintf("Max length: %d chars (must be 64+ or unlimited)", p.MaxLength)
			}

		case "NO_EXPIRY":
			pass = p.ExpiryDays == 0
			if pass {
				label = "Password expiry: Disabled ✓"
			} else {
				label = fmt.Sprintf("Password expiry: %d days (NIST says remove forced rotation)", p.ExpiryDays)
			}

		case "NO_COMPLEXITY":
			pass = !p.ComplexityRequired
			if pass {
				label = "Complexity rules: Not enforced ✓"
			} else {
				label = "Complexity rules: Enforced (NIST discourages character-class mandates)"
			}

		case "HIBP_CHECK":
			pass = p.HIBPCheckEnabled
			if pass {
				label = "Breach database check: Enabled ✓"
			} else {
				label = "Breach database check: Disabled"
			}

		case "MFA":
			pass = p.MFAEnabled
			if pass {
				label = "MFA enforced: Yes ✓"
			} else {
				label = "MFA enforced: No"
			}

		default:
			// Unknown rule ID — skip but don't crash
			continue
		}

		if pass {
			earned += rule.Weight
		}

		findings = append(findings, Finding{
			Rule:           label,
			Pass:           pass,
			Recommendation: rule.Recommendation,
			BreachStat:     rule.BreachStat,
		})
	}

	score := 0
	if totalWeight > 0 {
		score = (earned * 100) / totalWeight
	}

	return AuditResult{
		Score:    score,
		Findings: findings,
	}
}
