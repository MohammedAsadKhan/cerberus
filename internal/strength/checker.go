package strength

import (
	"fmt"
	"math"
	"strings"
	"unicode"
)

// CheckItem represents a single pass/fail strength check
type CheckItem struct {
	Label string
	Pass  bool
}

// StrengthResult is the full output of a password strength evaluation
type StrengthResult struct {
	Score     int
	Label     string
	Entropy   float64
	CrackTime string
	Checks    []CheckItem
}

// Check evaluates a single password and returns a full StrengthResult
func Check(password string) StrengthResult {
	var checks []CheckItem
	score := 0

	// ── Length ───────────────────────────────────────────────────────────────
	length := len(password)
	lengthPass := length >= 12
	checks = append(checks, CheckItem{
		Label: fmt.Sprintf("Length ≥ 12 characters (%d)", length),
		Pass:  lengthPass,
	})
	if lengthPass {
		score += 25
		// Bonus for exceptional length
		if length >= 20 {
			score += 10
		}
	}

	// ── Character classes ────────────────────────────────────────────────────
	hasUpper := strings.IndexFunc(password, unicode.IsUpper) >= 0
	hasLower := strings.IndexFunc(password, unicode.IsLower) >= 0
	hasDigit := strings.IndexFunc(password, unicode.IsDigit) >= 0
	hasSpecial := strings.IndexFunc(password, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) >= 0

	checks = append(checks, CheckItem{"Contains uppercase letters", hasUpper})
	checks = append(checks, CheckItem{"Contains lowercase letters", hasLower})
	checks = append(checks, CheckItem{"Contains digits", hasDigit})
	checks = append(checks, CheckItem{"Contains special characters", hasSpecial})

	charClassCount := 0
	if hasUpper {
		charClassCount++
	}
	if hasLower {
		charClassCount++
	}
	if hasDigit {
		charClassCount++
	}
	if hasSpecial {
		charClassCount++
	}
	score += charClassCount * 10

	// ── Common patterns ──────────────────────────────────────────────────────
	lower := strings.ToLower(password)
	commonPatterns := []string{
		"password", "123456", "qwerty", "abc123", "letmein",
		"welcome", "monkey", "dragon", "master", "iloveyou",
		"admin", "login", "pass", "111111", "sunshine",
	}
	hasCommon := false
	for _, pattern := range commonPatterns {
		if strings.Contains(lower, pattern) {
			hasCommon = true
			break
		}
	}
	noCommonPass := !hasCommon
	checks = append(checks, CheckItem{"No common password patterns", noCommonPass})
	if noCommonPass {
		score += 15
	}

	// ── Sequential characters ────────────────────────────────────────────────
	noSequential := !hasSequentialChars(password)
	checks = append(checks, CheckItem{"No sequential characters (abc, 123)", noSequential})
	if noSequential {
		score += 10
	}

	// ── Repeated characters ──────────────────────────────────────────────────
	noRepeated := !hasRepeatedChars(password)
	checks = append(checks, CheckItem{"No repeated character blocks (aaa, 111)", noRepeated})
	if noRepeated {
		score += 5
	}

	// ── Entropy and crack time ───────────────────────────────────────────────
	entropy := calculateEntropy(password)
	crackTime := estimateCrackTime(entropy)

	// ── Cap and label ────────────────────────────────────────────────────────
	if score > 100 {
		score = 100
	}

	label := "Weak"
	switch {
	case score >= 85:
		label = "Excellent"
	case score >= 65:
		label = "Strong"
	case score >= 40:
		label = "Fair"
	}

	return StrengthResult{
		Score:     score,
		Label:     label,
		Entropy:   entropy,
		CrackTime: crackTime,
		Checks:    checks,
	}
}

// calculateEntropy estimates the Shannon entropy of a password
// based on the character set it draws from
func calculateEntropy(password string) float64 {
	charset := 0

	hasLower := strings.IndexFunc(password, unicode.IsLower) >= 0
	hasUpper := strings.IndexFunc(password, unicode.IsUpper) >= 0
	hasDigit := strings.IndexFunc(password, unicode.IsDigit) >= 0
	hasSpecial := strings.IndexFunc(password, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) >= 0

	if hasLower {
		charset += 26
	}
	if hasUpper {
		charset += 26
	}
	if hasDigit {
		charset += 10
	}
	if hasSpecial {
		charset += 32
	}
	if charset == 0 {
		return 0
	}

	return float64(len(password)) * math.Log2(float64(charset))
}

// estimateCrackTime returns a human-readable crack time estimate
// assuming a modern GPU cluster at 10 billion guesses per second
func estimateCrackTime(entropy float64) string {
	const guessesPerSecond = 1e10

	combinations := math.Pow(2, entropy)
	seconds := combinations / guessesPerSecond

	switch {
	case seconds < 1:
		return "Instantly"
	case seconds < 60:
		return fmt.Sprintf("%.0f seconds", seconds)
	case seconds < 3600:
		return fmt.Sprintf("%.0f minutes", seconds/60)
	case seconds < 86400:
		return fmt.Sprintf("%.0f hours", seconds/3600)
	case seconds < 31536000:
		return fmt.Sprintf("%.0f days", seconds/86400)
	case seconds < 3.154e9:
		return fmt.Sprintf("%.0f years", seconds/31536000)
	case seconds < 3.154e12:
		return fmt.Sprintf("%.0f thousand years", seconds/3.154e9)
	case seconds < 3.154e15:
		return fmt.Sprintf("%.0f million years", seconds/3.154e12)
	default:
		return "Centuries (effectively uncrackable)"
	}
}

// hasSequentialChars detects runs of sequential characters (abc, 123, xyz)
func hasSequentialChars(password string) bool {
	const minRun = 3
	runes := []rune(strings.ToLower(password))
	count := 1

	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1]+1 {
			count++
			if count >= minRun {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}

// hasRepeatedChars detects runs of the same character (aaa, 111)
func hasRepeatedChars(password string) bool {
	const minRun = 3
	runes := []rune(password)
	count := 1

	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			count++
			if count >= minRun {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}
