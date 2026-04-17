package policy

// NISTRule represents a single NIST SP 800-63B guideline
type NISTRule struct {
	ID             string
	Description    string
	Recommendation string
	BreachStat     string
	Weight         int // contribution to overall score out of 100
}

// NISTRules is the full database of rules Cerberus audits against
var NISTRules = []NISTRule{
	{
		ID:             "MIN_LENGTH",
		Description:    "Minimum password length of at least 15 characters (NIST recommends 15+)",
		Recommendation: "Set minimum length to 15+ characters. Length is the single most impactful password security control.",
		BreachStat:     "81% of hacking-related breaches involve weak or stolen passwords (Verizon DBIR).",
		Weight:         20,
	},
	{
		ID:             "MAX_LENGTH",
		Description:    "Maximum password length of at least 64 characters (NIST mandates no low maximum)",
		Recommendation: "Set max length to at least 64 characters. Truncating passwords forces users toward weaker options.",
		BreachStat:     "",
		Weight:         10,
	},
	{
		ID:             "NO_EXPIRY",
		Description:    "No arbitrary password expiry (NIST SP 800-63B §5.1.1.2 discourages forced rotation)",
		Recommendation: "Remove periodic expiry. Forced rotation leads to predictable patterns like Password1 → Password2.",
		BreachStat:     "Forced password changes increase reuse by up to 41% (UNC Chapel Hill study).",
		Weight:         15,
	},
	{
		ID:             "NO_COMPLEXITY",
		Description:    "No mandatory complexity rules (NIST discourages arbitrary character-class requirements)",
		Recommendation: "Drop character-class mandates. They cause users to create predictable substitutions like P@ssw0rd!",
		BreachStat:     "Complexity rules are among the top causes of weak-but-technically-compliant passwords.",
		Weight:         10,
	},
	{
		ID:             "HIBP_CHECK",
		Description:    "Passwords checked against known breach databases (NIST §5.1.1.2)",
		Recommendation: "Integrate HaveIBeenPwned or a similar service to block known-compromised passwords at authentication.",
		BreachStat:     "Over 550 million compromised passwords are publicly searchable. Your users reuse them.",
		Weight:         20,
	},
	{
		ID:             "MFA",
		Description:    "Multi-factor authentication enforced alongside passwords (NIST AAL2)",
		Recommendation: "Mandate MFA. A breached password is game over without a second factor.",
		BreachStat:     "MFA blocks 99.9% of automated account compromise attacks (Microsoft, 2019).",
		Weight:         25,
	},
}
