# 🐕🐕🐕 Cerberus - Password Policy Auditor & Strength Analyzer

> Cerberus - the three-headed guardian of the underworld, destroyer of souls, devourer of the weak...
> ...is a CLI tool that checks if your password policy meets NIST guidelines.
>
> Yeah. That's it. Anticlimax intended.

Much like its namesake, Cerberus has three heads:

* 🐕 **Audit** - tears apart your organization's password policy against NIST SP 800-63B
* 🐕 **Check** - judges your individual passwords with zero mercy
* 🐕 **Bulk** - devours entire CSVs of passwords and spits out a professional audit report

While the name might suggest something terrifying, Cerberus is actually just tired of seeing companies get breached because their IT department thought `Password123!` with a 90-day expiry was secure.

---

## Why This Project Exists

Everyone builds password strength checkers and password savers. Nobody thinks about the business side.

**Weak password *policies* are what actually get companies breached — not individual weak passwords.**

This tool bridges the gap between technical security and GRC (Governance, Risk and Compliance), benchmarking policies against NIST SP 800-63B guidelines and explaining findings in a way that non-technical stakeholders understand.

---

## Why Go

Real security tools ship as binaries, not scripts. Go compiles to a single binary with zero dependencies - drop it on any machine, even air-gapped systems, and run it instantly.

Modern security tools like [Gobuster](https://github.com/OJ/gobuster), [Nuclei](https://github.com/projectdiscovery/nuclei), [Subfinder](https://github.com/projectdiscovery/subfinder), and [Trivy](https://github.com/aquasecurity/trivy) all use Go for exactly this reason.

---

## Features

| Feature | Status |
|---|---|
| Audit password policy against NIST SP 800-63B | ✅ |
| Score policy (0–100%) with detailed breakdown | ✅ |
| Flag weak rules with real breach statistics | ✅ |
| Test individual passwords for strength | ✅ |
| Estimate crack time (brute force + entropy) | ✅ |
| HaveIBeenPwned API integration | ✅ |
| Bulk CSV password audit | ✅ |
| Export professional PDF audit report | ✅ |
| Color-coded CLI output | ✅ |

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/cerberus.git
cd cerberus
go build -o cerberus .
```

---

## Usage

### 🐕 Head 1 - Audit a Password Policy

```bash
cerberus audit \
  --min-length 12 \
  --max-length 128 \
  --expiry-days 90 \
  --complexity \
  --hibp-check \
  --mfa
```

### 🐕 Head 2 - Check a Single Password

```bash
cerberus check "MyP@ssw0rd!" --hibp
```

### 🐕 Head 3 - Bulk Audit via CSV

```bash
cerberus bulk passwords.csv --output report.pdf --hibp
```

CSV format - one password per line:

```
hunter2
correcthorsebatterystaple
P@ssw0rd!
```

---

## NIST SP 800-63B - What Cerberus Checks

| Rule | NIST Guidance | Weight |
|---|---|---|
| Minimum length 15+ | §5.1.1.1 | 20pts |
| No low maximum length | §5.1.1.1 | 10pts |
| No periodic expiry | §5.1.1.2 | 15pts |
| No complexity mandates | §5.1.1.2 | 10pts |
| Breach database check | §5.1.1.2 | 20pts |
| MFA enforced | AAL2 | 25pts |

---

## Stack

- **Go** - single binary, zero dependencies
- **[Cobra](https://github.com/spf13/cobra)** - CLI framework
- **[gofpdf](https://github.com/jung-kurt/gofpdf)** - PDF report generation
- **[color](https://github.com/fatih/color)** - terminal color output
- **[HaveIBeenPwned API](https://haveibeenpwned.com/API/v3)** - k-Anonymity breach lookup (your password is never transmitted in full)

---

## License

MIT