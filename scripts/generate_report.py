import json
from datetime import datetime

with open("nist_content.json") as f:
    content = json.load(f)

today = datetime.utcnow().strftime("%Y-%m-%d")

report = f"""# NIST SP 800-63B Change Detected

**Date detected:** {today}
**Action required:** Review the changes below and update `rules/nist_rules.json` if the Cerberus ruleset needs to change.

---

## What Changed

A difference was detected in the NIST SP 800-63B page content relevant to password policy.
The sections below were extracted from the live NIST page at the time of detection.

> This is an automated diff. The hash of the relevant sections changed since the last check.
> Manual review is required before any rules are updated.

---

## Extracted Section Content

"""

for section_id, text in content.items():
    report += f"### Section {section_id}\n\n"
    report += f"```\n{text[:2000]}{'...' if len(text) > 2000 else ''}\n```\n\n"

report += """---

## Review Checklist

- [ ] Read the extracted sections above
- [ ] Compare against the current `rules/nist_rules.json`
- [ ] Update any rules that no longer reflect current NIST guidance
- [ ] Increment the `version` field in `nist_rules.json`
- [ ] Update the `last_updated` field
- [ ] Merge this PR to push updates to all users

---

*This PR was opened automatically by the Cerberus NIST Rules Update workflow.*
*The binary's bundled rules are unaffected until a new release is cut.*
"""

with open("NIST_CHANGE_REPORT.md", "w") as f:
    f.write(report)

print("Diff report written to NIST_CHANGE_REPORT.md")
