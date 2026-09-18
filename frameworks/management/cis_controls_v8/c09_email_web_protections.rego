package cis_controls_v8.c09

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 9:
# Email and Web Browser Protections. Official IDs, titles, and IG levels.
safeguards := {
	"9.1": {"ig": 1, "title": "Ensure Use of Only Fully Supported Browsers and Email Clients"},
	"9.2": {"ig": 1, "title": "Use DNS Filtering Services"},
	"9.3": {"ig": 2, "title": "Maintain and Enforce Network-Based URL Filters"},
	"9.4": {"ig": 2, "title": "Restrict Unnecessary or Unauthorized Browser and Email Client Extensions"},
	"9.5": {"ig": 2, "title": "Implement DMARC"},
	"9.6": {"ig": 2, "title": "Block Unnecessary File Types"},
	"9.7": {"ig": 3, "title": "Deploy and Maintain Email Server Anti-Malware Protections"},
}

attested(id) if input.cis_controls.safeguards[id] == true

# Fail closed: an unattested (absent or non-true) safeguard is a violation.
violation contains msg if {
	some id, m in safeguards
	not attested(id)
	msg := sprintf("CIS Controls v8 %s (IG%d): %s — not implemented", [id, m.ig, m.title])
}

default control_compliant := false

control_compliant if count(violation) == 0

compliance_report := {
	"control": 9,
	"name": "Email and Web Browser Protections",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
