package cis_controls_v8.c02

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 2:
# Inventory and Control of Software Assets.
safeguards := {
	"2.1": {"ig": 1, "title": "Establish and Maintain a Software Inventory"},
	"2.2": {"ig": 1, "title": "Ensure Authorized Software is Currently Supported"},
	"2.3": {"ig": 1, "title": "Address Unauthorized Software"},
	"2.4": {"ig": 2, "title": "Utilize Automated Software Inventory Tools"},
	"2.5": {"ig": 2, "title": "Allowlist Authorized Software"},
	"2.6": {"ig": 2, "title": "Allowlist Authorized Libraries"},
	"2.7": {"ig": 3, "title": "Allowlist Authorized Scripts"},
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
	"control": 2,
	"name": "Inventory and Control of Software Assets",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
