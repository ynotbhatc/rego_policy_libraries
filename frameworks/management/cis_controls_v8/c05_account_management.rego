package cis_controls_v8.c05

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 5:
# Account Management.
safeguards := {
	"5.1": {"ig": 1, "title": "Establish and Maintain an Inventory of Accounts"},
	"5.2": {"ig": 1, "title": "Use Unique Passwords"},
	"5.3": {"ig": 1, "title": "Disable Dormant Accounts"},
	"5.4": {"ig": 1, "title": "Restrict Administrator Privileges to Dedicated Administrator Accounts"},
	"5.5": {"ig": 2, "title": "Establish and Maintain an Inventory of Service Accounts"},
	"5.6": {"ig": 2, "title": "Centralize Account Management"},
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
	"control": 5,
	"name": "Account Management",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
