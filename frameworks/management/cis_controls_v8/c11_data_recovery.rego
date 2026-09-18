package cis_controls_v8.c11

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 11:
# Data Recovery.
safeguards := {
	"11.1": {"ig": 1, "title": "Establish and Maintain a Data Recovery Process"},
	"11.2": {"ig": 1, "title": "Perform Automated Backups"},
	"11.3": {"ig": 1, "title": "Protect Recovery Data"},
	"11.4": {"ig": 1, "title": "Establish and Maintain an Isolated Instance of Recovery Data"},
	"11.5": {"ig": 2, "title": "Test Data Recovery"},
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
	"control": 11,
	"name": "Data Recovery",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
