package cis_controls_v8.c06

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 6:
# Access Control Management.
safeguards := {
	"6.1": {"ig": 1, "title": "Establish an Access Granting Process"},
	"6.2": {"ig": 1, "title": "Establish an Access Revoking Process"},
	"6.3": {"ig": 1, "title": "Require MFA for Externally-Exposed Applications"},
	"6.4": {"ig": 1, "title": "Require MFA for Remote Network Access"},
	"6.5": {"ig": 1, "title": "Require MFA for Administrative Access"},
	"6.6": {"ig": 2, "title": "Establish and Maintain an Inventory of Authentication and Authorization Systems"},
	"6.7": {"ig": 2, "title": "Centralize Access Control"},
	"6.8": {"ig": 3, "title": "Define and Maintain Role-Based Access Control"},
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
	"control": 6,
	"name": "Access Control Management",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
