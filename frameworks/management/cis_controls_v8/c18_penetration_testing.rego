package cis_controls_v8.c18

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 18:
# Penetration Testing. Official IDs, titles, and IG levels.
safeguards := {
	"18.1": {"ig": 2, "title": "Establish and Maintain a Penetration Testing Program"},
	"18.2": {"ig": 2, "title": "Perform Periodic External Penetration Tests"},
	"18.3": {"ig": 2, "title": "Remediate Penetration Test Findings"},
	"18.4": {"ig": 3, "title": "Validate Security Measures"},
	"18.5": {"ig": 3, "title": "Perform Periodic Internal Penetration Tests"},
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
	"control": 18,
	"name": "Penetration Testing",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
