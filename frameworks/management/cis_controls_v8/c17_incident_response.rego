package cis_controls_v8.c17

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 17:
# Incident Response Management. Official IDs, titles, and IG levels.
safeguards := {
	"17.1": {"ig": 1, "title": "Designate Personnel to Manage Incident Handling"},
	"17.2": {"ig": 1, "title": "Establish and Maintain Contact Information for Reporting Security Incidents"},
	"17.3": {"ig": 1, "title": "Establish and Maintain an Enterprise Process for Reporting Incidents"},
	"17.4": {"ig": 2, "title": "Establish and Maintain an Incident Response Process"},
	"17.5": {"ig": 2, "title": "Assign Key Roles and Responsibilities"},
	"17.6": {"ig": 2, "title": "Define Mechanisms for Communicating During Incident Response"},
	"17.7": {"ig": 2, "title": "Conduct Routine Incident Response Exercises"},
	"17.8": {"ig": 2, "title": "Conduct Post-Incident Reviews"},
	"17.9": {"ig": 3, "title": "Establish and Maintain Security Incident Thresholds"},
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
	"control": 17,
	"name": "Incident Response Management",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
