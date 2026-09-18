package cis_controls_v8.c08

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 8:
# Audit Log Management. Official IDs, titles, and IG levels.
safeguards := {
	"8.1": {"ig": 1, "title": "Establish and Maintain an Audit Log Management Process"},
	"8.2": {"ig": 1, "title": "Collect Audit Logs"},
	"8.3": {"ig": 1, "title": "Ensure Adequate Audit Log Storage"},
	"8.4": {"ig": 2, "title": "Standardize Time Synchronization"},
	"8.5": {"ig": 2, "title": "Collect Detailed Audit Logs"},
	"8.6": {"ig": 2, "title": "Collect DNS Query Audit Logs"},
	"8.7": {"ig": 2, "title": "Collect URL Request Audit Logs"},
	"8.8": {"ig": 2, "title": "Collect Command-Line Audit Logs"},
	"8.9": {"ig": 2, "title": "Centralize Audit Logs"},
	"8.10": {"ig": 2, "title": "Retain Audit Logs"},
	"8.11": {"ig": 2, "title": "Conduct Audit Log Reviews"},
	"8.12": {"ig": 3, "title": "Collect Service Provider Logs"},
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
	"control": 8,
	"name": "Audit Log Management",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
