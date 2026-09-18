package cis_controls_v8.c14

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 14:
# Security Awareness and Skills Training.
safeguards := {
	"14.1": {"ig": 1, "title": "Establish and Maintain a Security Awareness Program"},
	"14.2": {"ig": 1, "title": "Train Workforce Members to Recognize Social Engineering Attacks"},
	"14.3": {"ig": 1, "title": "Train Workforce Members on Authentication Best Practices"},
	"14.4": {"ig": 1, "title": "Train Workforce on Data Handling Best Practices"},
	"14.5": {"ig": 1, "title": "Train Workforce Members on Causes of Unintentional Data Exposure"},
	"14.6": {"ig": 1, "title": "Train Workforce Members on Recognizing and Reporting Security Incidents"},
	"14.7": {"ig": 1, "title": "Train Workforce on How to Identify and Report if Their Enterprise Assets are Missing Security Updates"},
	"14.8": {"ig": 1, "title": "Train Workforce on the Dangers of Connecting to and Transmitting Enterprise Data Over Insecure Networks"},
	"14.9": {"ig": 2, "title": "Conduct Role-Specific Security Awareness and Skills Training"},
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
	"control": 14,
	"name": "Security Awareness and Skills Training",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
