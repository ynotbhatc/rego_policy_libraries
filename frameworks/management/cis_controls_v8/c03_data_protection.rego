package cis_controls_v8.c03

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 3: Data Protection.
safeguards := {
	"3.1": {"ig": 1, "title": "Establish and Maintain a Data Management Process"},
	"3.2": {"ig": 1, "title": "Establish and Maintain a Data Inventory"},
	"3.3": {"ig": 1, "title": "Configure Data Access Control Lists"},
	"3.4": {"ig": 1, "title": "Enforce Data Retention"},
	"3.5": {"ig": 1, "title": "Securely Dispose of Data"},
	"3.6": {"ig": 1, "title": "Encrypt Data on End-User Devices"},
	"3.7": {"ig": 2, "title": "Establish and Maintain a Data Classification Scheme"},
	"3.8": {"ig": 2, "title": "Document Data Flows"},
	"3.9": {"ig": 2, "title": "Encrypt Data on Removable Media"},
	"3.10": {"ig": 2, "title": "Encrypt Sensitive Data in Transit"},
	"3.11": {"ig": 2, "title": "Encrypt Sensitive Data at Rest"},
	"3.12": {"ig": 2, "title": "Segment Data Processing and Storage Based on Sensitivity"},
	"3.13": {"ig": 3, "title": "Deploy a Data Loss Prevention Solution"},
	"3.14": {"ig": 3, "title": "Log Sensitive Data Access"},
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
	"control": 3,
	"name": "Data Protection",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
