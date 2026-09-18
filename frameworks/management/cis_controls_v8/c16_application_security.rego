package cis_controls_v8.c16

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 16:
# Application Software Security. Official IDs, titles, and IG levels.
safeguards := {
	"16.1": {"ig": 2, "title": "Establish and Maintain a Secure Application Development Process"},
	"16.2": {"ig": 2, "title": "Establish and Maintain a Process to Accept and Address Software Vulnerabilities"},
	"16.3": {"ig": 2, "title": "Perform Root Cause Analysis on Security Vulnerabilities"},
	"16.4": {"ig": 2, "title": "Establish and Manage an Inventory of Third-Party Software Components"},
	"16.5": {"ig": 2, "title": "Use Up-to-Date and Trusted Third-Party Software Components"},
	"16.6": {"ig": 2, "title": "Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities"},
	"16.7": {"ig": 2, "title": "Use Standard Hardening Configuration Templates for Application Infrastructure"},
	"16.8": {"ig": 2, "title": "Separate Production and Non-Production Systems"},
	"16.9": {"ig": 2, "title": "Train Developers in Application Security Concepts and Secure Coding"},
	"16.10": {"ig": 2, "title": "Apply Secure Design Principles in Application Architectures"},
	"16.11": {"ig": 2, "title": "Leverage Vetted Modules or Services for Application Security Components"},
	"16.12": {"ig": 3, "title": "Implement Code-Level Security Checks"},
	"16.13": {"ig": 3, "title": "Conduct Application Penetration Testing"},
	"16.14": {"ig": 3, "title": "Conduct Threat Modeling"},
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
	"control": 16,
	"name": "Application Software Security",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
