package cis_controls_v8.c15

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 15:
# Service Provider Management.
safeguards := {
	"15.1": {"ig": 1, "title": "Establish and Maintain an Inventory of Service Providers"},
	"15.2": {"ig": 2, "title": "Establish and Maintain a Service Provider Management Policy"},
	"15.3": {"ig": 3, "title": "Classify Service Providers"}, # FIDELITY: unsure — IG2 vs IG3
	"15.4": {"ig": 3, "title": "Ensure Service Provider Contracts Include Security Requirements"},
	"15.5": {"ig": 3, "title": "Assess Service Providers"},
	"15.6": {"ig": 3, "title": "Monitor Service Providers"},
	"15.7": {"ig": 3, "title": "Securely Decommission Service Providers"},
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
	"control": 15,
	"name": "Service Provider Management",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
