package cis_controls_v8.c13

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 13:
# Network Monitoring and Defense.
safeguards := {
	"13.1": {"ig": 2, "title": "Centralize Security Event Alerting"},
	"13.2": {"ig": 2, "title": "Deploy a Host-Based Intrusion Detection Solution"},
	"13.3": {"ig": 2, "title": "Deploy a Network Intrusion Detection Solution"},
	"13.4": {"ig": 2, "title": "Perform Traffic Filtering Between Network Segments"},
	"13.5": {"ig": 2, "title": "Manage Access Control for Remote Assets"},
	"13.6": {"ig": 2, "title": "Collect Network Traffic Flow Logs"},
	"13.7": {"ig": 3, "title": "Deploy a Host-Based Intrusion Prevention Solution"},
	"13.8": {"ig": 3, "title": "Deploy a Network Intrusion Prevention Solution"},
	"13.9": {"ig": 3, "title": "Deploy Port-Level Access Control"},
	"13.10": {"ig": 3, "title": "Perform Application Layer Filtering"},
	"13.11": {"ig": 3, "title": "Tune Security Event Alerting Thresholds"},
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
	"control": 13,
	"name": "Network Monitoring and Defense",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
