package cis_controls_v8.c12

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 12:
# Network Infrastructure Management.
safeguards := {
	"12.1": {"ig": 1, "title": "Ensure Network Infrastructure is Up-to-Date"},
	"12.2": {"ig": 2, "title": "Establish and Maintain a Secure Network Architecture"},
	"12.3": {"ig": 2, "title": "Securely Manage Network Infrastructure"},
	"12.4": {"ig": 2, "title": "Establish and Maintain Architecture Diagram(s)"},
	"12.5": {"ig": 2, "title": "Centralize Network Authentication, Authorization, and Auditing (AAA)"},
	"12.6": {"ig": 2, "title": "Use of Secure Network Management and Communication Protocols"},
	"12.7": {"ig": 2, "title": "Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise's AAA Infrastructure"},
	"12.8": {"ig": 3, "title": "Establish and Maintain Dedicated Computing Resources for All Administrative Work"},
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
	"control": 12,
	"name": "Network Infrastructure Management",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
