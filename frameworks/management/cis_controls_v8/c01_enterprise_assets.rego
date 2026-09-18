package cis_controls_v8.c01

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 1:
# Inventory and Control of Enterprise Assets.
safeguards := {
	"1.1": {"ig": 1, "title": "Establish and Maintain Detailed Enterprise Asset Inventory"},
	"1.2": {"ig": 1, "title": "Address Unauthorized Assets"},
	"1.3": {"ig": 2, "title": "Utilize an Active Discovery Tool"},
	"1.4": {"ig": 2, "title": "Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory"},
	"1.5": {"ig": 3, "title": "Use a Passive Asset Discovery Tool"},
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
	"control": 1,
	"name": "Inventory and Control of Enterprise Assets",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
