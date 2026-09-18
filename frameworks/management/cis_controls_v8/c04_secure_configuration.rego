package cis_controls_v8.c04

import rego.v1

# Official CIS Controls v8.1 safeguards for Control 4:
# Secure Configuration of Enterprise Assets and Software.
safeguards := {
	"4.1": {"ig": 1, "title": "Establish and Maintain a Secure Configuration Process"},
	"4.2": {"ig": 1, "title": "Establish and Maintain a Secure Configuration Process for Network Infrastructure"},
	"4.3": {"ig": 1, "title": "Configure Automatic Session Locking on Enterprise Assets"},
	"4.4": {"ig": 1, "title": "Implement and Manage a Firewall on Servers"},
	"4.5": {"ig": 1, "title": "Implement and Manage a Firewall on End-User Devices"},
	"4.6": {"ig": 1, "title": "Securely Manage Enterprise Assets and Software"},
	"4.7": {"ig": 1, "title": "Manage Default Accounts on Enterprise Assets and Software"},
	"4.8": {"ig": 2, "title": "Uninstall or Disable Unnecessary Services on Enterprise Assets and Software"},
	"4.9": {"ig": 2, "title": "Configure Trusted DNS Servers on Enterprise Assets"},
	"4.10": {"ig": 2, "title": "Enforce Automatic Device Lockout on Portable End-User Devices"},
	"4.11": {"ig": 2, "title": "Enforce Remote Wipe Capability on Portable End-User Devices"},
	"4.12": {"ig": 3, "title": "Separate Enterprise Workspaces on Mobile End-User Devices"},
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
	"control": 4,
	"name": "Secure Configuration of Enterprise Assets and Software",
	"safeguards_evaluated": count(safeguards),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": control_compliant,
}
