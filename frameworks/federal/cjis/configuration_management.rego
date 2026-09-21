package cjis.configuration_management

import rego.v1

# FBI CJIS Security Policy — Policy Area 7: Configuration Management.
# Requirements are AAC's operationalization of the policy area (CJIS maps to NIST 800-53).
requirements := {
	"CM-1": {"area": 7, "title": "A documented, current baseline configuration is maintained for information systems that store, process, or transmit CJI"},
	"CM-2": {"area": 7, "title": "The principle of least functionality is enforced — only essential ports, protocols, services, and capabilities are enabled"},
	"CM-3": {"area": 7, "title": "A formal change control process governs and documents changes to CJI systems before they are applied"},
	"CM-4": {"area": 7, "title": "Access to make configuration changes is restricted to authorized personnel with an approval and audit trail"},
	"CM-5": {"area": 7, "title": "A current network topology (system architecture) diagram documenting the CJI environment is maintained and protected"},
	"CM-6": {"area": 7, "title": "Security-relevant configuration settings are hardened to a documented standard and enforced across CJI systems"},
	"CM-7": {"area": 7, "title": "Security impact of proposed configuration changes is analyzed prior to implementation"},
}

attested(id) if input.cjis.configuration_management.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Configuration Management] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 7,
	"area_name": "Configuration Management",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
