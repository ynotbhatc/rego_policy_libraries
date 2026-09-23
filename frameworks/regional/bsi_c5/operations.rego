package bsi_c5.operations

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain OPS: Operations.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"OPS-1": {"domain": "OPS", "title": "Operating procedures are documented and changes to them are controlled"},
	"OPS-2": {"domain": "OPS", "title": "Capacity is monitored and forecast so that agreed service levels are sustained"},
	"OPS-3": {"domain": "OPS", "title": "Systems supporting the cloud service run current malware protection"},
	"OPS-4": {"domain": "OPS", "title": "Data backups are performed, protected against unauthorized access, and restore-tested regularly"},
	"OPS-5": {"domain": "OPS", "title": "Security-relevant events are logged; logs are protected against tampering and analysed centrally"},
	"OPS-6": {"domain": "OPS", "title": "Vulnerabilities are identified (including by penetration tests), assessed, and remediated within defined timeframes"},
}

attested(id) if input.bsi_c5.operations.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Operations] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "OPS",
	"area_name": "Operations",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
