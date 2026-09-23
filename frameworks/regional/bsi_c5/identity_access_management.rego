package bsi_c5.identity_access_management

import rego.v1

# BSI C5:2020 (Cloud Computing Compliance Criteria Catalogue) — criteria
# domain IDM: Identity and Access Management.
# Requirement ids are AAC's operationalization of the domain, not the official
# C5 criterion numbering.
requirements := {
	"IDM-1": {"domain": "IDM", "title": "Access is provisioned through a formal process on least-privilege and need-to-know principles"},
	"IDM-2": {"domain": "IDM", "title": "Every user has a unique identifier; shared accounts are prohibited or strictly controlled and attributable"},
	"IDM-3": {"domain": "IDM", "title": "Privileged access is restricted, separately managed, and its use monitored"},
	"IDM-4": {"domain": "IDM", "title": "Access rights are reviewed at regular intervals and revoked without undue delay on role change or departure"},
	"IDM-5": {"domain": "IDM", "title": "Strong (multi-factor) authentication protects administrative and remote access to the service infrastructure"},
}

attested(id) if input.bsi_c5.identity_access_management.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("BSI C5 [Identity and Access Management] %s: %s — not met", [id, m.title])
}

default domain_compliant := false

domain_compliant if count(violation) == 0

compliance_report := {
	"domain": "IDM",
	"area_name": "Identity and Access Management",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": domain_compliant,
}
