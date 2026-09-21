package cjis.personnel_security

import rego.v1

# FBI CJIS Security Policy — Policy Area 12: Personnel Security.
# Requirements are AAC's operationalization of the policy area (CJIS maps to NIST 800-53).
requirements := {
	"PS-1": {"area": 12, "title": "A state of residency and national fingerprint-based background check is completed before authorizing access to CJI"},
	"PS-2": {"area": 12, "title": "Access to CJI is not granted until the background check adjudication is favorably resolved"},
	"PS-3": {"area": 12, "title": "Personnel with access to CJI are re-investigated on a defined periodic basis"},
	"PS-4": {"area": 12, "title": "Contractors, vendors, and third-party personnel are screened to the same personnel security standard before CJI access"},
	"PS-5": {"area": 12, "title": "Access authorizations are revoked immediately upon termination of employment or contract"},
	"PS-6": {"area": 12, "title": "Access authorizations are reviewed and adjusted upon personnel transfer or reassignment"},
	"PS-7": {"area": 12, "title": "A documented process governs personnel security incidents, sanctions, and disqualifying criteria"},
	"PS-8": {"area": 12, "title": "Personnel with access to unescorted CJI are subject to state and agency support-personnel screening requirements"}, # FIDELITY: unsure
}

attested(id) if input.cjis.personnel_security.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Personnel Security] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 12,
	"area_name": "Personnel Security",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
