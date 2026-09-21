package cjis.media_protection

import rego.v1

# FBI CJIS Security Policy — Policy Area 8: Media Protection.
# Requirements are AAC's operationalization of the policy area (CJIS maps to NIST 800-53).
requirements := {
	"MP-1": {"area": 8, "title": "Access to digital and physical media containing CJI is restricted to authorized users"},
	"MP-2": {"area": 8, "title": "Digital and physical media containing CJI is securely stored within physically secure or controlled areas"},
	"MP-3": {"area": 8, "title": "CJI is encrypted while at rest on digital media and while in transit outside physically secure locations"},
	"MP-4": {"area": 8, "title": "Media containing CJI is protected and controlled during transport outside of controlled areas, with accountability maintained"},
	"MP-5": {"area": 8, "title": "Digital media is sanitized or destroyed using approved methods before disposal or reuse"},
	"MP-6": {"area": 8, "title": "Physical media containing CJI is destroyed by shredding, incineration, or another approved method when no longer needed"},
	"MP-7": {"area": 8, "title": "Sanitization and destruction of media containing CJI is witnessed or carried out by authorized personnel and documented"},
}

attested(id) if input.cjis.media_protection.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Media Protection] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 8,
	"area_name": "Media Protection",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
