package cjis.security_awareness_training

import rego.v1

# FBI CJIS Security Policy — Policy Area 2: Security Awareness Training.
# Requirements are AAC's operationalization of the policy area (CJIS maps to NIST 800-53).
requirements := {
	"SAT-1": {"area": 2, "title": "Security awareness training is completed within six months of assignment for all personnel with access to CJI"},
	"SAT-2": {"area": 2, "title": "Security awareness training is repeated at least once every two years (biennially)"},
	"SAT-3": {"area": 2, "title": "Role-based training content matches each individual's level of access to CJI and information systems"},
	"SAT-4": {"area": 2, "title": "Training covers proper handling, storage, dissemination, and protection of CJI"},
	"SAT-5": {"area": 2, "title": "Training records are maintained and auditable for each individual"},
	"SAT-6": {"area": 2, "title": "Personnel with physical or logical access to CJI, including IT and contractor staff, are covered by the training program"},
	"SAT-7": {"area": 2, "title": "Training addresses incident reporting responsibilities and recognition of security threats such as social engineering"},
}

attested(id) if input.cjis.security_awareness_training.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Security Awareness Training] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 2,
	"area_name": "Security Awareness Training",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
