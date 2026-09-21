package cjis.auditing_accountability

import rego.v1

# FBI CJIS Security Policy — Policy Area 4: Auditing and Accountability. AAC operationalization (CJIS maps to NIST 800-53 AU family).

requirements := {
	"AA-1": {"area": 4, "title": "Auditable events are defined and logged (successful/failed logons, access to CJI)"},
	"AA-2": {"area": 4, "title": "Audit records capture required content (event type, timestamp, source, outcome, user identity)"},
	"AA-3": {"area": 4, "title": "Audit logs are retained for a minimum of one year"},
	"AA-4": {"area": 4, "title": "Audit records are reviewed and analyzed for indications of inappropriate activity"},
	"AA-5": {"area": 4, "title": "Audit logs are protected from unauthorized access, modification, and deletion"},
	"AA-6": {"area": 4, "title": "Time is synchronized to an authoritative source for accurate audit timestamps"},
	"AA-7": {"area": 4, "title": "Personnel are alerted upon audit processing or storage failure"},
}

attested(id) if input.cjis.auditing_accountability.requirements[id] == true

violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Auditing and Accountability] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 4,
	"area_name": "Auditing and Accountability",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
