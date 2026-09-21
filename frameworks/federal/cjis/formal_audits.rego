package cjis.formal_audits

import rego.v1

# FBI CJIS Security Policy — Policy Area 11: Formal Audits. AAC operationalization (maps to NIST 800-53 CA/AU families).

requirements := {
	"FA-1": {"area": 11, "title": "The agency is subject to a triennial CJIS Security Policy compliance audit conducted by the FBI CJIS Division (or CSA on its behalf)"},
	"FA-2": {"area": 11, "title": "The CSA/SIB conducts audits of the agency, and the agency cooperates with and remediates findings from those audits"},
	"FA-3": {"area": 11, "title": "The agency audits its contractors, vendors, and subordinate/servicing agencies with access to CJI at least triennially"},
	"FA-4": {"area": 11, "title": "Use of NCIC, III, and other CJIS systems is audited for authorized purpose and compliance (transaction/log review)"},
	"FA-5": {"area": 11, "title": "Audit findings are documented and tracked to remediation through a corrective action plan"},
	"FA-6": {"area": 11, "title": "The agency permits FBI/CSA inspection and can produce records demonstrating CJIS Security Policy compliance on request"},
}

attested(id) if input.cjis.formal_audits.requirements[id] == true

violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Formal Audits] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 11,
	"area_name": "Formal Audits",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
