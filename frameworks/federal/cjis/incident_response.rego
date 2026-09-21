package cjis.incident_response

import rego.v1

# FBI CJIS Security Policy — Policy Area 3: Incident Response.
# Requirements are AAC's operationalization of the policy area (CJIS maps to NIST 800-53).
requirements := {
	"IR-1": {"area": 3, "title": "A documented incident response plan defines roles, responsibilities, and handling procedures"},
	"IR-2": {"area": 3, "title": "An incident handling capability covers preparation, detection, analysis, containment, eradication, and recovery"},
	"IR-3": {"area": 3, "title": "Security incidents are reported to the CJIS Systems Officer (CSO) and the FBI CJIS Information Security Officer (ISO)"},
	"IR-4": {"area": 3, "title": "Incidents are tracked and documented from detection through resolution"},
	"IR-5": {"area": 3, "title": "Incident information and evidence are collected and preserved for analysis and reporting"},
	"IR-6": {"area": 3, "title": "The incident response capability is tested and exercised on a defined schedule"},
	"IR-7": {"area": 3, "title": "Personnel receive incident response training appropriate to their role"},
	"IR-8": {"area": 3, "title": "Lessons learned from incidents are used to update controls and the incident response plan"},
}

attested(id) if input.cjis.incident_response.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("CJIS [Incident Response] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"policy_area": 3,
	"area_name": "Incident Response",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
