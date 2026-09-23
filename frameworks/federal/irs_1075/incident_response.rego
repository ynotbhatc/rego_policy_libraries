package irs_1075.incident_response

import rego.v1

# IRS Publication 1075 (Rev. 11-2021) — Section 10: Data Incident Response.
# Covers unauthorized access, inspection, or disclosure of FTI (UNAX).
# Requirements are AAC's operationalization of the section.
requirements := {
	"IR-1": {"section": "10", "title": "Incident response procedures specifically cover FTI incidents, including unauthorized inspection or disclosure"},
	"IR-2": {"section": "10", "title": "Suspected or confirmed FTI incidents are reported to TIGTA and the IRS Office of Safeguards within 24 hours of identification"},
	"IR-3": {"section": "10", "title": "Incident details — systems, FTI records, and individuals affected — are documented, preserved, and provided to investigators"},
	"IR-4": {"section": "10", "title": "Willful unauthorized access or inspection (UNAX) is addressed under IRC 7213A and reported"},
	"IR-5": {"section": "10", "title": "Post-incident corrective actions are tracked to closure and safeguards updated"},
	"IR-6": {"section": "10", "title": "Taxpayer notification is coordinated with the IRS and TIGTA before the agency notifies affected individuals"},
}

attested(id) if input.irs_1075.incident_response.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("IRS 1075 [Incident Response] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"section": "10",
	"area_name": "Incident Response",
	"authority": "IRS Pub 1075 §10",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
