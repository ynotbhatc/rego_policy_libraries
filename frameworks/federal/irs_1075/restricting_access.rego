package irs_1075.restricting_access

import rego.v1

# IRS Publication 1075 (Rev. 11-2021) — Section 5: Restricting Access.
# Authority: IRC 6103(p)(4)(C).
# Requirements are AAC's operationalization of the section (Pub 1075 maps to NIST SP 800-53 Rev 5).
requirements := {
	"RA-1": {"section": "5", "title": "Access to FTI is limited to personnel with a need-to-know for a purpose authorized by statute"},
	"RA-2": {"section": "5", "title": "Disclosure awareness training is completed before initial FTI access and annually thereafter, with certification"},
	"RA-3": {"section": "5", "title": "A background investigation (FBI fingerprint check, citizenship/residency verification, local law-enforcement check) is completed before FTI access is granted"},
	"RA-4": {"section": "5", "title": "Background reinvestigations are conducted at least every 10 years for personnel with FTI access"},
	"RA-5": {"section": "5", "title": "Personnel acknowledge in writing the civil and criminal penalties of IRC 7213, 7213A, and 7431 (UNAX awareness)"},
	"RA-6": {"section": "5", "title": "Contractor or agent access to FTI occurs only where statute authorizes it and IRS notification requirements are met"},
	"RA-7": {"section": "5", "title": "FTI access authorizations are reviewed and revoked promptly on role change or separation"},
}

attested(id) if input.irs_1075.restricting_access.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("IRS 1075 [Restricting Access] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"section": "5",
	"area_name": "Restricting Access",
	"authority": "IRC 6103(p)(4)(C)",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
