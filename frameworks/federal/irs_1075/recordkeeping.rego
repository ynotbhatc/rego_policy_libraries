package irs_1075.recordkeeping

import rego.v1

# IRS Publication 1075 (Rev. 11-2021) — Section 3: Recordkeeping Requirement.
# Authority: IRC 6103(p)(4)(A).
# Requirements are AAC's operationalization of the section (Pub 1075 maps to NIST SP 800-53 Rev 5).
requirements := {
	"RK-1": {"section": "3", "title": "A permanent system of standardized records of requests for and receipts of FTI is maintained"},
	"RK-2": {"section": "3", "title": "FTI is tracked from receipt through processing, storage, and disposal, for both electronic and physical media"},
	"RK-3": {"section": "3", "title": "Disclosures of FTI to authorized recipients are logged with date, recipient, and purpose"},
	"RK-4": {"section": "3", "title": "Electronic transmissions of FTI are logged"},
	"RK-5": {"section": "3", "title": "FTI is labeled and kept identifiable — never commingled with other agency data without remaining distinguishable"},
	"RK-6": {"section": "3", "title": "Recordkeeping logs are retained and available for IRS Office of Safeguards review"},
}

attested(id) if input.irs_1075.recordkeeping.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("IRS 1075 [Recordkeeping] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"section": "3",
	"area_name": "Recordkeeping",
	"authority": "IRC 6103(p)(4)(A)",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
