package irs_1075.reporting

import rego.v1

# IRS Publication 1075 (Rev. 11-2021) — Section 7: Reporting Requirements.
# Authority: IRC 6103(p)(4)(E).
# Requirements are AAC's operationalization of the section (Pub 1075 maps to NIST SP 800-53 Rev 5).
requirements := {
	"RP-1": {"section": "7", "title": "A Safeguard Security Report (SSR) is submitted annually to the IRS Office of Safeguards"},
	"RP-2": {"section": "7", "title": "The SSR reflects the current processing environment — locations, systems, contractors, and safeguards"},
	"RP-3": {"section": "7", "title": "The Office of Safeguards is notified at least 45 days before FTI enters a cloud computing environment"},
	"RP-4": {"section": "7", "title": "The Office of Safeguards is notified at least 45 days before contractor or agent access, consolidated data center use, or off-site storage of FTI"},
	"RP-5": {"section": "7", "title": "The Office of Safeguards is notified at least 45 days before FTI is used in live-data testing"},
	"RP-6": {"section": "7", "title": "New facilities, systems, or uses of FTI are reported through SSR updates or 45-day notifications as applicable"},
}

attested(id) if input.irs_1075.reporting.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("IRS 1075 [Reporting] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"section": "7",
	"area_name": "Reporting",
	"authority": "IRC 6103(p)(4)(E)",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
