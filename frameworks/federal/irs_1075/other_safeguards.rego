package irs_1075.other_safeguards

import rego.v1

# IRS Publication 1075 (Rev. 11-2021) — Section 6: Other Safeguards.
# Authority: IRC 6103(p)(4)(D).
# Requirements are AAC's operationalization of the section (Pub 1075 maps to NIST SP 800-53 Rev 5).
requirements := {
	"OS-1": {"section": "6", "title": "A safeguards program with a designated accountable official is established for FTI protection"},
	"OS-2": {"section": "6", "title": "Internal inspections of every location where FTI is received, processed, stored, or maintained are conducted on the Pub 1075 cycle and documented"},
	"OS-3": {"section": "6", "title": "An ongoing employee awareness program (reminders, certifications, warning banners) is maintained"},
	"OS-4": {"section": "6", "title": "Current written procedures cover FTI handling end to end — receipt, processing, storage, transmission, and disposal"},
	"OS-5": {"section": "6", "title": "Corrective actions from internal inspections and IRS Safeguard reviews are tracked to closure"},
	"OS-6": {"section": "6", "title": "The agency supports IRS Office of Safeguards on-site reviews and provides requested records"},
}

attested(id) if input.irs_1075.other_safeguards.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("IRS 1075 [Other Safeguards] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"section": "6",
	"area_name": "Other Safeguards",
	"authority": "IRC 6103(p)(4)(D)",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
