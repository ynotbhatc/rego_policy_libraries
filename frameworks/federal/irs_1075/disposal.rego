package irs_1075.disposal

import rego.v1

# IRS Publication 1075 (Rev. 11-2021) — Section 8: Disposing of FTI.
# Authority: IRC 6103(p)(4)(F).
# Requirements are AAC's operationalization of the section (Pub 1075 maps to NIST SP 800-53 Rev 5).
requirements := {
	"DS-1": {"section": "8", "title": "FTI is returned to the IRS or destroyed when no longer needed for the authorized purpose"},
	"DS-2": {"section": "8", "title": "Paper FTI is destroyed by burning or shredding so it is unreadable and cannot be reconstructed"},
	"DS-3": {"section": "8", "title": "Electronic media holding FTI is sanitized per NIST SP 800-88 before disposal or reuse"},
	"DS-4": {"section": "8", "title": "Destruction is performed or witnessed by authorized agency personnel; contractor destruction meets IRS notification and oversight requirements"},
	"DS-5": {"section": "8", "title": "Each destruction is documented in the recordkeeping logs with date, method, and items destroyed"},
	"DS-6": {"section": "8", "title": "Devices with internal storage that processed FTI (printers, copiers, fax, multifunction devices) are sanitized before disposal or return"},
}

attested(id) if input.irs_1075.disposal.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("IRS 1075 [Disposal] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"section": "8",
	"area_name": "Disposal",
	"authority": "IRC 6103(p)(4)(F)",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
