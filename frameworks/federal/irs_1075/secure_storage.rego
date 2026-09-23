package irs_1075.secure_storage

import rego.v1

# IRS Publication 1075 (Rev. 11-2021) — Section 4: Secure Storage.
# Authority: IRC 6103(p)(4)(B).
# Requirements are AAC's operationalization of the section (Pub 1075 maps to NIST SP 800-53 Rev 5).
requirements := {
	"SS-1": {"section": "4", "title": "Minimum Protection Standards two-barrier rule: FTI is protected by two barriers (e.g., secured perimeter plus locked container or interior room)"},
	"SS-2": {"section": "4", "title": "Areas where FTI is received, processed, or stored are designated restricted areas with entry limited to authorized personnel"},
	"SS-3": {"section": "4", "title": "Visitor access logs are maintained for restricted areas holding FTI"},
	"SS-4": {"section": "4", "title": "FTI is secured in locked containers or locked rooms when not in use and outside duty hours"},
	"SS-5": {"section": "4", "title": "Access devices (keys, combinations, badges) for FTI areas are controlled and updated when personnel change"},
	"SS-6": {"section": "4", "title": "Alternative work sites (including telework) provide protections for FTI equivalent to the primary site"},
	"SS-7": {"section": "4", "title": "FTI transported between sites is protected in transit and receipted on delivery"},
}

attested(id) if input.irs_1075.secure_storage.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("IRS 1075 [Secure Storage] %s: %s — not met", [id, m.title])
}

default area_compliant := false

area_compliant if count(violation) == 0

compliance_report := {
	"section": "4",
	"area_name": "Secure Storage",
	"authority": "IRC 6103(p)(4)(B)",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": area_compliant,
}
