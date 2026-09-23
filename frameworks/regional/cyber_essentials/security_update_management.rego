package cyber_essentials.security_update_management

import rego.v1

# UK Cyber Essentials (Willow question set, effective April 2025) — Control
# theme 3: Security Update Management. Requirements are AAC's
# operationalization of the NCSC "Cyber Essentials Requirements for IT
# infrastructure" document.
requirements := {
	"SU-1": {"theme": 3, "title": "All in-scope software is licensed and vendor-supported"},
	"SU-2": {"theme": 3, "title": "Unsupported software is removed from devices, or moved out of scope by preventing its access to and from the internet"},
	"SU-3": {"theme": 3, "title": "Automatic updates are enabled wherever the software supports them"},
	"SU-4": {"theme": 3, "title": "Updates fixing vulnerabilities the vendor rates critical or high risk (CVSS 7 and above) are applied within 14 days of release"},
	"SU-5": {"theme": 3, "title": "Where the vendor publishes no severity detail, all updates are applied within 14 days of release"},
}

attested(id) if input.cyber_essentials.security_update_management.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Cyber Essentials [Security Update Management] %s: %s — not met", [id, m.title])
}

default theme_compliant := false

theme_compliant if count(violation) == 0

compliance_report := {
	"theme": 3,
	"area_name": "Security Update Management",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": theme_compliant,
}
