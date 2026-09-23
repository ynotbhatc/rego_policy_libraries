package cyber_essentials.firewalls

import rego.v1

# UK Cyber Essentials (Willow question set, effective April 2025) — Control
# theme 1: Firewalls. Requirements are AAC's operationalization of the NCSC
# "Cyber Essentials Requirements for IT infrastructure" document.
requirements := {
	"FW-1": {"theme": 1, "title": "Every in-scope device is protected by a correctly configured boundary or software firewall"},
	"FW-2": {"theme": 1, "title": "Default administrative passwords on firewalls are changed to strong, unique passwords"},
	"FW-3": {"theme": 1, "title": "Inbound connections are blocked by default; each open inbound service is documented with a business need"},
	"FW-4": {"theme": 1, "title": "Firewall administrative interfaces are not reachable from the internet unless protected by MFA or an IP allow list, with a documented business need"},
	"FW-5": {"theme": 1, "title": "Firewall rules no longer required are removed or disabled promptly"},
	"FW-6": {"theme": 1, "title": "Software firewalls are enabled on devices used on untrusted networks, including remote working"},
}

attested(id) if input.cyber_essentials.firewalls.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Cyber Essentials [Firewalls] %s: %s — not met", [id, m.title])
}

default theme_compliant := false

theme_compliant if count(violation) == 0

compliance_report := {
	"theme": 1,
	"area_name": "Firewalls",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": theme_compliant,
}
