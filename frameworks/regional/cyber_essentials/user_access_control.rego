package cyber_essentials.user_access_control

import rego.v1

# UK Cyber Essentials (Willow question set, effective April 2025) — Control
# theme 4: User Access Control. Requirements are AAC's operationalization of
# the NCSC "Cyber Essentials Requirements for IT infrastructure" document.
requirements := {
	"UA-1": {"theme": 4, "title": "User accounts are created only through an approval process and are unique to one person"},
	"UA-2": {"theme": 4, "title": "Accounts are disabled or removed promptly when no longer required"},
	"UA-3": {"theme": 4, "title": "Multi-factor authentication is enabled for all users of cloud services"},
	"UA-4": {"theme": 4, "title": "Administrative privileges are granted only where needed, via separate administrative accounts"},
	"UA-5": {"theme": 4, "title": "Administrative accounts are not used for routine activities such as email and web browsing"},
	"UA-6": {"theme": 4, "title": "Password-based authentication requires at least 12 characters, or at least 8 characters combined with MFA or additional controls such as a deny list and throttling"},
	"UA-7": {"theme": 4, "title": "Users can change their own passwords easily, and passwords are changed promptly on suspected compromise — with no forced periodic expiry"},
}

attested(id) if input.cyber_essentials.user_access_control.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Cyber Essentials [User Access Control] %s: %s — not met", [id, m.title])
}

default theme_compliant := false

theme_compliant if count(violation) == 0

compliance_report := {
	"theme": 4,
	"area_name": "User Access Control",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": theme_compliant,
}
