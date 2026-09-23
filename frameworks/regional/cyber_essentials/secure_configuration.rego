package cyber_essentials.secure_configuration

import rego.v1

# UK Cyber Essentials (Willow question set, effective April 2025) — Control
# theme 2: Secure Configuration. Requirements are AAC's operationalization of
# the NCSC "Cyber Essentials Requirements for IT infrastructure" document.
requirements := {
	"SC-1": {"theme": 2, "title": "Unnecessary user accounts are removed or disabled"},
	"SC-2": {"theme": 2, "title": "Default or easily guessable account passwords are changed"},
	"SC-3": {"theme": 2, "title": "Unnecessary software, services, and applications are removed or disabled"},
	"SC-4": {"theme": 2, "title": "Auto-run and auto-play of files from removable media or the network is disabled"},
	"SC-5": {"theme": 2, "title": "Device unlocking requires biometrics or a PIN/password of at least 6 characters"},
	"SC-6": {"theme": 2, "title": "Brute-force unlock protection: throttling to no more than 10 guesses in 5 minutes, or lockout after no more than 10 unsuccessful attempts"},
}

attested(id) if input.cyber_essentials.secure_configuration.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Cyber Essentials [Secure Configuration] %s: %s — not met", [id, m.title])
}

default theme_compliant := false

theme_compliant if count(violation) == 0

compliance_report := {
	"theme": 2,
	"area_name": "Secure Configuration",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": theme_compliant,
}
