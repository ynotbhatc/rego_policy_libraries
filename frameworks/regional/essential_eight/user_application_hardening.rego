package essential_eight.user_application_hardening

import rego.v1

# ACSC Essential Eight Maturity Model (Nov 2023) — User Application Hardening.
# Requirements tagged by maturity level. Higher levels are cumulative over lower levels.
requirements := {
	# Maturity Level 1
	"UAH-ML1-1": {"level": 1, "title": "Web browsers do not process Java from the internet"},
	"UAH-ML1-2": {"level": 1, "title": "Web browsers do not process web advertisements from the internet"},
	"UAH-ML1-3": {"level": 1, "title": "Internet Explorer 11 does not process content from the internet"},
	"UAH-ML1-4": {"level": 1, "title": "Web browser security settings cannot be changed by users"},
	# Maturity Level 2 (adds to ML1)
	"UAH-ML2-1": {"level": 2, "title": "Microsoft Office is blocked from creating child processes"},
	"UAH-ML2-2": {"level": 2, "title": "Microsoft Office is blocked from creating executable content"},
	"UAH-ML2-3": {"level": 2, "title": "Microsoft Office is blocked from injecting code into other processes"},
	"UAH-ML2-4": {"level": 2, "title": "Microsoft Office is configured to prevent activation of OLE packages"},
	"UAH-ML2-5": {"level": 2, "title": "Microsoft Office security settings cannot be changed by users"},
	"UAH-ML2-6": {"level": 2, "title": "PDF software is blocked from creating child processes"},
	"UAH-ML2-7": {"level": 2, "title": "PDF software security settings cannot be changed by users"},
	# Maturity Level 3 (adds to ML2)
	"UAH-ML3-1": {"level": 3, "title": "Internet Explorer 11 is disabled or removed"},
	"UAH-ML3-2": {"level": 3, "title": ".NET Framework 3.5 (includes .NET 2.0 and 3.0) is disabled or removed"},
	"UAH-ML3-3": {"level": 3, "title": "Windows PowerShell 2.0 is disabled or removed"},
	"UAH-ML3-4": {"level": 3, "title": "PowerShell is configured to use Constrained Language Mode"},
	# FIDELITY: unsure — command-line process creation logging appears across several E8 strategies;
	# maturity level attribution for User Application Hardening is approximate.
	"UAH-ML3-5": {"level": 3, "title": "Command line process creation events are logged"},
}

attested(id) if input.essential_eight.user_application_hardening.requirements[id] == true

violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Essential Eight [User Application Hardening] %s (ML%d): %s — not met", [id, m.level, m.title])
}

default strategy_compliant := false

strategy_compliant if count(violation) == 0

compliance_report := {
	"strategy": "User Application Hardening",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": strategy_compliant,
}
