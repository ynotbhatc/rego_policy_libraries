package essential_eight.application_control

import rego.v1

# ACSC Essential Eight Maturity Model (Nov 2023) — Application Control.
# Requirements tagged by maturity level (1|2|3) per the published model.
# Each maturity level is cumulative over the ones below it.
requirements := {
	# --- Maturity Level 1 ---
	"AC-ML1-1": {"level": 1, "title": "Application control is implemented on workstations"},
	"AC-ML1-2": {"level": 1, "title": "Application control restricts execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets to an approved set on workstations"},
	# --- Maturity Level 2 ---
	"AC-ML2-1": {"level": 2, "title": "Application control is implemented on workstations and internet-facing servers"},
	"AC-ML2-2": {"level": 2, "title": "Microsoft's recommended application blocklist is implemented"},
	"AC-ML2-3": {"level": 2, "title": "Application control rulesets are validated on an annual or more frequent basis"},
	"AC-ML2-4": {"level": 2, "title": "Allowed and blocked execution events are centrally logged"},
	# --- Maturity Level 3 ---
	"AC-ML3-1": {"level": 3, "title": "Application control is implemented on workstations and servers"},
	"AC-ML3-2": {"level": 3, "title": "Application control restricts execution of drivers to an approved set"},
	"AC-ML3-3": {"level": 3, "title": "Microsoft's recommended driver blocklist is implemented"},
	"AC-ML3-4": {"level": 3, "title": "Event logs are protected from unauthorised modification and deletion"},
	"AC-ML3-5": {"level": 3, "title": "Event logs are monitored for signs of compromise and actioned when detected"},
}

attested(id) if input.essential_eight.application_control.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Essential Eight [Application Control] %s (ML%d): %s — not met", [id, m.level, m.title])
}

default strategy_compliant := false

strategy_compliant if count(violation) == 0

compliance_report := {
	"strategy": "Application Control",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": strategy_compliant,
}
