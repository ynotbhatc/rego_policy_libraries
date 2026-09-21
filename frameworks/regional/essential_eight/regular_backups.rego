package essential_eight.regular_backups

import rego.v1

# ACSC Essential Eight Maturity Model (Nov 2023) — Regular Backups.
# Requirements tagged by maturity level (1|2|3) per the published model.
# Each maturity level is cumulative over the ones below it.
#
# Input contract:
#   input.essential_eight.regular_backups.requirements[<id>] == true
#   attests that the correspondingly-identified requirement is met. Any id that is
#   absent or not exactly true is treated as an unmet gap (fail closed).
requirements := {
	# --- Maturity Level 1 ---
	"RB-ML1-1": {"level": 1, "title": "Backups of data, applications and settings are performed and retained with a frequency and retention timeframe in accordance with business criticality and business continuity requirements"},
	"RB-ML1-2": {"level": 1, "title": "Backups of data, applications and settings are synchronised to enable restoration to a common point in time"},
	"RB-ML1-3": {"level": 1, "title": "Backups of data, applications and settings are retained in a secure and resilient manner"},
	"RB-ML1-4": {"level": 1, "title": "Unprivileged accounts cannot access backups belonging to other accounts, nor their own backups (except where required to perform their duties)"},
	# --- Maturity Level 2 ---
	"RB-ML2-1": {"level": 2, "title": "Unprivileged accounts are prevented from modifying and deleting backups during their retention period"},
	"RB-ML2-2": {"level": 2, "title": "Restoration of data, applications and settings from backups to a common point in time is tested as part of disaster recovery exercises"}, # FIDELITY: unsure — level placement of restoration testing
	# --- Maturity Level 3 ---
	"RB-ML3-1": {"level": 3, "title": "Privileged accounts (excluding backup administrators) cannot access backups belonging to other accounts, nor their own backups"},
	"RB-ML3-2": {"level": 3, "title": "Privileged accounts (excluding backup administrators) are prevented from modifying and deleting backups during their retention period"},
}

attested(id) if input.essential_eight.regular_backups.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Essential Eight [Regular Backups] %s (ML%d): %s — not met", [id, m.level, m.title])
}

default strategy_compliant := false

strategy_compliant if count(violation) == 0

compliance_report := {
	"strategy": "Regular Backups",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": strategy_compliant,
}
