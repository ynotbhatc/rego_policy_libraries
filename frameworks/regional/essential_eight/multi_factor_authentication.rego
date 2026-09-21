package essential_eight.multi_factor_authentication

import rego.v1

# ACSC Essential Eight Maturity Model (Nov 2023) — Multi-Factor Authentication.
# Requirements tagged by maturity level (1|2|3) per the published model.
# Each maturity level is cumulative over the ones below it.
#
# Input contract:
#   input.essential_eight.multi_factor_authentication.requirements[<id>] == true
#   attests that the correspondingly-identified requirement is met. Any id that is
#   absent or not exactly true is treated as an unmet gap (fail closed).
requirements := {
	# --- Maturity Level 1 ---
	"MFA-ML1-1": {"level": 1, "title": "Multi-factor authentication is used to authenticate users to their organisation's internet-facing services"},
	"MFA-ML1-2": {"level": 1, "title": "Multi-factor authentication is used to authenticate users to third-party internet-facing services that process, store or communicate their organisation's sensitive data"},
	"MFA-ML1-3": {"level": 1, "title": "Multi-factor authentication (where available) is used to authenticate users to third-party internet-facing services that process, store or communicate their organisation's non-sensitive data"},
	"MFA-ML1-4": {"level": 1, "title": "Multi-factor authentication uses either something users have and something users know, or something users have that is unlocked by something users know or are"},
	# --- Maturity Level 2 ---
	"MFA-ML2-1": {"level": 2, "title": "Multi-factor authentication is used to authenticate users to their organisation's internet-facing services (all users, not only where feasible)"},
	"MFA-ML2-2": {"level": 2, "title": "Multi-factor authentication is used to authenticate privileged users of systems"},
	"MFA-ML2-3": {"level": 2, "title": "Multi-factor authentication events are logged"},
	# --- Maturity Level 3 ---
	"MFA-ML3-1": {"level": 3, "title": "Multi-factor authentication is used to authenticate users to their organisation's online services and to authenticate users of systems"},
	"MFA-ML3-2": {"level": 3, "title": "Multi-factor authentication is verifier impersonation resistant (phishing-resistant)"},
	"MFA-ML3-3": {"level": 3, "title": "Multi-factor authentication event logs are protected from unauthorised modification and deletion, and monitored for signs of compromise"},
}

attested(id) if input.essential_eight.multi_factor_authentication.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Essential Eight [Multi-Factor Authentication] %s (ML%d): %s — not met", [id, m.level, m.title])
}

default strategy_compliant := false

strategy_compliant if count(violation) == 0

compliance_report := {
	"strategy": "Multi-Factor Authentication",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": strategy_compliant,
}
