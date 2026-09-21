package essential_eight.restrict_admin_privileges

import rego.v1

# ACSC Essential Eight Maturity Model (November 2023) — Restrict Administrative Privileges.
# Requirements tagged by maturity level (ML1/ML2/ML3). Each higher level is cumulative
# in the official model; this module evaluates each stated requirement independently.
requirements := {
	# ---- Maturity Level 1 ----
	"RAP-ML1-1": {"level": 1, "title": "Requests for privileged access to systems and applications are validated when first requested"},
	"RAP-ML1-2": {"level": 1, "title": "Privileged accounts (excluding privileged service accounts) are prevented from accessing the internet, email and web services"},
	"RAP-ML1-3": {"level": 1, "title": "Privileged users use separate privileged and unprivileged operating environments"},
	"RAP-ML1-4": {"level": 1, "title": "Privileged operating environments are not virtualised within unprivileged operating environments"},
	"RAP-ML1-5": {"level": 1, "title": "Unprivileged accounts cannot logon to privileged operating environments"},
	# ---- Maturity Level 2 ----
	"RAP-ML2-1": {"level": 2, "title": "Privileged access to systems and applications is automatically disabled after 12 months unless revalidated"},
	"RAP-ML2-2": {"level": 2, "title": "Privileged access to systems and applications is automatically disabled after 45 days of inactivity"},
	"RAP-ML2-3": {"level": 2, "title": "Privileged access to systems and applications is limited to only what is required for users and services to undertake their duties"},
	"RAP-ML2-4": {"level": 2, "title": "Administrative activities are conducted through jump servers"},
	"RAP-ML2-5": {"level": 2, "title": "Credentials for local administrator accounts and service accounts are long, unique, unpredictable and managed"},
	"RAP-ML2-6": {"level": 2, "title": "Privileged access events are centrally logged"},
	"RAP-ML2-7": {"level": 2, "title": "Privileged account and group management events are centrally logged"},
	# ---- Maturity Level 3 ----
	"RAP-ML3-1": {"level": 3, "title": "Just-in-time administration is used for administering systems and applications"},
	"RAP-ML3-2": {"level": 3, "title": "Windows Defender Credential Guard and Windows Defender Remote Credential Guard are enabled"},
	# FIDELITY: unsure — LAPS is the common implementation of ML2-5's managed local admin credentials;
	# its explicit call-out as a distinct ML3 line item is not certain in the Nov 2023 model.
	"RAP-ML3-3": {"level": 3, "title": "Local Administrator Password Solution (or equivalent) manages local administrator account credentials"},
	"RAP-ML3-4": {"level": 3, "title": "Privileged access event logs are protected from unauthorised modification and deletion, monitored for signs of compromise, and actioned when detected"},
}

attested(id) if input.essential_eight.restrict_admin_privileges.requirements[id] == true

violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Essential Eight [Restrict Administrative Privileges] %s (ML%d): %s — not met", [id, m.level, m.title])
}

default strategy_compliant := false

strategy_compliant if count(violation) == 0

compliance_report := {
	"strategy": "Restrict Administrative Privileges",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": strategy_compliant,
}
