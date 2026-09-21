package essential_eight.patch_applications

import rego.v1

# ACSC Essential Eight Maturity Model (Nov 2023) — Patch Applications.
# Requirements tagged by maturity level (1|2|3) per the published model.
# Each maturity level is cumulative over the ones below it.
# "Online services", "office productivity suites/web browsers/email clients/PDF
# software/security products", and "other applications" are the three asset
# classes the model scans and patches on distinct cadences.
requirements := {
	# --- Maturity Level 1 ---
	"PA-ML1-1": {"level": 1, "title": "An automated asset discovery method is used at least fortnightly to support vulnerability scanning"},
	"PA-ML1-2": {"level": 1, "title": "A vulnerability scanner with an up-to-date vulnerability database is used for scanning activities"},
	"PA-ML1-3": {"level": 1, "title": "The scanner is used at least daily to identify missing patches for internet-facing services"},
	"PA-ML1-4": {"level": 1, "title": "The scanner is used at least weekly for office productivity suites, web browsers/extensions, email clients, PDF software and security products"},
	"PA-ML1-5": {"level": 1, "title": "Patches for internet-facing services are applied within 2 weeks, or 48 hours if an exploit exists"},
	"PA-ML1-6": {"level": 1, "title": "Patches for office productivity, browsers, email, PDF and security products are applied within 2 weeks of release"},
	"PA-ML1-7": {"level": 1, "title": "Applications no longer supported by vendors are removed"},
	# --- Maturity Level 2 ---
	"PA-ML2-1": {"level": 2, "title": "The scanner is used at least fortnightly to identify missing patches for other applications"},
	"PA-ML2-2": {"level": 2, "title": "Patches for internet-facing services are applied within 48 hours if an exploit exists, otherwise within 2 weeks"},
	"PA-ML2-3": {"level": 2, "title": "Patches for other applications are applied within 1 month of release"},
	# --- Maturity Level 3 ---
	"PA-ML3-1": {"level": 3, "title": "The scanner is used at least weekly to identify missing patches for other applications"},
	"PA-ML3-2": {"level": 3, "title": "Patches for office productivity, browsers, email, PDF and security products are applied within 48 hours if an exploit exists"},
	"PA-ML3-3": {"level": 3, "title": "Patches for other applications are applied within 48 hours if an exploit exists, otherwise within 1 month"},
}

attested(id) if input.essential_eight.patch_applications.requirements[id] == true

# Fail closed: an unattested requirement is a gap.
violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Essential Eight [Patch Applications] %s (ML%d): %s — not met", [id, m.level, m.title])
}

default strategy_compliant := false

strategy_compliant if count(violation) == 0

compliance_report := {
	"strategy": "Patch Applications",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": strategy_compliant,
}
