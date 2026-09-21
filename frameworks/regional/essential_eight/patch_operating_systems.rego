package essential_eight.patch_operating_systems

import rego.v1

# ACSC Essential Eight Maturity Model (November 2023) — Patch Operating Systems.
# Requirements tagged by maturity level (ML1/ML2/ML3). Each higher level is cumulative
# in the official model; this module evaluates each stated requirement independently.
requirements := {
	# ---- Maturity Level 1 ----
	"POS-ML1-1": {"level": 1, "title": "An automated method of asset discovery is used at least fortnightly to support detection of assets for subsequent vulnerability scanning activities"},
	"POS-ML1-2": {"level": 1, "title": "A vulnerability scanner with an up-to-date vulnerability database is used for vulnerability scanning activities"},
	"POS-ML1-3": {"level": 1, "title": "A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in operating systems of internet-facing services"},
	"POS-ML1-4": {"level": 1, "title": "A vulnerability scanner is used at least fortnightly to identify missing patches or updates for vulnerabilities in operating systems of workstations, servers and network devices"},
	"POS-ML1-5": {"level": 1, "title": "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of internet-facing services are applied within two weeks of release, or within 48 hours if an exploit exists"},
	"POS-ML1-6": {"level": 1, "title": "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, servers and network devices are applied within one month of release"},
	"POS-ML1-7": {"level": 1, "title": "Operating systems that are no longer supported by vendors are replaced"},
	# ---- Maturity Level 2 ----
	"POS-ML2-1": {"level": 2, "title": "A vulnerability scanner is used at least weekly to identify missing patches or updates for vulnerabilities in operating systems of workstations, servers and network devices"},
	"POS-ML2-2": {"level": 2, "title": "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, servers and network devices are applied within two weeks of release, or within 48 hours if an exploit exists"},
	# ---- Maturity Level 3 ----
	# FIDELITY: unsure — daily scanning of workstations/servers/network devices at ML3 is a plausible
	# tightening but its exact cadence in the Nov 2023 model is not certain.
	"POS-ML3-1": {"level": 3, "title": "A vulnerability scanner is used at least daily to identify missing patches or updates for vulnerabilities in operating systems of workstations, servers and network devices"},
	"POS-ML3-2": {"level": 3, "title": "Patches, updates or other vendor mitigations for vulnerabilities in operating systems of workstations, servers and network devices are applied within 48 hours of release if an exploit exists, otherwise within two weeks"},
	"POS-ML3-3": {"level": 3, "title": "The latest release, or the previous release, of operating systems are used"},
}

attested(id) if input.essential_eight.patch_operating_systems.requirements[id] == true

violation contains msg if {
	some id, m in requirements
	not attested(id)
	msg := sprintf("Essential Eight [Patch Operating Systems] %s (ML%d): %s — not met", [id, m.level, m.title])
}

default strategy_compliant := false

strategy_compliant if count(violation) == 0

compliance_report := {
	"strategy": "Patch Operating Systems",
	"requirements_evaluated": count(requirements),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": strategy_compliant,
}
