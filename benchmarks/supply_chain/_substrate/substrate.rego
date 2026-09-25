# AAC Supply-Chain Control Substrate
#
# The invariant control set that the major software-supply-chain frameworks
# collapse onto. Every framework package (slsa, ssdf, ...) maps its own
# requirements to THESE rules, so the count of shared substrate rules referenced
# across the frameworks is the empirical measure of the collapse — the
# supply-chain analogue of "2,767 STIG rules -> 65 controls".
#
# Seven themes, each mapped to NIST 800-53 (SR / SA / CM) with a centrality
# weight. Themes 4 and 7 (source-change control, build hardening) sit on the
# CM-5/6/7 controls that are also in the original OS-hardening spine — the
# shared "CM seam".
#
# Fail-closed: every theme defaults to false, so a missing or unshaped fact
# reports the control unsatisfied rather than silently passing.
#
# Input contract (supply-chain facts) — see README.md for the full shape.
package supply_chain.substrate

import rego.v1

# ── Theme metadata: 800-53 anchor families + centrality weight ────────────
themes := {
	"sbom": {"title": "Component inventory / SBOM", "families": ["SR-3", "SR-4"], "weight": 3},
	"provenance": {"title": "Build provenance / attestation", "families": ["SR-4", "SA-15"], "weight": 3},
	"signing": {"title": "Artifact & source integrity / signing", "families": ["SR-11", "SI-7"], "weight": 3},
	"source_control": {"title": "Source & change control", "families": ["CM-5", "CM-3"], "weight": 3},
	"dependencies": {"title": "Dependency trust & vetting", "families": ["SR-3", "SR-5", "SR-6"], "weight": 2},
	"vulns": {"title": "Vulnerability management", "families": ["RA-5", "SR-6"], "weight": 3},
	"build_hardening": {"title": "Build-environment hardening", "families": ["CM-6", "CM-7"], "weight": 2},
}

# ── Theme satisfaction from the supply-chain facts ────────────────────────
default sbom_ok := false

sbom_ok if {
	input.sbom.present == true
	count(input.sbom.components) > 0
}

default provenance_ok := false

provenance_ok if {
	input.provenance.present == true
	input.provenance.signed == true
}

default signing_ok := false

signing_ok if input.signing.artifacts_signed == true

default source_control_ok := false

source_control_ok if {
	input.source.branch_protection == true
	input.source.required_reviews >= 1
	input.source.code_owner_review == true
}

default dependencies_ok := false

dependencies_ok if {
	input.dependencies.pinned == true
	input.dependencies.vetted == true
	input.dependencies.unresolved_purls == 0
}

default vulns_ok := false

vulns_ok if {
	input.vulnerabilities.kev_hits == 0
	input.vulnerabilities.unaddressed == 0
}

default build_hardening_ok := false

build_hardening_ok if {
	input.build.hardened == true
	input.build.isolated == true
}

# ── Roll-up: which themes are satisfied vs not ────────────────────────────
theme_status := {
	"sbom": sbom_ok,
	"provenance": provenance_ok,
	"signing": signing_ok,
	"source_control": source_control_ok,
	"dependencies": dependencies_ok,
	"vulns": vulns_ok,
	"build_hardening": build_hardening_ok,
}

satisfied contains k if {
	some k, v in theme_status
	v == true
}

unsatisfied contains k if {
	some k, v in theme_status
	v == false
}
