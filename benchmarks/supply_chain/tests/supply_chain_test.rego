# Tests for the supply-chain scaffold: the baseline (spine), the framework
# mappings, the P28 coverage triage, and — the point of the scaffold — that the
# frameworks REUSE the shared substrate (the empirical collapse).
package supply_chain.tests

import rego.v1

import data.supply_chain.baseline
import data.supply_chain.coverage
import data.supply_chain.metrics
import data.supply_chain.slsa
import data.supply_chain.ssdf
import data.supply_chain.ssdf_genai

# A fully-compliant supply-chain fact set.
_full := {
	"sbom": {"present": true, "format": "cyclonedx", "components": [{"purl": "pkg:pypi/requests@2.31"}]},
	"provenance": {"present": true, "signed": true, "slsa_build_level": 3, "builder": "hosted"},
	"signing": {"artifacts_signed": true, "method": "cosign"},
	"source": {"branch_protection": true, "required_reviews": 1, "code_owner_review": true, "signed_commits": true},
	"dependencies": {"pinned": true, "vetted": true, "unresolved_purls": 0},
	"vulnerabilities": {"kev_hits": 0, "osv_hits": 0, "unaddressed": 0},
	"build": {"hardened": true, "isolated": true, "ephemeral": true},
}

# Same, but unsigned artifacts and a non-hardened build (two themes fail).
_missing := {
	"sbom": {"present": true, "components": [{"purl": "pkg:pypi/requests@2.31"}]},
	"provenance": {"present": true, "signed": true},
	"signing": {"artifacts_signed": false},
	"source": {"branch_protection": true, "required_reviews": 1, "code_owner_review": true},
	"dependencies": {"pinned": true, "vetted": true, "unresolved_purls": 0},
	"vulnerabilities": {"kev_hits": 0, "unaddressed": 0},
	"build": {"hardened": false, "isolated": false},
}

test_baseline_compliant_when_all_ok if {
	baseline.compliance_report.compliant == true with input as _full
	baseline.compliance_report.passed_controls == 7 with input as _full
}

test_baseline_noncompliant_when_missing if {
	baseline.compliance_report.compliant == false with input as _missing
	baseline.compliance_report.failed_controls == 2 with input as _missing
}

test_slsa_level3_when_full if {
	slsa.level == 3 with input as _full
}

test_slsa_level0_when_empty if {
	slsa.level == 0 with input as {}
}

test_ssdf_all_practices_met_when_full if {
	ssdf.report.practices_met == ssdf.report.practices_total with input as _full
}

# ── P28 coverage triage ──
test_coverage_focused_for_security_artifact if {
	coverage.report.evaluation_depth == "focused" with input as {"artifact": {"name": "authlib", "capabilities": ["auth", "crypto", "config"]}}
}

test_coverage_light_for_benign_artifact if {
	coverage.report.evaluation_depth == "light" with input as {"artifact": {"name": "leftpad", "capabilities": ["string_util"]}}
}

# ── SSDF-GenAI (800-218A) — AI-contribution attestation ──
test_ssdf_genai_attested_when_ai_signed if {
	ssdf_genai.ai_attested with input as {"ai": {"has_ai_contributions": true, "ai_contributions_attested": true}}
}

test_ssdf_genai_not_attested_when_ai_unattested if {
	not ssdf_genai.ai_attested with input as {"ai": {"has_ai_contributions": true, "ai_contributions_attested": false}}
}

test_ssdf_genai_vacuous_when_no_ai if {
	ssdf_genai.ai_attested with input as {"ai": {"has_ai_contributions": false}}
}

# ── The collapse: independent frameworks reference the SAME substrate rules ──
test_collapse_frameworks_reuse_substrate if {
	"signing" in slsa.report.reuses_substrate
	"signing" in ssdf.report.reuses_substrate
}

# ── The collapse, measured: many framework references -> few distinct themes ──
test_collapse_metric if {
	metrics.collapse_report.frameworks == 5
	metrics.collapse_report.distinct_themes_referenced <= 7
	metrics.collapse_report.framework_theme_references > metrics.collapse_report.distinct_themes_referenced
}
