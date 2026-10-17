package supply_chain.slsa_test

import rego.v1

# Validation fix pass 2026-10-17.

has_prefix(v, p) if {
	some m in v
	startswith(m, p)
}

test_copyleft_violation_is_emitted if {
	inp := {"policy": {"enforce_license_compliance": true}, "sbom": {"components": [{"name": "left-pad", "license_concluded": "GPL-3.0-only"}]}}
	v := data.supply_chain.slsa.violations with input as inp
	"License: left-pad uses GPL-3.0-only (strong copyleft — legal review required for commercial distribution)" in v
}

test_approved_exemption_suppresses_cvss_and_critical_violations if {
	dep := {"name": "lib", "version": "1.0.0", "vulnerabilities": [{"cve_id": "CVE-1", "cvss_score": 9.8, "severity": "critical", "exemption_approved": true}]}
	v := data.supply_chain.slsa.violations with input as {"dependencies": [dep]}
	not has_prefix(v, "Dependencies: lib@1.0.0 has")
}

test_exempted_spelling_also_suppresses if {
	dep := {"name": "lib", "version": "1.0.0", "vulnerabilities": [{"cve_id": "CVE-1", "cvss_score": 9.8, "severity": "critical", "exempted": true}]}
	v := data.supply_chain.slsa.violations with input as {"dependencies": [dep]}
	not has_prefix(v, "Dependencies: lib@1.0.0 has")
}

test_unexempted_cve_still_flagged if {
	dep := {"name": "lib", "version": "1.0.0", "vulnerabilities": [{"cve_id": "CVE-1", "cvss_score": 9.8, "severity": "critical"}]}
	v := data.supply_chain.slsa.violations with input as {"dependencies": [dep]}
	count({m | some m in v; startswith(m, "Dependencies: lib@1.0.0 has")}) == 2
}

signed(issuer) := {"artifact": {"signed": true, "signature_verified": true, "signing_identity": {"issuer": issuer}}}

test_lookalike_issuer_flagged if {
	v := data.supply_chain.slsa.violations with input as signed("https://gitlab.com.attacker.example")
	"Signing: Signing identity not from an approved OIDC provider" in v
}

test_exact_issuer_accepted if {
	v := data.supply_chain.slsa.violations with input as signed("https://token.actions.githubusercontent.com")
	not "Signing: Signing identity not from an approved OIDC provider" in v
	v2 := data.supply_chain.slsa.violations with input as signed("https://gitlab.com/")
	not "Signing: Signing identity not from an approved OIDC provider" in v2
}

prov(uri) := {"provenance": {"exists": true, "build_definition": {"external_parameters": {"source_uri": uri}}}}

test_source_uri_check_not_silently_skipped_without_policy if {
	v := data.supply_chain.slsa.violations with input as prov("https://github.com/org/repo")
	has_prefix(v, "Provenance: policy.expected_source_uri_prefix is not set")
}

test_source_uri_mismatch_flagged_and_match_passes if {
	bad := object.union(prov("https://evil.example/repo"), {"policy": {"expected_source_uri_prefix": "https://github.com/org/"}})
	good := object.union(prov("https://github.com/org/repo"), {"policy": {"expected_source_uri_prefix": "https://github.com/org/"}})
	vbad := data.supply_chain.slsa.violations with input as bad
	vgood := data.supply_chain.slsa.violations with input as good
	"Provenance: Build source URI does not match expected repository" in vbad
	not "Provenance: Build source URI does not match expected repository" in vgood
}

test_missing_source_uri_flagged if {
	v := data.supply_chain.slsa.violations with input as {"provenance": {"exists": true}, "policy": {"expected_source_uri_prefix": "https://github.com/org/"}}
	has_prefix(v, "Provenance: Build source URI missing")
}

floating_dep(version) := {"dependencies": [{"name": "d", "version": version}]}

test_floating_versions_flagged if {
	every ver in ["1.x", "1.2.X", "1.*", "latest", "^1.0.0"] {
		v := data.supply_chain.slsa.violations with input as floating_dep(ver)
		has_prefix(v, "Dependencies: Floating version")
	}
}

test_pinned_versions_not_flagged if {
	every ver in ["2.0.0-linux-x64", "1.0.0-rc.1", "3.4.5"] {
		v := data.supply_chain.slsa.violations with input as floating_dep(ver)
		not has_prefix(v, "Dependencies: Floating version")
	}
}

builder_input(id) := {"provenance": {"exists": true, "run_details": {"builder": {"id": id}}}}

test_builder_lookalike_flagged if {
	v := data.supply_chain.slsa.violations with input as builder_input("https://github.com/actions/runner-evil")
	"Provenance: Builder identity not in approved builder registry" in v
}

test_approved_builders_accepted if {
	every id in ["https://github.com/actions/runner", "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1.9.0"] {
		v := data.supply_chain.slsa.violations with input as builder_input(id)
		not "Provenance: Builder identity not in approved builder registry" in v
	}
}

test_controls_checked_reflects_inputs if {
	r := data.supply_chain.slsa.compliance_report with input as {}
	r.controls_checked.provenance == false
	r.controls_checked.sbom == false
	r2 := data.supply_chain.slsa.compliance_report with input as {"sbom": {"present": true}, "provenance": {"exists": true}}
	r2.controls_checked.sbom == true
	r2.controls_checked.provenance == true
}
