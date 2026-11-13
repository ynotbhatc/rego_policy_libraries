package cra.supply_chain_evidence_test

import rego.v1

# Generated smoke test for frameworks/compliance/cra/supply_chain_evidence/cra_supply_chain_evidence.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cra_supply_chain_evidence_loads_on_empty_input if {
	m := data.cra.supply_chain_evidence with input as {}
	is_object(m)
}

test_cra_supply_chain_evidence_report_wellformed_on_empty_input if {
	report := data.cra.supply_chain_evidence.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cra_supply_chain_evidence_fail_closed_on_empty_input if {
	report := data.cra.supply_chain_evidence.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# Semantic review 2026-11-13: bridge must match the strings SLSA really emits.
test_cra_bridge_purl_and_critical_cve_fire if {
	inp := {
		"sbom": {"present": true, "components": [{"name": "a"}]},
		"dependencies": [{"name": "lib", "version": "1.0.0", "vulnerabilities": [{"cve_id": "CVE-2024-1", "severity": "critical", "cvss_score": 9.8}]}],
	}
	v := data.cra.supply_chain_evidence.violation with input as inp
	some m in v
	contains(m, "missing PURL")
	some m2 in v
	contains(m2, "Critical CVE in third-party component with no documented exemption")
}
