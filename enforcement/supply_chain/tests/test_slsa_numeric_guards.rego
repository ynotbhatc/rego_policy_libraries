package supply_chain.slsa_numeric_guards_test

import rego.v1

# null sorts below every number: a CVE with no numeric CVSS score must still produce a finding.
test_null_cvss_score_is_a_finding if {
	vs := data.supply_chain.slsa.violations with input as {"dependencies": [{"name": "lib", "version": "1.0.0", "vulnerabilities": [{"cve_id": "CVE-2026-0001", "cvss_score": null}]}]}
	some v in vs
	contains(v, "no numeric CVSS score")
}

test_string_cvss_score_is_a_finding if {
	vs := data.supply_chain.slsa.violations with input as {"dependencies": [{"name": "lib", "version": "1.0.0", "vulnerabilities": [{"cve_id": "CVE-2026-0001", "cvss_score": "9.8"}]}]}
	some v in vs
	contains(v, "no numeric CVSS score")
}

test_numeric_cvss_score_no_type_finding if {
	vs := data.supply_chain.slsa.violations with input as {"dependencies": [{"name": "lib", "version": "1.0.0", "vulnerabilities": [{"cve_id": "CVE-2026-0001", "cvss_score": 3.1}]}]}
	every v in vs {
		not contains(v, "no numeric CVSS score")
	}
}
