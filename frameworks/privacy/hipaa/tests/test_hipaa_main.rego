# Integration test for hipaa.main - every module green on the shared fixture.
package hipaa.main_test

import rego.v1

import data.hipaa.test_fixtures as fx

test_hipaa_main_all_green_is_compliant if {
	r := data.hipaa.main.report with input as fx.full_input
	r.overall_compliant == true
	r.domains_passing == 5
	r.domains_total == 5
	r.domains.part_162.satisfied == 43
	r.domains.security_rule.details.satisfied == 68
}

test_hipaa_main_one_module_failing_fails_overall if {
	inp := object.union(fx.full_input, {"hipaa": {"part_160": {"160.105": false}}})
	r := data.hipaa.main.report with input as inp
	r.overall_compliant == false
	r.domains_passing == 4
}

# Audit 2026-11-17: advisories are collected but never decide compliance.
test_advisories_collected_without_affecting_compliance if {
	inp := object.union(fx.full_input, {"encryption": {"key_rotation_days": 900}, "tls": {"mutual_tls_for_phi_apis": false}})
	r := data.hipaa.main.compliance_report with input as inp
	r.compliant == true
	count(r.advisories) == 2
}
