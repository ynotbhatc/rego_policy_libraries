package stig.rhel_10.network_test

import rego.v1

# Generated smoke test for benchmarks/stig/rhel_10/network.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_network_loads_on_empty_input if {
	m := data.stig.rhel_10.network with input as {}
	is_object(m)
}

test_network_report_wellformed_on_empty_input if {
	report := data.stig.rhel_10.network.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_network_violations_on_empty_input if {
	v := data.stig.rhel_10.network.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: missing evidence must not pass.

test_missing_evidence_open_status_rhel_10_700870 if {
	data.stig.rhel_10.network.status_rhel_10_700870 == "Open" with input as {"x": 1}
}

test_missing_evidence_open_status_rhel_10_800020 if {
	data.stig.rhel_10.network.status_rhel_10_800020 == "Open" with input as {"x": 1}
}

# Semantic review 2026-11-13: `compliant` means no open finding at any category (RHEL 8/9 meaning);
# the CAT-I-only flag is kept as cat_i_compliant.
test_compliant_false_when_cat_ii_open if {
	r := data.stig.rhel_10.network.compliance_report with input as {"x": 1}
	r.compliant == false
	r.cat_i_compliant == true
}
