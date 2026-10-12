package stig.kubernetes.main_test

import rego.v1

# Generated smoke test for benchmarks/stig/kubernetes/stig_kubernetes_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_stig_kubernetes_main_loads_on_empty_input if {
	m := data.stig.kubernetes.main with input as {}
	is_object(m)
}

test_stig_kubernetes_main_report_wellformed_on_empty_input if {
	report := data.stig.kubernetes.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_stig_kubernetes_main_fail_closed_on_empty_input if {
	report := data.stig.kubernetes.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_stig_kubernetes_main_violations_on_empty_input if {
	v := data.stig.kubernetes.main.violations with input as {}
	count(v) > 0
}
