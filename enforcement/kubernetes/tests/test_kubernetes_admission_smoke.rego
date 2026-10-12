package kubernetes.admission_test

import rego.v1

# Generated smoke test for enforcement/kubernetes/kubernetes_admission.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_kubernetes_admission_loads_on_empty_input if {
	m := data.kubernetes.admission with input as {}
	is_object(m)
}

test_kubernetes_admission_report_wellformed_on_empty_input if {
	report := data.kubernetes.admission.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

