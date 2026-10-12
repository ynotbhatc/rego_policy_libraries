package supply_chain.ssdf_genai_test

import rego.v1

# Generated smoke test for benchmarks/supply_chain/ssdf_genai/ssdf_genai.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_ssdf_genai_loads_on_empty_input if {
	m := data.supply_chain.ssdf_genai with input as {}
	is_object(m)
}

test_ssdf_genai_report_wellformed_on_empty_input if {
	report := data.supply_chain.ssdf_genai.report with input as {}
	is_object(report)
	count(report) > 0
}

test_ssdf_genai_fail_closed_on_empty_input if {
	report := data.supply_chain.ssdf_genai.report with input as {}
	not object.get(report, "compliant", false) == true
}
