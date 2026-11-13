package cis_rocky_linux_9_test

import rego.v1

# Generated smoke test for benchmarks/cis/rocky_linux_9/cis_rocky_linux_9_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_rocky_linux_9_complete_loads_on_empty_input if {
	m := data.cis_rocky_linux_9 with input as {}
	is_object(m)
}

# Semantic review 2026-11-13: violations are strings, so risk and recommendations must derive from them.
test_risk_level_not_low_when_violations_exist if {
	s := data.cis_rocky_linux_9.executive_summary with input as {}
	s.total_violations > 0
	s.risk_level != "low"
}

test_recommendations_built_from_violation_strings if {
	recs := data.cis_rocky_linux_9.generate_recommendations with input as {}
	count(recs) > 0
	some r in recs
	r.control != ""
}
