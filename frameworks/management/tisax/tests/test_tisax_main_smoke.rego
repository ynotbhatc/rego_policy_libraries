package tisax.main_test

import rego.v1

# Generated smoke test for frameworks/management/tisax/tisax_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_tisax_main_loads_on_empty_input if {
	m := data.tisax.main with input as {}
	is_object(m)
}

test_tisax_main_report_wellformed_on_empty_input if {
	report := data.tisax.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_tisax_main_fail_closed_on_empty_input if {
	report := data.tisax.main.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_tisax_main_violations_on_empty_input if {
	v := data.tisax.main.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: PD checks apply when assessment_level is absent; explicit AL1 skips them.
test_semrev_pd_checks_apply_without_assessment_level if {
	v := data.tisax.main.violations with input as {}
	some m in v
	startswith(m, "TISAX PD AL2: Prototype handling")
}

test_semrev_pd_checks_skipped_for_explicit_al1 if {
	v := data.tisax.main.violations with input as {"assessment_level": 1}
	count([m | some m in v; startswith(m, "TISAX PD AL2")]) == 0
}

test_semrev_pd_checks_apply_for_al2 if {
	v := data.tisax.main.violations with input as {"assessment_level": 2}
	count([m | some m in v; startswith(m, "TISAX PD AL2")]) == 3
}
