package ncsc_caf.main_test

import rego.v1

# Counts (audit 2026-11-24, round 3): the total is the 23 contributing outcomes on every input, failed is counted
# (no min clamp), and passed + failed + not applicable = total.

test_total_is_the_co_table if {
	count(data.ncsc_caf.main.all_co_achievements) == 23
	every doc in [{}, {"x": 1}, "true", null] {
		data.ncsc_caf.main.compliance_report.total_controls == 23 with input as doc
	}
}

test_counts_add_up_on_every_input if {
	every doc in [{}, {"x": 1}, "true", null] {
		r := data.ncsc_caf.main.compliance_report with input as doc
		r.total_controls == 23
		r.failed_controls == r.violation_count
		(r.passed_controls + r.failed_controls) + r.not_applicable_controls == 23
		r.passed_controls >= 0
		r.compliant == (r.failed_controls == 0)
	}
}

test_empty_input_fails_every_outcome if {
	r := data.ncsc_caf.main.compliance_report with input as {}
	r.failed_controls == 23
	r.passed_controls == 0
}

test_all_achieved_counts_every_outcome_passed if {
	r := data.ncsc_caf.main.compliance_report with data.ncsc_caf.main.all_co_achievements as {co: "achieved" | some co, _ in data.ncsc_caf.main.all_co_achievements}
	r.total_controls == 23
	r.failed_controls == 0
	r.passed_controls == 23
}
