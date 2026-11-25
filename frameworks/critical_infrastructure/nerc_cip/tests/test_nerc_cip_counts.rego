package nerc_cip.main_counts_test

import rego.v1

# Counts (audit 2026-11-24, round 3): the total is the 14 CIP standards on every input, failed counts standards
# and is never clamped, and passed + failed + not applicable = total. Findings are counted apart.

_arith(r) if {
	r.total_controls == 14
	(r.passed_controls + r.failed_controls) + r.not_applicable_controls == 14
	r.passed_controls >= 0
	r.failed_controls >= 0
	r.compliant == (r.failed_controls == 0)
}

# 80 people who all fail training and the risk assessment: findings multiply, the one standard fails once
_many_people := {"personnel": [p |
	some i in numbers.range(1, 80)
	p := {"person_id": sprintf("p%d", [i]), "training_completed": false, "risk_assessment_completed": false}
]}

test_empty_input if {
	r := data.nerc_cip.main.compliance_report with input as {}
	_arith(r)
	r.failed_controls == 14
	r.passed_controls == 0
}

test_many_failing_entities_do_not_exceed_the_total if {
	r := data.nerc_cip.main.compliance_report with input as _many_people
	_arith(r)
	r.violation_count >= 160
	r.failed_controls <= 14
	r.failed_controls == 14
}

test_other_inputs if {
	every doc in [{"x": 1}, {"personnel": "yes"}] {
		r := data.nerc_cip.main.compliance_report with input as doc
		_arith(r)
	}
}

# the one standard that fails because of the entities, with the others made compliant, counts once
test_a_single_standard_counts_once if {
	r := data.nerc_cip.main.compliance_report with input as _many_people
		with data.nerc_cip_main.standards_passing as 13
	r.failed_controls == 1
	r.passed_controls == 13
	r.violation_count >= 160
}
