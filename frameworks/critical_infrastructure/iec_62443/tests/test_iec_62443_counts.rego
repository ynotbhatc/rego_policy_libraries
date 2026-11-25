package iec_62443_counts_test

import rego.v1

# Counts (audit 2026-11-24, round 3): the total is the 51 system security requirements plus the four process
# modules (55) on every input, failed counts controls and is never clamped to a declared figure, and
# passed + failed + not applicable = total. Findings (violation_count) are counted apart.

_all_pass := data.iec_62443_evidence_rule_test.all_pass

# 60 ICS systems that all fail the same per-system checks: findings multiply, controls do not
_many_systems := object.union(_all_pass, {"ics_systems": [s |
	some i in numbers.range(1, 60)
	s := object.union(_all_pass.ics_systems[0], {"name": sprintf("sys-%d", [i]), "rate_limiting_enabled": false, "backup_configured": false, "resource_monitoring_enabled": false})
]})

_arith(r) if {
	r.total_controls == 55
	(r.passed_controls + r.failed_controls) + r.not_applicable_controls == 55
	r.passed_controls >= 0
	r.failed_controls >= 0
	r.compliant == (r.failed_controls == 0)
}

test_empty_input if {
	r := data.iec_62443.main.compliance_report with input as {}
	_arith(r)
	r.failed_controls == 55
	r.passed_controls == 0
}

test_all_pass_fixture if {
	r := data.iec_62443.main.compliance_report with input as _all_pass
	_arith(r)
	r.failed_controls == 0
	r.passed_controls == 55
	r.violation_count == 0
}

test_many_failing_entities_are_not_clamped_and_not_miscounted if {
	r := data.iec_62443.main.compliance_report with input as _many_systems
	_arith(r)
	r.compliant == false
	r.violation_count > 60
	r.failed_controls < r.violation_count
	r.failed_controls > 0
}

test_other_inputs if {
	every doc in [{"target_sl": 4}, {"ics_systems": "yes"}] {
		r := data.iec_62443.main.compliance_report with input as doc
		_arith(r)
	}
}
