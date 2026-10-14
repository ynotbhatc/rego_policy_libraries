# Tests for far_cyber.main — FAR 52.204-21, 52.204-25, 52.204-27 contractor obligations.
package far_cyber.main_test

import rego.v1

import data.far_cyber.main

_all := {id: true | some id, _ in main.requirements}

_gates_on := {"contract_includes_52_204_21": true, "contract_includes_52_204_25": true, "contract_includes_52_204_27": true}

_gates_off := {"contract_includes_52_204_21": false, "contract_includes_52_204_25": false, "contract_includes_52_204_27": false}

test_row_counts_pinned if {
	count(main.requirements_list) == 24
	count(main.requirements) == 24
	count({id | some id, r in main.requirements; r.section == "52.204-21"}) == 16
	count({id | some id, r in main.requirements; r.section == "52.204-25"}) == 6
	count({id | some id, r in main.requirements; r.section == "52.204-27"}) == 2
	main.compliance_report.standard_total == 24 with input as {}
}

test_every_row_has_known_section_and_prefix if {
	count({id | some id, r in main.requirements; not main.sections[r.section]}) == 0
	count({id | some id, r in main.requirements; not startswith(id, concat("", [r.section, "("]))}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED")

	# FAIL-CLOSED + 3 undeclared gates; no clause is evaluated
	r.violation_count == 4
	r.gates.contract_includes_52_204_21 == "undeclared"
}

test_all_true_with_gates_on_is_compliant if {
	inp := {"far_cyber": object.union(_gates_on, {"requirements": _all})}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.rows_evaluated == 24
	r.rows_attested == 24
	r.clauses["52.204-21"].rows_attested == 16
}

test_gates_off_with_empty_container_is_compliant if {
	r := main.compliance_report with input as {"far_cyber": object.union(_gates_off, {"requirements": {}})}
	r.compliant == true
	r.rows_evaluated == 0
}

test_one_false_is_named if {
	inp := {"far_cyber": object.union(_gates_on, {"requirements": object.union(_all, {"52.204-25(d)(2)(i)": false})})}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "FAR 52.204-25(d)(2)(i)")
	contains(m, "Within one business day")
	r := main.compliance_report with input as inp
	r.clauses["52.204-25"].gaps == ["52.204-25(d)(2)(i)"]
}

test_string_true_rejected_and_unknown_id_flagged if {
	inp := {"far_cyber": object.union(_gates_on, {"requirements": object.union(_all, {"52.204-21(b)(1)(x)": "true", "52.204-23(b)": true})})}
	v := main.violations with input as inp
	count(v) == 2
	some m1 in v
	contains(m1, "FAR 52.204-21(b)(1)(x)")
	some m2 in v
	contains(m2, "unknown id 52.204-23(b)")
}

test_only_52_204_21_gate_on if {
	gates := object.union(_gates_off, {"contract_includes_52_204_21": true})
	r := main.compliance_report with input as {"far_cyber": object.union(gates, {"requirements": {}})}
	r.rows_evaluated == 16
	r.violation_count == 16
	r.clauses["52.204-27"].rows_evaluated == 0
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"far_cyber": object.union(_gates_off, {"requirements": ["52.204-21(c)"]})}
	count(v) == 1
	some m in v
	contains(m, "FAIL-CLOSED")
}

test_report_carries_notification_clocks if {
	r := main.compliance_report with input as {}
	startswith(r.notification_clocks["52.204-25(d)(2)(i)"], "Within one business day")
}
