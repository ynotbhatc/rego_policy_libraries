# Tests for ftc_red_flags.main — 16 CFR 681.1 (Red Flags) and 682.3 (Disposal).
package ftc_red_flags.main_test

import rego.v1

import data.ftc_red_flags.main

_all := {id: true | some id, _ in main.obligations}

_gates_on := {"is_financial_institution_or_creditor_with_covered_accounts": true, "possesses_consumer_report_information": true}

test_row_counts_pinned if {
	count(main.obligations_list) == 12
	count(main.obligations) == 12
	count({id | some id, r in main.obligations; r.section == "681.1"}) == 11
	count({id | some id, r in main.obligations; r.section == "682.3"}) == 1
	count(main.appendix_a_guidelines) == 11
	count(main.appendix_a_supplement_a_examples) == 26
	count(main.disposal_examples) == 5
	main.compliance_report.standard_total == 12 with input as {}
}

test_every_row_has_known_section_and_prefix if {
	count({id | some id, r in main.obligations; not main.sections[r.section]}) == 0
	count({id | some id, r in main.obligations; not startswith(id, concat("", [r.section, "("]))}) == 0
}

test_empty_input_fails_closed if {
	r := main.compliance_report with input as {}
	r.compliant == false
	some m in r.violations
	contains(m, "FAIL-CLOSED")

	# FAIL-CLOSED + 2 undeclared gates
	r.violation_count == 3
}

test_all_true_with_gates_on_is_compliant if {
	inp := {"ftc_red_flags": object.union(_gates_on, {"obligations": _all})}
	main.compliant with input as inp
	r := main.compliance_report with input as inp
	r.rows_evaluated == 12
}

test_disposal_only if {
	inp := {"ftc_red_flags": {"is_financial_institution_or_creditor_with_covered_accounts": false, "possesses_consumer_report_information": true, "obligations": {}}}
	r := main.compliance_report with input as inp
	r.rows_evaluated == 1
	r.sections["682.3"].gaps == ["682.3(a)"]
	r.sections["681.1"].rows_evaluated == 0
}

test_one_false_is_named if {
	inp := {"ftc_red_flags": object.union(_gates_on, {"obligations": object.union(_all, {"681.1(e)(1)": false})})}
	v := main.violations with input as inp
	count(v) == 1
	some m in v
	contains(m, "16 CFR 681.1(e)(1)")
}

test_unknown_id_and_guideline_id_rejected if {
	inp := {"ftc_red_flags": object.union(_gates_on, {"obligations": object.union(_all, {"681.2(c)": true, "682.3(b)(1)": true})})}
	v := main.violations with input as inp
	count(v) == 2
	some m in v
	contains(m, "unknown id 681.2(c)")
}

test_non_object_container_fails_closed if {
	v := main.violations with input as {"ftc_red_flags": object.union(_gates_on, {"obligations": true})}
	some m in v
	contains(m, "FAIL-CLOSED")
}
