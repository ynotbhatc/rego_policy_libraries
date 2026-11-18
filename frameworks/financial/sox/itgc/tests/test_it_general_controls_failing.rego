package sox.itgc_test

import rego.v1

test_itgc_compliant_false_not_undefined_when_controls_fail if {
	data.sox.itgc.itgc_compliant == false
}

test_score_defined_when_every_control_fails if {
	s := data.sox.itgc.itgc_compliance_score
	s == 0
}

test_risk_level_defined_when_controls_fail if {
	data.sox.itgc.itgc_risk_level == "CRITICAL"
}

test_findings_populated_for_failing_controls if {
	f := data.sox.itgc._get_access_control_findings
	count(f) > 0
}

test_one_false_check_still_scores if {
	# one of the four access-control checks failing (family score 0.75) contributes 0.75 / 7 of the score: a failure
	# lowers the score without zeroing it, and the other six families still count
	s := data.sox.itgc.itgc_compliance_score with data.sox.itgc.access_controls_score as 0.75
	abs(s - ((0.75 / 7) * 100)) < 0.001
}

test_financial_family_gates_verdict if {
	not data.sox.itgc.itgc_compliant with data.sox.itgc.financial_application_itgc_compliant as false
		with data.sox.itgc.access_controls_compliant as true
		with data.sox.itgc.change_management_compliant as true
		with data.sox.itgc.computer_operations_compliant as true
		with data.sox.itgc.system_development_compliant as true
		with data.sox.itgc.data_center_operations_compliant as true
		with data.sox.itgc.backup_recovery_compliant as true
}

test_all_families_true_is_compliant if {
	data.sox.itgc.itgc_compliant with data.sox.itgc.financial_application_itgc_compliant as true
		with data.sox.itgc.access_controls_compliant as true
		with data.sox.itgc.change_management_compliant as true
		with data.sox.itgc.computer_operations_compliant as true
		with data.sox.itgc.system_development_compliant as true
		with data.sox.itgc.data_center_operations_compliant as true
		with data.sox.itgc.backup_recovery_compliant as true
}
