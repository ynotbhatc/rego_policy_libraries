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

# ── Audit 2026-11-23: score, findings and counts come from one set of checks ─

logical_access_true := {
	"unique_user_ids": {"required": true},
	"strong_authentication": {"enforced": true},
	"password_policy": {"compliant": true},
	"session_management": {"secure": true},
	"account_lockout": {"configured": true},
}

test_empty_data_counts_add_up if {
	c := data.sox.itgc.control_counts
	c.total_controls == 34
	c.failed_controls == 34
	c.passed_controls == 0
}

test_every_family_reports_each_failed_check if {
	e := data.sox.itgc.itgc_control_effectiveness
	count(e.access_controls.key_findings) == 5
	count(e.financial_applications.key_findings) == 4
	total := sum([count(family.key_findings) | some family in e])
	total == data.sox.itgc.control_counts.failed_controls
}

# Before: the area flag gated the verdict but was neither scored nor reported.
test_area_attestation_is_scored_and_reported if {
	message := "Access controls are not attested as in place (data.sox.itgc.access_controls.implemented)"
	message in data.sox.itgc.itgc_control_effectiveness.access_controls.key_findings
	s := data.sox.itgc.access_controls_score with data.sox.itgc.access_controls as {"implemented": true}
	s == 0.2
	e := data.sox.itgc.itgc_control_effectiveness with data.sox.itgc.access_controls as {"implemented": true}
	count(e.access_controls.key_findings) == 4
	not message in e.access_controls.key_findings
}

test_one_passing_check_moves_score_findings_and_counts_together if {
	s := data.sox.itgc.access_controls_score with data.sox.itgc.logical_access as logical_access_true
	s == 0.2
	e := data.sox.itgc.itgc_control_effectiveness with data.sox.itgc.logical_access as logical_access_true
	not "Logical access controls require strengthening" in e.access_controls.key_findings
	count(e.access_controls.key_findings) == 4
	c := data.sox.itgc.control_counts with data.sox.itgc.logical_access as logical_access_true
	c.passed_controls == 1
	c.failed_controls == 33
	c.passed_controls + c.failed_controls == c.total_controls
}

# Only the boolean true is evidence: the string "no" used to satisfy the check.
test_string_evidence_does_not_pass if {
	stringy := object.union(logical_access_true, {"unique_user_ids": {"required": "no"}})
	not data.sox.itgc.logical_access_controls_effective with data.sox.itgc.logical_access as stringy
	data.sox.itgc.logical_access_controls_effective with data.sox.itgc.logical_access as logical_access_true
}
