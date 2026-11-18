package nist.sp800_53.assessment_authorization_logic_test

# CA family: one finding per base control, fail closed, organization-defined frequencies.

import data.nist.sp800_53.assessment_authorization as ca
import rego.v1

# The ids that have a finding in a report ("NIST CA-2: ..." -> "CA-2").
_ids(r) := {trim_prefix(split(v, ":")[0], "NIST ") | some v in r.violations}

_freq(days, odp) := {"days_since_last": days, "odp": {"frequency_days": odp}}

_pass := {"ca_controls": {
	"policy_procedures": {
		"policy_documented": true,
		"procedures_documented": true,
		"official_designated": true,
		"policy_review": _freq(200, 365),
		"procedures_review": _freq(100, 365),
	},
	"control_assessment": object.union(
		{
			"assessor_selected": true,
			"plan_developed": true,
			"plan_approved_before_assessment": true,
			"report_produced": true,
			"results_provided": true,
		},
		_freq(300, 365),
	),
	"information_exchange": {
		"exchanges_approved_under_agreements": true,
		"agreements_document_requirements": true,
		"agreement_review": _freq(100, 365),
	},
	"poam": object.union({"documented": true}, _freq(20, 30)),
	"authorization": object.union(
		{
			"system_ao_assigned": true,
			"common_controls_ao_assigned": true,
			"common_controls_accepted": true,
			"authorized_to_operate": true,
			"common_controls_authorized_for_inheritance": true,
		},
		_freq(400, 1095),
	),
	"continuous_monitoring": {
		"strategy_implemented": true,
		"metrics_established": true,
		"frequencies_established": true,
		"ongoing_assessments": true,
		"ongoing_metric_monitoring": true,
		"correlation_and_analysis": true,
		"response_actions": true,
		"status_reporting": _freq(25, 30),
	},
	"penetration_testing": object.union({"defined_scope_covered": true}, _freq(200, 365)),
	"internal_connections": {
		"all_authorized": true,
		"all_documented": true,
		"terminated_on_defined_conditions": true,
		"review": _freq(60, 365),
	},
}}

test_all_pass_fixture_is_compliant if {
	fx := _pass
	r := ca.compliance_report with input as fx
	r.compliant == true
	r.violation_count == 0
}

test_evaluated_controls_match_the_catalog if {
	ca.evaluated_controls == {"CA-1", "CA-2", "CA-3", "CA-5", "CA-6", "CA-7", "CA-8", "CA-9"}
}

test_empty_input_one_finding_per_control if {
	r := ca.compliance_report with input as {}
	r.compliant == false
	count(r.violations) == count(ca.evaluated_controls)
	_ids(r) == ca.evaluated_controls
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

# --- each control: one failing case flips exactly that id -------------------------------------------------------

test_ca1_policy_review_overdue_flips_only_ca1 if {
	fx := object.union(_pass, {"ca_controls": {"policy_procedures": {"procedures_review": {"days_since_last": 500}}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-1"}
	contains(concat("", r.violations), "procedures last reviewed 500 days ago")
}

test_ca2_plan_not_approved_flips_only_ca2 if {
	fx := object.union(_pass, {"ca_controls": {"control_assessment": {"plan_approved_before_assessment": false}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-2"}
}

test_ca3_agreement_review_overdue_flips_only_ca3 if {
	fx := object.union(_pass, {"ca_controls": {"information_exchange": {"agreement_review": {"days_since_last": 366}}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-3"}
}

test_ca5_poam_stale_flips_only_ca5 if {
	fx := object.union(_pass, {"ca_controls": {"poam": {"days_since_last": 45}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-5"}
	contains(concat("", r.violations), "last updated 45 days ago; the organization-defined frequency is 30 days")
}

test_ca6_not_authorized_flips_only_ca6 if {
	fx := object.union(_pass, {"ca_controls": {"authorization": {"authorized_to_operate": false}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-6"}
}

test_ca7_no_correlation_flips_only_ca7 if {
	fx := object.union(_pass, {"ca_controls": {"continuous_monitoring": {"correlation_and_analysis": false}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-7"}
}

test_ca8_pentest_overdue_flips_only_ca8 if {
	fx := object.union(_pass, {"ca_controls": {"penetration_testing": {"days_since_last": 400}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-8"}
}

test_ca9_unauthorized_connection_flips_only_ca9 if {
	fx := object.union(_pass, {"ca_controls": {"internal_connections": {"all_authorized": false}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-9"}
}

# --- type traps -------------------------------------------------------------------------------------------------

test_numeric_fact_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"ca_controls": {"penetration_testing": {"days_since_last": "1"}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-8"}
	msg := concat("", r.violations)
	contains(msg, "evidence missing")
	contains(msg, "penetration_testing.days_since_last")
}

test_numeric_fact_as_null_is_evidence_missing if {
	fx := object.union(_pass, {"ca_controls": {"poam": {"odp": {"frequency_days": null}}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-5"}
	contains(concat("", r.violations), "evidence missing — input.ca_controls.poam.odp.frequency_days")
}

test_boolean_as_string_true_is_a_finding if {
	fx := object.union(_pass, {"ca_controls": {"authorization": {"system_ao_assigned": "true"}}})
	r := ca.compliance_report with input as fx
	_ids(r) == {"CA-6"}
	contains(concat("", r.violations), "system_ao_assigned is not true")
}

test_unmet_element_and_missing_evidence_share_one_finding if {
	fx := object.union(_pass, {"ca_controls": {"control_assessment": {"report_produced": false, "days_since_last": null}}})
	r := ca.compliance_report with input as fx
	count(r.violations) == 1
	msg := concat("", r.violations)
	contains(msg, "no control assessment report produced")
	contains(msg, "evidence missing — input.ca_controls.control_assessment.days_since_last not collected")
}
