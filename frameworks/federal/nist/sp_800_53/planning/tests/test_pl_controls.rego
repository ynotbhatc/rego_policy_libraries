package nist.sp800_53.planning_logic_test

# Logic tests for the PL family: all-pass fixture, fail-closed on empty input, one id per failing case,
# type traps, and the evaluated id list. Every test binds its own input (no `with` inside helpers).

import rego.v1

_ids(vs) := {m[0][1] |
	some v in vs
	m := regex.find_all_string_submatch_n(`^NIST ([A-Z]{2}-[0-9]+(?:\([0-9]+\))?): `, v, 1)
	count(m) == 1
}

# Empty input yields evidence missing for fact controls and a missing attestation for organizational ones.
_fail_closed_message(v) if contains(v, "evidence missing")

_fail_closed_message(v) if contains(v, "not attested")

_pass := {"pl_controls": {
	"policy": {
		"documented": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"procedures": {
		"documented": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"official": {"designated": true},
	"ssp": {
		"documented": true,
		"required_content_complete": true,
		"distributed": true,
		"protected": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"rules_of_behavior": {
		"established": true,
		"reacknowledgment_required": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
		"users_without_acknowledgment": 0,
		"social_media_restrictions": {"social_media_use": true, "public_posting": true, "external_account_credentials": true},
	},
	"conops": {
		"documented": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"architecture": {
		"protection_approach_described": true,
		"pii_processing_described": true,
		"enterprise_integration_described": true,
		"external_dependencies_described": true,
		"changes_reflected": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"central_management": {"centrally_managed": true},
	"baseline": {
		"selected": true,
		"name": "NIST SP 800-53B moderate",
	},
	"tailoring": {"actions_applied": true},
}}

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.planning.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
	r.controls_evaluated == 9
}

test_empty_input_one_finding_per_control if {
	vs := data.nist.sp800_53.planning.violation with input as {}
	ec := data.nist.sp800_53.planning.evaluated_controls with input as {}
	count(vs) == count(ec)
	_ids(vs) == ec
	every v in vs {
		_fail_closed_message(v)
	}
	r := data.nist.sp800_53.planning.compliance_report with input as {}
	r.compliant == false
}

test_non_object_family_root_fails_closed if {
	vs := data.nist.sp800_53.planning.violation with input as {"pl_controls": "yes"}
	count(vs) == 9
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.planning.evaluated_controls == {"PL-1", "PL-2", "PL-4", "PL-4(1)", "PL-7", "PL-8", "PL-9", "PL-10", "PL-11"}
}

test_pl1_failing_case_flips_only_pl1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/policy/documented", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
	count(vs) == 1
}

test_pl2_failing_case_flips_only_pl2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/ssp/documented", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-2"}
	count(vs) == 1
}

test_pl4_failing_case_flips_only_pl4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/rules_of_behavior/established", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-4"}
	count(vs) == 1
}

test_pl7_failing_case_flips_only_pl7 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/conops/documented", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-7"}
	count(vs) == 1
}

test_pl8_failing_case_flips_only_pl8 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/architecture/protection_approach_described", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-8"}
	count(vs) == 1
}

test_pl9_failing_case_flips_only_pl9 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/central_management/centrally_managed", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-9"}
	count(vs) == 1
}

test_pl10_failing_case_flips_only_pl10 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/baseline/selected", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-10"}
	count(vs) == 1
}

test_pl11_failing_case_flips_only_pl11 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/tailoring/actions_applied", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-11"}
	count(vs) == 1
}

test_pl1_procedures_documented_flips_only_pl1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/procedures/documented", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
	count(vs) == 1
}

test_pl1_official_designated_flips_only_pl1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/official/designated", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
	count(vs) == 1
}

test_pl1_policy_days_since_last_flips_only_pl1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/policy/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
	count(vs) == 1
}

test_pl1_procedures_days_since_last_flips_only_pl1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/procedures/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
	count(vs) == 1
}

test_pl2_ssp_required_content_complete_flips_only_pl2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/ssp/required_content_complete", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-2"}
	count(vs) == 1
}

test_pl2_ssp_distributed_flips_only_pl2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/ssp/distributed", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-2"}
	count(vs) == 1
}

test_pl2_ssp_protected_flips_only_pl2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/ssp/protected", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-2"}
	count(vs) == 1
}

test_pl2_ssp_days_since_last_flips_only_pl2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/ssp/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-2"}
	count(vs) == 1
}

test_pl4_rules_of_behavior_reacknowledgment_required_flips_only_pl4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/rules_of_behavior/reacknowledgment_required", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-4"}
	count(vs) == 1
}

test_pl4_rules_of_behavior_days_since_last_flips_only_pl4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/rules_of_behavior/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-4"}
	count(vs) == 1
}

test_pl4_rules_of_behavior_users_without_acknowledgment_flips_only_pl4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/rules_of_behavior/users_without_acknowledgment", "value": 3}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-4"}
	count(vs) == 1
}

test_pl7_conops_days_since_last_flips_only_pl7 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/conops/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-7"}
	count(vs) == 1
}

test_pl8_architecture_pii_processing_described_flips_only_pl8 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/architecture/pii_processing_described", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-8"}
	count(vs) == 1
}

test_pl8_architecture_enterprise_integration_described_flips_only_pl8 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/architecture/enterprise_integration_described", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-8"}
	count(vs) == 1
}

test_pl8_architecture_external_dependencies_described_flips_only_pl8 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/architecture/external_dependencies_described", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-8"}
	count(vs) == 1
}

test_pl8_architecture_changes_reflected_flips_only_pl8 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/architecture/changes_reflected", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-8"}
	count(vs) == 1
}

test_pl8_architecture_days_since_last_flips_only_pl8 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/architecture/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-8"}
	count(vs) == 1
}

test_pl10_baseline_name_flips_only_pl10 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/baseline/name", "value": ""}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-10"}
	count(vs) == 1
}

test_numeric_fact_as_string_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/policy/days_since_last", "value": "1"}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
	some v in vs
	contains(v, "evidence missing")
	contains(v, "policy.days_since_last")
}

test_numeric_fact_as_null_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/policy/days_since_last", "value": null}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
	some v in vs
	contains(v, "evidence missing")
	contains(v, "policy.days_since_last")
}

test_boolean_fact_as_string_true_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/policy/documented", "value": "true"}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
}

test_boolean_fact_as_one_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/policy/documented", "value": 1}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
}

test_pl1_lists_every_unmet_element if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/policy/documented", "value": false}, {"op": "replace", "path": "/pl_controls/procedures/days_since_last", "value": 999}, {"op": "remove", "path": "/pl_controls/official/designated"}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-1"}
	count(vs) == 1
	some v in vs
	contains(v, "evidence missing")
	contains(v, "input.pl_controls.official.designated")
	contains(v, "policy not documented")
	contains(v, "999 days ago")
}

test_pl1_review_within_frequency_passes if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/policy/days_since_last", "value": 365}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	count(vs) == 0
}

test_pl4_1_public_posting_unrestricted_flips_only_pl4_1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/rules_of_behavior/social_media_restrictions/public_posting", "value": false}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	vs == {"NIST PL-4(1): rules of behavior restrictions not met: rules of behavior do not restrict posting organizational information on public websites"}
}

test_pl4_1_boolean_as_string_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pl_controls/rules_of_behavior/social_media_restrictions/social_media_use", "value": "true"}])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-4(1)"}
	contains(concat("", vs), "evidence missing — input.pl_controls.rules_of_behavior.social_media_restrictions.social_media_use not collected")
}

test_pl4_base_unaffected_by_pl4_1_facts if {
	inp := json.remove(_pass, ["pl_controls/rules_of_behavior/social_media_restrictions"])
	vs := data.nist.sp800_53.planning.violation with input as inp
	_ids(vs) == {"PL-4(1)"}
	every v in vs {
		contains(v, "evidence missing")
	}
}
