package nist.sp800_53.maintenance_logic_test

# MA-1 to MA-7: all-pass fixture, empty input, one flip per control id, type traps.

import rego.v1

_pass := {"ma_controls": {
	"policy": {"documented": true, "official_designated": true, "review": {"days_since_last": 100, "odp": {"frequency_days": 365}}},
	"procedures": {"documented": true, "review": {"days_since_last": 200, "odp": {"frequency_days": 365}}},
	"controlled_maintenance": {
		"records_scheduled_documented_reviewed": true,
		"activities_approved_and_monitored": true,
		"offsite_removal_approved": true,
		"media_sanitized_before_offsite": true,
		"controls_checked_after_maintenance": true,
		"records_include_required_information": true,
	},
	"maintenance_tools": {"approved": true, "controlled": true, "monitored": true, "review": {"days_since_last": 30, "odp": {"frequency_days": 365}}},
	"nonlocal_maintenance": {
		"approved_and_monitored": true,
		"tools_per_policy_and_security_plan": true,
		"strong_authentication": true,
		"records_maintained": true,
		"sessions_terminated_on_completion": true,
	},
	"maintenance_personnel": {
		"authorization_process_established": true,
		"authorized_list_maintained": true,
		"unescorted_access_verified": true,
		"supervisors_designated": true,
	},
	"timely_maintenance": {"components_covered": true, "max_hours_to_support": 24, "odp": {"time_period_hours": 48}},
	"field_maintenance": {"attestation": {"attested": true, "by": "Facilities manager", "date": "2026-11-01"}},
}}

# Control ids that have a finding ("NIST MA-3: ..." -> "MA-3"); the colon keeps MA-1 apart from MA-10+.
_failing(r) := {id |
	some v in r.violations
	id := substring(v, 5, indexof(v, ":") - 5)
}

_msg(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.maintenance.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.maintenance.compliance_report with input as {}
	ids := data.nist.sp800_53.maintenance.evaluated_controls with input as {}
	count(r.violations) == count(ids)
	_failing(r) == ids
	r.compliant == false
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.maintenance.evaluated_controls == {"MA-1", "MA-2", "MA-3", "MA-4", "MA-5", "MA-6", "MA-7"}
}

test_ma1_policy_not_documented if {
	inp := object.union(_pass, {"ma_controls": {"policy": {"documented": false}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-1"}
}

test_ma1_lists_every_unmet_element_in_one_finding if {
	inp := object.union(_pass, {"ma_controls": {
		"policy": {"official_designated": false},
		"procedures": {"review": {"days_since_last": 400}},
	}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	f := _msg(r, "MA-1")
	count(f) == 1
	contains(f[0], "official_designated is false")
	contains(f[0], "Procedures review last done 400 days ago")
	_failing(r) == {"MA-1"}
}

test_ma1_missing_odp_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"policy": {"review": {"odp": {"frequency_days": null}}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	f := _msg(r, "MA-1")
	count(f) == 1
	contains(f[0], "evidence missing: input.ma_controls.policy.review.odp.frequency_days not collected")
}

test_ma2_offsite_removal_not_approved if {
	inp := object.union(_pass, {"ma_controls": {"controlled_maintenance": {"offsite_removal_approved": false}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-2"}
}

test_ma3_tool_review_overdue if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_tools": {"review": {"days_since_last": 400}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-3"}
	contains(_msg(r, "MA-3")[0], "365")
}

test_ma3_days_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_tools": {"review": {"days_since_last": "1"}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-3"}
	contains(_msg(r, "MA-3")[0], "evidence missing")
}

test_ma3_days_as_null_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_tools": {"review": {"days_since_last": null}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-3"}
	contains(_msg(r, "MA-3")[0], "evidence missing")
}

test_ma4_no_strong_authentication if {
	inp := object.union(_pass, {"ma_controls": {"nonlocal_maintenance": {"strong_authentication": false}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-4"}
}

test_ma4_boolean_as_string_is_a_finding if {
	inp := object.union(_pass, {"ma_controls": {"nonlocal_maintenance": {"strong_authentication": "true"}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-4"}
	contains(_msg(r, "MA-4")[0], "evidence missing")
}

test_ma5_unescorted_access_not_verified if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_personnel": {"unescorted_access_verified": false}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-5"}
}

test_ma6_support_slower_than_odp if {
	inp := object.union(_pass, {"ma_controls": {"timely_maintenance": {"max_hours_to_support": 72}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-6"}
	contains(_msg(r, "MA-6")[0], "72 hours")
}

test_ma6_hours_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"timely_maintenance": {"max_hours_to_support": "1"}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-6"}
	contains(_msg(r, "MA-6")[0], "evidence missing")
}

test_ma6_odp_as_null_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"timely_maintenance": {"odp": {"time_period_hours": null}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-6"}
	contains(_msg(r, "MA-6")[0], "evidence missing")
}

test_ma7_attested_as_string_is_a_finding if {
	inp := object.union(_pass, {"ma_controls": {"field_maintenance": {"attestation": {"attested": "true"}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-7"}
}

test_ma7_attestation_without_attester_is_a_finding if {
	inp := object.union(_pass, {"ma_controls": {"field_maintenance": {"attestation": {"by": " "}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-7"}
}
