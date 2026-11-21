package nist.sp800_53.maintenance_logic_test

# MA-1 to MA-7 and MA-3(1), MA-3(2), MA-3(3): all-pass fixture, empty input, one flip per control id, type traps.

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
		"automation": {"automated": true, "records_incomplete": 0},
	},
	"maintenance_tools": {
		"approved": true, "controlled": true, "monitored": true, "review": {"days_since_last": 30, "odp": {"frequency_days": 365}},
		"inspection": {"tools_not_inspected": 0},
		"media_inspection": {"media_not_scanned": 0},
		"removal": {"removals_without_disposition": 0},
	},
	"nonlocal_maintenance": {
		"approved_and_monitored": true,
		"tools_per_policy_and_security_plan": true,
		"strong_authentication": true,
		"records_maintained": true,
		"sessions_terminated_on_completion": true,
		"comparable_security": {"sessions_meeting_neither": 0},
	},
	"maintenance_personnel": {
		"authorization_process_established": true,
		"authorized_list_maintained": true,
		"unescorted_access_verified": true,
		"supervisors_designated": true,
		"uncleared": {"alternate_controls_defined": true, "sessions_without_escort": 0, "sessions_without_storage_protection": 0},
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
	data.nist.sp800_53.maintenance.evaluated_controls == {
		"MA-1", "MA-2", "MA-2(2)", "MA-3", "MA-3(1)", "MA-3(2)", "MA-3(3)", "MA-4", "MA-4(3)", "MA-5", "MA-5(1)",
		"MA-6", "MA-7",
	}
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

test_empty_input_every_finding_is_evidence_missing if {
	r := data.nist.sp800_53.maintenance.compliance_report with input as {}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_ma7_attestation_false_is_not_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"field_maintenance": {"attestation": {"attested": false}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-7"}
	msg := _msg(r, "MA-7")[0]
	contains(msg, "not attested")
	not contains(msg, "evidence missing")
}

test_ma7_attestation_absent_is_evidence_missing if {
	inp := json.remove(_pass, ["ma_controls/field_maintenance/attestation"])
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-7"}
	msg := _msg(r, "MA-7")[0]
	contains(msg, "evidence missing — input.ma_controls.field_maintenance.attestation not collected")
	contains(msg, "not attested")
}

test_ma3_1_uninspected_tools_flip_only_ma3_1 if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_tools": {"inspection": {"tools_not_inspected": 2}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	r.violations == {"NIST MA-3(1): 2 maintenance tools used without an inspection for improper or unauthorized modification"}
}

test_ma3_1_count_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_tools": {"inspection": {"tools_not_inspected": "1"}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-3(1)"}
	contains(_msg(r, "MA-3(1)")[0], "evidence missing")
}

test_ma3_2_unscanned_media_flip_only_ma3_2 if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_tools": {"media_inspection": {"media_not_scanned": 1}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-3(2)"}
}

test_ma3_2_count_as_null_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_tools": {"media_inspection": {"media_not_scanned": null}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-3(2)"}
	contains(_msg(r, "MA-3(2)")[0], "evidence missing")
}

test_ma3_3_removal_without_disposition_flips_only_ma3_3 if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_tools": {"removal": {"removals_without_disposition": 1}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-3(3)"}
}

test_ma3_3_negative_count_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_tools": {"removal": {"removals_without_disposition": -2}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-3(3)"}
	contains(_msg(r, "MA-3(3)")[0], "evidence missing")
}

test_ma3_base_unaffected_by_enhancement_facts if {
	inp := json.remove(_pass, ["ma_controls/maintenance_tools/inspection", "ma_controls/maintenance_tools/media_inspection", "ma_controls/maintenance_tools/removal"])
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-3(1)", "MA-3(2)", "MA-3(3)"}
}

# --- High-baseline enhancements: one flip, one evidence-missing case ---------------------------------------------

test_ma2_2_incomplete_records_flip_only_ma2_2 if {
	inp := object.union(_pass, {"ma_controls": {"controlled_maintenance": {"automation": {"records_incomplete": 3}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	r.violations == {"NIST MA-2(2): Maintenance actions not scheduled, conducted and documented with automated mechanisms — 3 maintenance, repair or replacement actions with an incomplete or out-of-date record"}
}

test_ma2_2_automated_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"controlled_maintenance": {"automation": {"automated": "true"}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	r.violations == {"NIST MA-2(2): evidence missing — input.ma_controls.controlled_maintenance.automation.automated not collected"}
}

test_ma4_3_session_meeting_neither_flips_only_ma4_3 if {
	inp := object.union(_pass, {"ma_controls": {"nonlocal_maintenance": {"comparable_security": {"sessions_meeting_neither": 1}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-4(3)"}
	not contains(concat("", r.violations), "evidence missing")
}

test_ma4_3_count_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"ma_controls": {"nonlocal_maintenance": {"comparable_security": {"sessions_meeting_neither": "0"}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-4(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_ma5_1_unescorted_session_flips_only_ma5_1 if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_personnel": {"uncleared": {"sessions_without_escort": 2}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-5(1)"}
	contains(concat("", r.violations), "2 maintenance sessions by personnel without appropriate access not escorted")
}

test_ma5_1_no_alternate_controls_flips_only_ma5_1 if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_personnel": {"uncleared": {"alternate_controls_defined": false}}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-5(1)"}
}

test_ma5_1_missing_is_evidence_missing_and_base_unaffected if {
	inp := object.union(_pass, {"ma_controls": {"maintenance_personnel": {"uncleared": null}}})
	r := data.nist.sp800_53.maintenance.compliance_report with input as inp
	_failing(r) == {"MA-5(1)"}
	contains(concat("", r.violations), "evidence missing")
}
