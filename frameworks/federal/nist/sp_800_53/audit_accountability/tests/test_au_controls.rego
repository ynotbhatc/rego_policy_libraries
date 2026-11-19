package nist.sp800_53.audit_accountability_logic_test

# AU-11 retention is an organization-defined period (audit 2026-11-17): no fixed 365-day floor.

import data.nist.sp800_53.audit_accountability as au
import rego.v1

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

test_au11_meets_org_period_passes if {
	rr1 := au.compliance_report with input as {"au_controls": {"retention_period_days": 90, "odp": {"retention_period_days": 90}}}
	count(_finding(rr1, "AU-11")) == 0
}

test_au11_below_org_period_fails if {
	rr2 := au.compliance_report with input as {"au_controls": {"retention_period_days": 180, "odp": {"retention_period_days": 1095}}}
	f := _finding(rr2, "AU-11")
	count(f) == 1
	contains(f[0], "1095")
}

test_au11_missing_odp_is_missing_evidence if {
	rr3 := au.compliance_report with input as {"au_controls": {"retention_period_days": 3650}}
	f := _finding(rr3, "AU-11")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_au11_missing_retention_is_missing_evidence if {
	rr4 := au.compliance_report with input as {"au_controls": {"odp": {"retention_period_days": 365}}}
	f := _finding(rr4, "AU-11")
	count(f) == 1
	contains(f[0], "retention_period_days")
}

test_au_one_finding_per_evaluated_id_on_empty_input if {
	r := au.compliance_report with input as {}
	count(r.violations) == 17
	every id in au.evaluated_controls {
		count(_finding(r, id)) == 1
	}
}

# AU-8: UTC / offset, not synchronisation (AU-8(1) withdrawn, moved to SC-45(1)).
test_au8_utc_passes if {
	rr5 := au.compliance_report with input as {"au_controls": {"time_stamps": {"utc_or_offset_recorded": true}}}
	count(_finding(rr5, "AU-8")) == 0
}

test_au8_sync_alone_is_not_au8_evidence if {
	rr6 := au.compliance_report with input as {"au_controls": {"time_stamps": {"synchronized": true}}}
	count(_finding(rr6, "AU-8")) == 1
}

test_au8_false_fails if {
	rr7 := au.compliance_report with input as {"au_controls": {"time_stamps": {"utc_or_offset_recorded": false}}}
	count(_finding(rr7, "AU-8")) == 1
}

# --- NIST SP 800-53B Moderate enhancements and fail-closed existing rules ------------------------------------

_ids(r) := {trim_prefix(split(v, ":")[0], "NIST ") | some v in r.violations}

_pass := {"au_controls": {
	"policy": {"documented": true},
	"event_logging": {"enabled": true},
	"content_of_records": {
		"adequate": true,
		"additional_information": {"fields_present": ["session_id", "source_ip", "user"], "odp": {"fields": ["session_id", "source_ip"]}},
	},
	"storage_capacity": {"adequate": true},
	"response_to_failures": {"alerting": true},
	"review_and_analysis": {
		"regular": true,
		"automated_integration": {"mechanisms_integrated": ["siem"], "odp": {"mechanisms": ["siem"]}},
		"correlation": {"correlation_enabled": true, "uncorrelated_repositories": 0},
	},
	"reduction_and_reporting": {
		"tools_available": true,
		"automatic_processing": {"searchable_fields": ["user", "event_type", "time"], "sort_supported": true, "odp": {"fields": ["user", "event_type"]}},
	},
	"time_stamps": {"utc_or_offset_recorded": true},
	"protection_of_records": {
		"tamper_resistant": true,
		"management_access": {"accounts_outside_authorized_roles": 0, "odp": {"authorized_roles": ["audit-admin"]}},
	},
	"non_repudiation": {"implemented": true},
	"retention_period_days": 365,
	"odp": {"retention_period_days": 365},
	"generation": {"required_events_captured": true},
}}

test_all_pass_fixture_is_compliant if {
	fx := _pass
	r := au.compliance_report with input as fx
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_every_finding_is_evidence_missing if {
	r := au.compliance_report with input as {}
	count(r.violations) == count(au.evaluated_controls)
	_ids(r) == au.evaluated_controls
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

# [id, override that fails only that id, override that removes that id's evidence]
_new_cases := [
	["AU-3(1)", {"content_of_records": {"additional_information": {"fields_present": ["user"]}}}, {"content_of_records": {"additional_information": {"odp": {"fields": []}}}}],
	["AU-6(1)", {"review_and_analysis": {"automated_integration": {"mechanisms_integrated": []}}}, {"review_and_analysis": {"automated_integration": {"mechanisms_integrated": null}}}],
	["AU-6(3)", {"review_and_analysis": {"correlation": {"uncorrelated_repositories": 2}}}, {"review_and_analysis": {"correlation": {"correlation_enabled": null}}}],
	["AU-7(1)", {"reduction_and_reporting": {"automatic_processing": {"sort_supported": false}}}, {"reduction_and_reporting": {"automatic_processing": {"odp": null}}}],
	["AU-9(4)", {"protection_of_records": {"management_access": {"accounts_outside_authorized_roles": 1}}}, {"protection_of_records": {"management_access": {"accounts_outside_authorized_roles": null}}}],
]

test_new_ids_are_evaluated if {
	every c in _new_cases {
		c[0] in au.evaluated_controls
	}
	count(au.evaluated_controls) == 17
}

test_each_new_id_failing_case_flips_only_that_id if {
	every c in _new_cases {
		fx := object.union(_pass, {"au_controls": c[1]})
		r := au.compliance_report with input as fx
		_ids(r) == {c[0]}
		not contains(concat("", r.violations), "evidence missing")
	}
}

test_each_new_id_missing_evidence_flips_only_that_id if {
	every c in _new_cases {
		fx := object.union(_pass, {"au_controls": c[2]})
		r := au.compliance_report with input as fx
		_ids(r) == {c[0]}
		contains(concat("", r.violations), "evidence missing")
	}
}

test_au3_1_names_the_lacking_field if {
	fx := object.union(_pass, {"au_controls": {"content_of_records": {"additional_information": {"fields_present": ["user"]}}}})
	r := au.compliance_report with input as fx
	contains(concat("", r.violations), "session_id")
}

test_new_numeric_fact_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"au_controls": {"protection_of_records": {"management_access": {"accounts_outside_authorized_roles": "1"}}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-9(4)"}
	contains(concat("", r.violations), "evidence missing")
}

test_new_boolean_as_string_true_is_evidence_missing if {
	fx := object.union(_pass, {"au_controls": {"review_and_analysis": {"correlation": {"correlation_enabled": "true"}}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-6(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_enhancement_failure_leaves_base_passing if {
	fx := object.union(_pass, {"au_controls": {"protection_of_records": {"management_access": {"accounts_outside_authorized_roles": 3}}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-9(4)"}
}

# Existing rules: an absent fact is evidence missing; a false fact is the rule's own finding.
test_existing_absent_fact_is_evidence_missing if {
	fx := json.remove(_pass, ["au_controls/non_repudiation/implemented"])
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-10"}
	contains(concat("", r.violations), "evidence missing — input.au_controls.non_repudiation.implemented")
}

test_existing_false_fact_is_not_evidence_missing if {
	fx := object.union(_pass, {"au_controls": {"non_repudiation": {"implemented": false}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-10"}
	not contains(concat("", r.violations), "evidence missing")
}

test_au8_string_true_is_evidence_missing if {
	fx := object.union(_pass, {"au_controls": {"time_stamps": {"utc_or_offset_recorded": "true"}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-8"}
	contains(concat("", r.violations), "evidence missing")
}
