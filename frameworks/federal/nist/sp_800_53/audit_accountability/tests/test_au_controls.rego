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
	count(r.violations) == 30
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
	"response_to_failures": {
		"alerting": true,
		"storage_warning": {
			"warning_threshold_percent": 75, "warning_delivery_minutes": 5, "warning_recipients": ["isso", "soc"],
			"odp": {"threshold_percent": 80, "within_minutes": 15, "recipients": ["isso"]},
		},
		"real_time_alerts": {
			"alerted_events": ["audit_service_stopped", "log_write_failure"], "alert_latency_seconds": 30,
			"odp": {"failure_events": ["log_write_failure"], "within_seconds": 60, "recipients": ["soc"]},
		},
	},
	"review_and_analysis": {
		"regular": true,
		"automated_integration": {"mechanisms_integrated": ["siem"], "odp": {"mechanisms": ["siem"]}},
		"correlation": {"correlation_enabled": true, "uncorrelated_repositories": 0},
		"central_review": {"enabled": true, "components_not_centralized": 0},
		"integrated_analysis": {"sources_integrated": ["vulnerability_scanning", "performance"], "odp": {"sources": ["vulnerability_scanning"]}},
		"physical_correlation": {"enabled": true, "physical_access_sources_uncorrelated": 0},
		"permitted_actions": {"entities_without_defined_actions": 0, "odp": {"defined_for": ["role", "user"]}},
	},
	"reduction_and_reporting": {
		"tools_available": true,
		"automatic_processing": {"searchable_fields": ["user", "event_type", "time"], "sort_supported": true, "odp": {"fields": ["user", "event_type"]}},
	},
	"time_stamps": {"utc_or_offset_recorded": true},
	"protection_of_records": {
		"tamper_resistant": true,
		"management_access": {"accounts_outside_authorized_roles": 0, "odp": {"authorized_roles": ["audit-admin"]}},
		"separate_system": {"stored_on_separate_system": true, "hours_since_last_transfer": 1, "odp": {"frequency_hours": 24}},
		"cryptographic": {"records_integrity_protected": true, "tools_integrity_protected": true},
	},
	"non_repudiation": {"implemented": true},
	"retention_period_days": 365,
	"odp": {"retention_period_days": 365},
	"generation": {
		"required_events_captured": true,
		"system_wide_trail": {"components_in_trail": ["web", "db"], "max_time_skew_ms": 200, "odp": {"components": ["web", "db"], "tolerance_ms": 1000}},
		"authorized_changes": {"capability_enabled": true, "accounts_outside_roles": 0, "max_minutes_to_apply": 5, "odp": {"roles": ["audit-admin"], "within_minutes": 15}},
	},
	"information_disclosure_monitoring": {"days_since_last": 3, "disclosures_not_notified": 0, "odp": {"sources": ["paste sites"], "frequency_days": 7}},
	"session_audit": {
		"capability_enabled": true, "odp": {"roles": ["insider-threat-team"]},
		"legal_consultation": {"attestation": {"attested": true, "by": "Office of General Counsel", "date": "2026-10-01"}},
	},
	"cross_organizational": {"methods_in_use": ["syslog-tls-federation"], "external_transfers_without_coordination": 0, "odp": {"methods": ["syslog-tls-federation"]}},
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
	count(au.evaluated_controls) == 30
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

# --- NIST / FedRAMP High-baseline ids ------------------------------------------------------------------------

# [id, override that fails only that id, override that removes that id's evidence]
_high_cases := [
	["AU-5(1)", {"response_to_failures": {"storage_warning": {"warning_threshold_percent": 95}}}, {"response_to_failures": {"storage_warning": {"odp": {"threshold_percent": null}}}}],
	["AU-5(2)", {"response_to_failures": {"real_time_alerts": {"alerted_events": ["audit_service_stopped"]}}}, {"response_to_failures": {"real_time_alerts": {"alert_latency_seconds": null}}}],
	["AU-6(4)", {"review_and_analysis": {"central_review": {"components_not_centralized": 2}}}, {"review_and_analysis": {"central_review": {"enabled": null}}}],
	["AU-6(5)", {"review_and_analysis": {"integrated_analysis": {"sources_integrated": ["performance"]}}}, {"review_and_analysis": {"integrated_analysis": {"odp": {"sources": []}}}}],
	["AU-6(6)", {"review_and_analysis": {"physical_correlation": {"enabled": false}}}, {"review_and_analysis": {"physical_correlation": {"physical_access_sources_uncorrelated": null}}}],
	["AU-6(7)", {"review_and_analysis": {"permitted_actions": {"entities_without_defined_actions": 1}}}, {"review_and_analysis": {"permitted_actions": {"odp": {"defined_for": ["everyone"]}}}}],
	["AU-9(2)", {"protection_of_records": {"separate_system": {"hours_since_last_transfer": 48}}}, {"protection_of_records": {"separate_system": {"stored_on_separate_system": null}}}],
	["AU-9(3)", {"protection_of_records": {"cryptographic": {"tools_integrity_protected": false}}}, {"protection_of_records": {"cryptographic": {"records_integrity_protected": null}}}],
	["AU-12(1)", {"generation": {"system_wide_trail": {"max_time_skew_ms": 5000}}}, {"generation": {"system_wide_trail": {"components_in_trail": null}}}],
	["AU-12(3)", {"generation": {"authorized_changes": {"accounts_outside_roles": 3}}}, {"generation": {"authorized_changes": {"odp": {"within_minutes": null}}}}],
	["AU-13", {"information_disclosure_monitoring": {"days_since_last": 30}}, {"information_disclosure_monitoring": {"odp": {"frequency_days": null}}}],
	["AU-14", {"session_audit": {"capability_enabled": false}}, {"session_audit": {"odp": {"roles": []}}}],
	["AU-16", {"cross_organizational": {"external_transfers_without_coordination": 1}}, {"cross_organizational": {"methods_in_use": null}}],
]

test_high_ids_are_evaluated if {
	every c in _high_cases {
		c[0] in au.evaluated_controls
	}
	count(_high_cases) == 13
}

test_each_high_id_failing_case_flips_only_that_id if {
	every c in _high_cases {
		fx := object.union(_pass, {"au_controls": c[1]})
		r := au.compliance_report with input as fx
		_ids(r) == {c[0]}
		not contains(concat("", r.violations), "evidence missing")
	}
}

test_each_high_id_missing_evidence_flips_only_that_id if {
	every c in _high_cases {
		fx := object.union(_pass, {"au_controls": c[2]})
		r := au.compliance_report with input as fx
		_ids(r) == {c[0]}
		contains(concat("", r.violations), "evidence missing")
	}
}

test_au14_legal_consultation_not_attested if {
	fx := object.union(_pass, {"au_controls": {"session_audit": {"legal_consultation": {"attestation": {"by": ""}}}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-14"}
	contains(concat("", r.violations), "not attested")
}

test_au5_1_threshold_as_string_is_evidence_missing if {
	fx := object.union(_pass, {"au_controls": {"response_to_failures": {"storage_warning": {"warning_threshold_percent": "1"}}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-5(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_au12_1_skew_as_null_is_evidence_missing if {
	fx := object.union(_pass, {"au_controls": {"generation": {"system_wide_trail": {"max_time_skew_ms": null}}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-12(1)"}
	contains(concat("", r.violations), "evidence missing")
}

test_au9_3_boolean_as_string_true_is_evidence_missing if {
	fx := object.union(_pass, {"au_controls": {"protection_of_records": {"cryptographic": {"records_integrity_protected": "true"}}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-9(3)"}
	contains(concat("", r.violations), "evidence missing")
}

test_high_enhancement_failure_leaves_base_passing if {
	fx := object.union(_pass, {"au_controls": {"response_to_failures": {"real_time_alerts": {"alert_latency_seconds": 600}}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-5(2)"}
}

# --- Strict booleans on the base rules (2026-11-19): only true passes ----------------------------------------

# [id, path below au_controls, trap value]
_strict_traps := [
	["AU-1", ["policy", "documented"], "true"],
	["AU-1", ["policy", "documented"], 1],
	["AU-1", ["policy", "documented"], null],
	["AU-4", ["storage_capacity", "adequate"], "yes"],
	["AU-4", ["storage_capacity", "adequate"], 1],
	["AU-4", ["storage_capacity", "adequate"], null],
	["AU-12", ["generation", "required_events_captured"], "true"],
	["AU-12", ["generation", "required_events_captured"], 1],
	["AU-12", ["generation", "required_events_captured"], {"captured": true}],
	["AU-2", ["event_logging", "enabled"], "false"],
	["AU-9", ["protection_of_records", "tamper_resistant"], 1],
]

test_strict_booleans_type_traps_are_evidence_missing if {
	every c in _strict_traps {
		fx := json.patch(_pass, [{"op": "add", "path": concat("/", array.concat(["", "au_controls"], c[1])), "value": c[2]}])
		r := au.compliance_report with input as fx
		_ids(r) == {c[0]}
		contains(concat("", r.violations), "evidence missing")
	}
}

test_strict_boolean_false_keeps_rule_text if {
	fx := object.union(_pass, {"au_controls": {"storage_capacity": {"adequate": false}}})
	r := au.compliance_report with input as fx
	_ids(r) == {"AU-4"}
	contains(concat("", r.violations), "storage capacity insufficient")
	not contains(concat("", r.violations), "evidence missing")
}
