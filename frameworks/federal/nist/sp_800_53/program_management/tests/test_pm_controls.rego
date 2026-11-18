package nist.sp800_53.program_management_logic_test

# Logic tests for the PM family: all-pass fixture, fail-closed on empty input, one id per failing case,
# type traps, and the evaluated id list. Every test binds its own input (no `with` inside helpers).

import rego.v1

_ids(vs) := {m[0][1] |
	some v in vs
	m := regex.find_all_string_submatch_n(`^NIST ([A-Z]{2}-[0-9]+): `, v, 1)
	count(m) == 1
}

# Empty input yields evidence missing for fact controls and a missing attestation for organizational ones.
_fail_closed_message(v) if contains(v, "evidence missing")

_fail_closed_message(v) if contains(v, "not attested")

_pass := {"pm_controls": {
	"security_program_plan": {
		"documented": true,
		"disseminated": true,
		"approved_by_senior_official": true,
		"protected": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"security_officer": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"program_resources": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"poam": {
		"process_implemented": true,
		"reported": true,
		"reviewed_against_risk_strategy": true,
	},
	"system_inventory": {
		"maintained": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"performance_measures": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"enterprise_architecture": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"critical_infrastructure_plan": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"risk_management_strategy": {
		"documented": true,
		"implemented_consistently": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"authorization_process": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"mission_business_processes": {
		"defined": true,
		"protection_needs_determined": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"insider_threat_program": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"workforce_program": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"testing_training_monitoring": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"groups_associations": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"threat_awareness_program": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"cui_external_systems": {
		"policy_established": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"privacy_program_plan": {
		"documented": true,
		"disseminated": true,
		"approved_by_senior_official": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"privacy_officer": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"privacy_program_webpage": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"disclosure_accounting": {
		"maintained": true,
		"retention_met": true,
		"available_on_request": true,
	},
	"pii_quality": {"policies_documented": true},
	"data_governance_body": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"data_integrity_board": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"pii_test_train_research": {
		"policies_documented": true,
		"use_minimized": true,
		"use_authorized": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"complaint_management": {
		"process_implemented": true,
		"max_days_to_address": 30,
		"odp": {
			"address_within_days": 365,
			"acknowledge_within_days": 365,
			"respond_within_days": 365,
		},
		"max_days_to_acknowledge": 30,
		"max_days_to_respond": 30,
	},
	"privacy_reporting": {
		"reports_disseminated": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"risk_framing": {
		"documented": true,
		"distributed": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"risk_leadership_roles": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
	"scrm_strategy": {
		"documented": true,
		"implemented_consistently": true,
		"days_since_last": 30,
		"odp": {"frequency_days": 365},
	},
	"continuous_monitoring": {
		"strategy_documented": true,
		"metrics_established": true,
		"ongoing_monitoring": true,
		"analysis_and_response": true,
		"status_reporting": {
			"days_since_last": 30,
			"odp": {"frequency_days": 365},
		},
	},
	"purposing": {"attestation": {
		"attested": true,
		"by": "Chief Information Security Officer",
		"date": "2026-11-01",
	}},
}}

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.program_management.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
	r.controls_evaluated == 32
}

test_empty_input_one_finding_per_control if {
	vs := data.nist.sp800_53.program_management.violation with input as {}
	ec := data.nist.sp800_53.program_management.evaluated_controls with input as {}
	count(vs) == count(ec)
	_ids(vs) == ec
	every v in vs {
		_fail_closed_message(v)
	}
	r := data.nist.sp800_53.program_management.compliance_report with input as {}
	r.compliant == false
}

test_non_object_family_root_fails_closed if {
	vs := data.nist.sp800_53.program_management.violation with input as {"pm_controls": "yes"}
	count(vs) == 32
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.program_management.evaluated_controls == {"PM-1", "PM-2", "PM-3", "PM-4", "PM-5", "PM-6", "PM-7", "PM-8", "PM-9", "PM-10", "PM-11", "PM-12", "PM-13", "PM-14", "PM-15", "PM-16", "PM-17", "PM-18", "PM-19", "PM-20", "PM-21", "PM-22", "PM-23", "PM-24", "PM-25", "PM-26", "PM-27", "PM-28", "PM-29", "PM-30", "PM-31", "PM-32"}
}

test_pm1_failing_case_flips_only_pm1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/documented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
	count(vs) == 1
}

test_pm2_failing_case_flips_only_pm2 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_officer/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-2"}
	count(vs) == 1
}

test_pm3_failing_case_flips_only_pm3 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/program_resources/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-3"}
	count(vs) == 1
}

test_pm4_failing_case_flips_only_pm4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/poam/process_implemented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-4"}
	count(vs) == 1
}

test_pm5_failing_case_flips_only_pm5 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/system_inventory/maintained", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-5"}
	count(vs) == 1
}

test_pm6_failing_case_flips_only_pm6 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/performance_measures/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-6"}
	count(vs) == 1
}

test_pm7_failing_case_flips_only_pm7 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/enterprise_architecture/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-7"}
	count(vs) == 1
}

test_pm8_failing_case_flips_only_pm8 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/critical_infrastructure_plan/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-8"}
	count(vs) == 1
}

test_pm9_failing_case_flips_only_pm9 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/risk_management_strategy/documented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-9"}
	count(vs) == 1
}

test_pm10_failing_case_flips_only_pm10 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/authorization_process/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-10"}
	count(vs) == 1
}

test_pm11_failing_case_flips_only_pm11 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/mission_business_processes/defined", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-11"}
	count(vs) == 1
}

test_pm12_failing_case_flips_only_pm12 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/insider_threat_program/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-12"}
	count(vs) == 1
}

test_pm13_failing_case_flips_only_pm13 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/workforce_program/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-13"}
	count(vs) == 1
}

test_pm14_failing_case_flips_only_pm14 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/testing_training_monitoring/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-14"}
	count(vs) == 1
}

test_pm15_failing_case_flips_only_pm15 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/groups_associations/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-15"}
	count(vs) == 1
}

test_pm16_failing_case_flips_only_pm16 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/threat_awareness_program/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-16"}
	count(vs) == 1
}

test_pm17_failing_case_flips_only_pm17 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/cui_external_systems/policy_established", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-17"}
	count(vs) == 1
}

test_pm18_failing_case_flips_only_pm18 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/privacy_program_plan/documented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-18"}
	count(vs) == 1
}

test_pm19_failing_case_flips_only_pm19 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/privacy_officer/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-19"}
	count(vs) == 1
}

test_pm20_failing_case_flips_only_pm20 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/privacy_program_webpage/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-20"}
	count(vs) == 1
}

test_pm21_failing_case_flips_only_pm21 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/disclosure_accounting/maintained", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-21"}
	count(vs) == 1
}

test_pm22_failing_case_flips_only_pm22 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/pii_quality/policies_documented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-22"}
	count(vs) == 1
}

test_pm23_failing_case_flips_only_pm23 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/data_governance_body/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-23"}
	count(vs) == 1
}

test_pm24_failing_case_flips_only_pm24 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/data_integrity_board/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-24"}
	count(vs) == 1
}

test_pm25_failing_case_flips_only_pm25 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/pii_test_train_research/policies_documented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-25"}
	count(vs) == 1
}

test_pm26_failing_case_flips_only_pm26 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/complaint_management/process_implemented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-26"}
	count(vs) == 1
}

test_pm27_failing_case_flips_only_pm27 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/privacy_reporting/reports_disseminated", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-27"}
	count(vs) == 1
}

test_pm28_failing_case_flips_only_pm28 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/risk_framing/documented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-28"}
	count(vs) == 1
}

test_pm29_failing_case_flips_only_pm29 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/risk_leadership_roles/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-29"}
	count(vs) == 1
}

test_pm30_failing_case_flips_only_pm30 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/scrm_strategy/documented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-30"}
	count(vs) == 1
}

test_pm31_failing_case_flips_only_pm31 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/continuous_monitoring/strategy_documented", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-31"}
	count(vs) == 1
}

test_pm32_failing_case_flips_only_pm32 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/purposing/attestation/attested", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-32"}
	count(vs) == 1
}

test_pm1_security_program_plan_disseminated_flips_only_pm1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/disseminated", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
	count(vs) == 1
}

test_pm1_security_program_plan_approved_by_senior_official_flips_only_pm1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/approved_by_senior_official", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
	count(vs) == 1
}

test_pm1_security_program_plan_protected_flips_only_pm1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/protected", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
	count(vs) == 1
}

test_pm1_security_program_plan_days_since_last_flips_only_pm1 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
	count(vs) == 1
}

test_pm4_poam_reported_flips_only_pm4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/poam/reported", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-4"}
	count(vs) == 1
}

test_pm4_poam_reviewed_against_risk_strategy_flips_only_pm4 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/poam/reviewed_against_risk_strategy", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-4"}
	count(vs) == 1
}

test_pm5_system_inventory_days_since_last_flips_only_pm5 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/system_inventory/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-5"}
	count(vs) == 1
}

test_pm9_risk_management_strategy_implemented_consistently_flips_only_pm9 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/risk_management_strategy/implemented_consistently", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-9"}
	count(vs) == 1
}

test_pm9_risk_management_strategy_days_since_last_flips_only_pm9 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/risk_management_strategy/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-9"}
	count(vs) == 1
}

test_pm11_mission_business_processes_protection_needs_determined_flips_only_pm11 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/mission_business_processes/protection_needs_determined", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-11"}
	count(vs) == 1
}

test_pm11_mission_business_processes_days_since_last_flips_only_pm11 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/mission_business_processes/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-11"}
	count(vs) == 1
}

test_pm17_cui_external_systems_days_since_last_flips_only_pm17 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/cui_external_systems/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-17"}
	count(vs) == 1
}

test_pm18_privacy_program_plan_disseminated_flips_only_pm18 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/privacy_program_plan/disseminated", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-18"}
	count(vs) == 1
}

test_pm18_privacy_program_plan_approved_by_senior_official_flips_only_pm18 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/privacy_program_plan/approved_by_senior_official", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-18"}
	count(vs) == 1
}

test_pm18_privacy_program_plan_days_since_last_flips_only_pm18 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/privacy_program_plan/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-18"}
	count(vs) == 1
}

test_pm21_disclosure_accounting_retention_met_flips_only_pm21 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/disclosure_accounting/retention_met", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-21"}
	count(vs) == 1
}

test_pm21_disclosure_accounting_available_on_request_flips_only_pm21 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/disclosure_accounting/available_on_request", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-21"}
	count(vs) == 1
}

test_pm25_pii_test_train_research_use_minimized_flips_only_pm25 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/pii_test_train_research/use_minimized", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-25"}
	count(vs) == 1
}

test_pm25_pii_test_train_research_use_authorized_flips_only_pm25 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/pii_test_train_research/use_authorized", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-25"}
	count(vs) == 1
}

test_pm25_pii_test_train_research_days_since_last_flips_only_pm25 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/pii_test_train_research/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-25"}
	count(vs) == 1
}

test_pm26_complaint_management_max_days_to_address_flips_only_pm26 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/complaint_management/max_days_to_address", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-26"}
	count(vs) == 1
}

test_pm26_complaint_management_max_days_to_acknowledge_flips_only_pm26 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/complaint_management/max_days_to_acknowledge", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-26"}
	count(vs) == 1
}

test_pm26_complaint_management_max_days_to_respond_flips_only_pm26 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/complaint_management/max_days_to_respond", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-26"}
	count(vs) == 1
}

test_pm27_privacy_reporting_days_since_last_flips_only_pm27 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/privacy_reporting/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-27"}
	count(vs) == 1
}

test_pm28_risk_framing_distributed_flips_only_pm28 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/risk_framing/distributed", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-28"}
	count(vs) == 1
}

test_pm28_risk_framing_days_since_last_flips_only_pm28 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/risk_framing/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-28"}
	count(vs) == 1
}

test_pm30_scrm_strategy_implemented_consistently_flips_only_pm30 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/scrm_strategy/implemented_consistently", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-30"}
	count(vs) == 1
}

test_pm30_scrm_strategy_days_since_last_flips_only_pm30 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/scrm_strategy/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-30"}
	count(vs) == 1
}

test_pm31_continuous_monitoring_metrics_established_flips_only_pm31 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/continuous_monitoring/metrics_established", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-31"}
	count(vs) == 1
}

test_pm31_continuous_monitoring_ongoing_monitoring_flips_only_pm31 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/continuous_monitoring/ongoing_monitoring", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-31"}
	count(vs) == 1
}

test_pm31_continuous_monitoring_analysis_and_response_flips_only_pm31 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/continuous_monitoring/analysis_and_response", "value": false}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-31"}
	count(vs) == 1
}

test_pm31_continuous_monitoring_status_reporting_days_since_last_flips_only_pm31 if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/continuous_monitoring/status_reporting/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-31"}
	count(vs) == 1
}

test_numeric_fact_as_string_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/days_since_last", "value": "1"}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
	some v in vs
	contains(v, "evidence missing")
	contains(v, "security_program_plan.days_since_last")
}

test_numeric_fact_as_null_is_evidence_missing if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/days_since_last", "value": null}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
	some v in vs
	contains(v, "evidence missing")
	contains(v, "security_program_plan.days_since_last")
}

test_boolean_fact_as_string_true_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/documented", "value": "true"}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
}

test_boolean_fact_as_one_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/documented", "value": 1}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
}

test_pm1_review_beyond_frequency_fails if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_program_plan/days_since_last", "value": 400}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-1"}
	some v in vs
	contains(v, "400 days ago")
	contains(v, "365 days")
}

test_attestation_attested_as_string_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_officer/attestation/attested", "value": "true"}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-2"}
	some v in vs
	contains(v, "not attested")
}

test_attestation_empty_by_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_officer/attestation/by", "value": ""}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-2"}
	some v in vs
	contains(v, "not attested")
}

test_attestation_missing_date_is_a_finding if {
	inp := json.patch(_pass, [{"op": "remove", "path": "/pm_controls/security_officer/attestation/date"}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-2"}
	some v in vs
	contains(v, "not attested")
}

test_attestation_bare_true_is_a_finding if {
	inp := json.patch(_pass, [{"op": "replace", "path": "/pm_controls/security_officer/attestation", "value": true}])
	vs := data.nist.sp800_53.program_management.violation with input as inp
	_ids(vs) == {"PM-2"}
	some v in vs
	contains(v, "not attested")
}
