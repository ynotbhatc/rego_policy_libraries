package nist.sp800_53.system_services_acquisition_logic_test

import rego.v1

# Logic tests for system_services_acquisition/sa_controls.rego. Every case states its input inline (no helper does
# `with input as`, which the wasm build rejects); each failing case changes one fact of the all-pass fixture
# and must flip exactly that control id.

_pass := {"sa_controls": {"policy": {"documented": true, "official_designated": true, "days_since_last": 30, "odp": {"frequency_days": 365}}, "procedures": {"documented": true, "days_since_last": 30, "odp": {"frequency_days": 365}}, "resource_allocation": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "sdlc": {"security_privacy_incorporated": true, "roles_documented": true, "role_holders_identified": true, "risk_management_integrated": true}, "acquisition": {"contract_language_defined": true, "contracts_missing_requirements": 0}, "documentation": {"administrator_documentation": true, "user_documentation": true, "unavailable_documentation_handled": true, "distributed": true}, "engineering_principles": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "external_services": {"oversight_roles_documented": true, "compliance_monitored": true, "noncompliant_providers": 0}, "developer_cm": {"performed": true, "change_integrity_controlled": true, "only_approved_changes": true, "changes_documented_with_impact": true, "flaws_tracked_and_reported": true}, "developer_testing": {"assessment_plan_implemented": true, "evidence_produced": true, "flaw_remediation_process": true, "flaws_corrected": true, "days_since_last": 60, "odp": {"frequency_days": 180}}, "development_process": {"documented": true, "addresses_security_privacy": true, "standards_tools_identified": true, "tool_configurations_documented": true, "process_changes_controlled": true, "review": {"days_since_last": 30, "odp": {"frequency_days": 365}}}, "developer_training": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "developer_architecture": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "custom_critical_components": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "developer_screening": {"criteria_defined": true, "unscreened_developers": 0}, "unsupported_components": {"without_alternative_support": 0}, "specialization": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}, "cyber_resiliency": {"attestation": {"attested": true, "by": "Privacy Officer", "date": "2026-11-01"}}}}

_flagged(v, id) := [x | some x in v; startswith(x, concat("", ["NIST ", id, ":"]))]

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.system_services_acquisition.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.system_services_acquisition.compliance_report with input as {}
	count(r.violations) == count(data.nist.sp800_53.system_services_acquisition.evaluated_controls)
	every id in data.nist.sp800_53.system_services_acquisition.evaluated_controls {
		count(_flagged(r.violations, id)) == 1
	}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.system_services_acquisition.evaluated_controls == {"SA-1", "SA-2", "SA-3", "SA-4", "SA-5", "SA-8", "SA-9", "SA-10", "SA-11", "SA-15", "SA-16", "SA-17", "SA-20", "SA-21", "SA-22", "SA-23", "SA-24"}
}

test_sa1_policy_not_documented_fails if {
	inp := object.union(_pass, {"sa_controls": {"policy": {"documented": false}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-1")
	count(f) == 1
	contains(f[0], "policy not documented")
}

test_sa1_no_official_fails if {
	inp := object.union(_pass, {"sa_controls": {"policy": {"official_designated": false}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-1")
	count(f) == 1
	contains(f[0], "official")
}

test_sa1_procedures_review_overdue_fails if {
	inp := object.union(_pass, {"sa_controls": {"procedures": {"days_since_last": 400}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-1")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 365")
}

test_sa1_policy_review_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"sa_controls": {"policy": {"odp": {"frequency_days": null}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sa1_procedures_documented_string_fails if {
	inp := object.union(_pass, {"sa_controls": {"procedures": {"documented": "true"}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sa2_attestation_missing_fails if {
	inp := object.union(_pass, {"sa_controls": {"resource_allocation": {"attestation": null}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-2")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa2_attested_string_true_fails if {
	inp := object.union(_pass, {"sa_controls": {"resource_allocation": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-2")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_sa2_attestation_empty_by_fails if {
	inp := object.union(_pass, {"sa_controls": {"resource_allocation": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-2")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa3_roles_not_documented_fails if {
	inp := object.union(_pass, {"sa_controls": {"sdlc": {"roles_documented": false}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-3")
	count(f) == 1
	contains(f[0], "roles and responsibilities")
}

test_sa3_risk_integration_string_true_fails if {
	inp := object.union(_pass, {"sa_controls": {"sdlc": {"risk_management_integrated": "true"}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-3")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sa4_contracts_missing_requirements_fail if {
	inp := object.union(_pass, {"sa_controls": {"acquisition": {"contracts_missing_requirements": 4}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-4")
	count(f) == 1
	contains(f[0], "4 acquisition contracts")
}

test_sa4_contract_count_string_is_evidence_missing if {
	inp := object.union(_pass, {"sa_controls": {"acquisition": {"contracts_missing_requirements": "1"}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-4")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sa4_contract_count_null_is_evidence_missing if {
	inp := object.union(_pass, {"sa_controls": {"acquisition": {"contracts_missing_requirements": null}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-4")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sa5_no_admin_documentation_fails if {
	inp := object.union(_pass, {"sa_controls": {"documentation": {"administrator_documentation": false}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-5")
	count(f) == 1
	contains(f[0], "administrator documentation")
}

test_sa8_attestation_missing_fails if {
	inp := object.union(_pass, {"sa_controls": {"engineering_principles": {"attestation": null}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-8")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa8_attested_string_true_fails if {
	inp := object.union(_pass, {"sa_controls": {"engineering_principles": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-8")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_sa8_attestation_empty_by_fails if {
	inp := object.union(_pass, {"sa_controls": {"engineering_principles": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-8")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa9_noncompliant_providers_fail if {
	inp := object.union(_pass, {"sa_controls": {"external_services": {"noncompliant_providers": 1}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-9")
	count(f) == 1
	contains(f[0], "1 external service providers")
}

test_sa9_not_monitored_fails if {
	inp := object.union(_pass, {"sa_controls": {"external_services": {"compliance_monitored": false}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-9")
	count(f) == 1
	contains(f[0], "ongoing basis")
}

test_sa10_unapproved_changes_fail if {
	inp := object.union(_pass, {"sa_controls": {"developer_cm": {"only_approved_changes": false}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-10")
	count(f) == 1
	contains(f[0], "not organization-approved")
}

test_sa11_testing_overdue_fails if {
	inp := object.union(_pass, {"sa_controls": {"developer_testing": {"days_since_last": 181}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-11")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 180")
}

test_sa11_days_as_string_is_evidence_missing if {
	inp := object.union(_pass, {"sa_controls": {"developer_testing": {"days_since_last": "1"}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-11")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sa11_flaws_not_corrected_fails if {
	inp := object.union(_pass, {"sa_controls": {"developer_testing": {"flaws_corrected": false}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-11")
	count(f) == 1
	contains(f[0], "not corrected")
}

test_sa15_review_overdue_fails if {
	inp := object.union(_pass, {"sa_controls": {"development_process": {"review": {"days_since_last": 366}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-15")
	count(f) == 1
	contains(f[0], "reviewed last 366 days ago")
}

test_sa15_review_odp_null_is_evidence_missing if {
	inp := object.union(_pass, {"sa_controls": {"development_process": {"review": {"odp": {"frequency_days": null}}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-15")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sa15_tool_configs_not_documented_fails if {
	inp := object.union(_pass, {"sa_controls": {"development_process": {"tool_configurations_documented": false}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-15")
	count(f) == 1
	contains(f[0], "tool options")
}

test_sa16_attestation_missing_fails if {
	inp := object.union(_pass, {"sa_controls": {"developer_training": {"attestation": null}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-16")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa16_attested_string_true_fails if {
	inp := object.union(_pass, {"sa_controls": {"developer_training": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-16")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_sa16_attestation_empty_by_fails if {
	inp := object.union(_pass, {"sa_controls": {"developer_training": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-16")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa17_attestation_missing_fails if {
	inp := object.union(_pass, {"sa_controls": {"developer_architecture": {"attestation": null}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-17")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa17_attested_string_true_fails if {
	inp := object.union(_pass, {"sa_controls": {"developer_architecture": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-17")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_sa17_attestation_empty_by_fails if {
	inp := object.union(_pass, {"sa_controls": {"developer_architecture": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-17")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa20_attestation_missing_fails if {
	inp := object.union(_pass, {"sa_controls": {"custom_critical_components": {"attestation": null}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-20")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa20_attested_string_true_fails if {
	inp := object.union(_pass, {"sa_controls": {"custom_critical_components": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-20")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_sa20_attestation_empty_by_fails if {
	inp := object.union(_pass, {"sa_controls": {"custom_critical_components": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-20")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa21_unscreened_developers_fail if {
	inp := object.union(_pass, {"sa_controls": {"developer_screening": {"unscreened_developers": 2}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-21")
	count(f) == 1
	contains(f[0], "2 developers")
}

test_sa21_criteria_not_defined_fails if {
	inp := object.union(_pass, {"sa_controls": {"developer_screening": {"criteria_defined": false}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-21")
	count(f) == 1
	contains(f[0], "screening criteria")
}

test_sa22_unsupported_components_fail if {
	inp := object.union(_pass, {"sa_controls": {"unsupported_components": {"without_alternative_support": 5}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-22")
	count(f) == 1
	contains(f[0], "5 unsupported")
}

test_sa22_count_string_is_evidence_missing if {
	inp := object.union(_pass, {"sa_controls": {"unsupported_components": {"without_alternative_support": "1"}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-22")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sa22_count_null_is_evidence_missing if {
	inp := object.union(_pass, {"sa_controls": {"unsupported_components": {"without_alternative_support": null}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-22")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_sa23_attestation_missing_fails if {
	inp := object.union(_pass, {"sa_controls": {"specialization": {"attestation": null}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-23")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa23_attested_string_true_fails if {
	inp := object.union(_pass, {"sa_controls": {"specialization": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-23")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_sa23_attestation_empty_by_fails if {
	inp := object.union(_pass, {"sa_controls": {"specialization": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-23")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa24_attestation_missing_fails if {
	inp := object.union(_pass, {"sa_controls": {"cyber_resiliency": {"attestation": null}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-24")
	count(f) == 1
	contains(f[0], "attestation")
}

test_sa24_attested_string_true_fails if {
	inp := object.union(_pass, {"sa_controls": {"cyber_resiliency": {"attestation": {"attested": "true"}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-24")
	count(f) == 1
	contains(f[0], "attestation only")
}

test_sa24_attestation_empty_by_fails if {
	inp := object.union(_pass, {"sa_controls": {"cyber_resiliency": {"attestation": {"by": "  "}}}})
	v := data.nist.sp800_53.system_services_acquisition.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SA-24")
	count(f) == 1
	contains(f[0], "attestation")
}
