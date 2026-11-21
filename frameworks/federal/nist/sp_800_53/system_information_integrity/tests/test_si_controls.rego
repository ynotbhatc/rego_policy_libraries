package nist.sp800_53.system_information_integrity_logic_test

import rego.v1

# Logic tests for system_information_integrity/si_controls.rego. Every case states its input inline (no helper
# does `with input as`, which the wasm build rejects); each failing case changes one fact of the all-pass fixture
# and must flip exactly that control id.

_pass_base := {"si_controls": {"policy": {"documented": true}, "flaw_remediation": {"timely": true, "automated_status": {"automated": true, "days_since_last": 1, "odp": {"frequency_days": 7}}, "time_to_remediate": {"measured": true, "max_days_to_remediate": 12, "odp": {"benchmark_days": 30}}}, "malicious_code_protection": {"deployed": true}, "system_monitoring": {"continuous": true, "real_time_analysis": {"automated_tools_enabled": true}, "traffic_monitoring": {"criteria_defined": true, "inbound_monitored": true, "outbound_monitored": true, "days_since_last": 0, "odp": {"frequency_days": 1}}, "alerts": {"recipients_configured": true, "indicators_without_alert": 0}, "system_wide_ids": {"integrated": true, "tools_not_connected": 0}, "encrypted_traffic_visibility": {"traffic_types_not_visible": 0}, "outbound_anomaly_analysis": {"external_interfaces_not_analyzed": 0, "interior_points_not_analyzed": 0}, "organization_alerts": {"automated": true, "recipients_configured": true, "triggers_without_alert": 0}, "wireless_ids": {"deployed": true, "rogue_device_detection": true, "attack_detection": true}, "correlation": {"sources_not_correlated": 0}, "covert_exfiltration": {"external_interfaces_not_analyzed": 0, "interior_points_not_analyzed": 0}, "individual_risk": {"individuals_without_additional_monitoring": 0}, "privileged_users": {"accounts_without_additional_monitoring": 0}, "unauthorized_services": {"detection_enabled": true, "response_configured": true, "unhandled_detections": 0}, "host_based": {"components_without_monitoring": 0}}, "security_alerts": {"acted_upon": true, "automated_broadcast": {"automated": true}}, "security_function_verification": {"tested": true}, "software_firmware_integrity": {"verified": true, "integrity_checks": {"unchecked_items": 0, "days_since_last": 1, "odp": {"frequency_days": 7}}, "incident_response_integration": {"unauthorized_changes_routed": true}, "automated_notifications": {"enabled": true, "recipients_configured": true}, "automated_response": {"enabled": true, "components_without_response": 0}, "code_authentication": {"signature_verification_enforced": true, "unauthenticated_installations": 0}}, "spam_protection": {"enabled": true, "automatic_updates": {"enabled": true, "days_since_last": 1, "odp": {"frequency_days": 1}}}, "input_validation": {"enforced": true}, "error_handling": {"no_info_disclosure": true}, "information_management_retention": {"policy_enforced": true}, "memory_protection": {"enabled": true}, "predictable_failure_prevention": {"components_without_mttf": 0, "substitution_criteria_defined": true, "components_without_standby": 0}, "non_persistence": {"components_not_from_known_state": 0, "oldest_instance_age_days": 0, "odp": {"max_lifetime_days": 1}}, "output_filtering": {"applications_without_validation": 0}, "fail_safe": {"procedures_defined": true, "conditions_without_procedure": 0}, "pii_quality": {"days_since_last": 30, "odp": {"frequency_days": 90}, "uncorrected_records": 0}, "de_identification": {"datasets_with_identifying_elements": 0, "days_since_last": 30, "odp": {"frequency_days": 180}}, "tainting": {"components_without_taint": 0}, "information_refresh": {"days_since_last": 1, "odp": {"frequency_days": 7}}, "information_diversity": {"functions_without_alternative_source": 0, "components_without_failover": 0}, "information_fragmentation": {"attestation": {"attested": true, "by": "System Owner", "date": "2026-11-01"}}}}

_flagged(v, id) := [x | some x in v; startswith(x, concat("", ["NIST ", id, ":"]))]

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.system_information_integrity.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.system_information_integrity.compliance_report with input as {}
	r.controls_evaluated == 49
	count(r.violations) == count(data.nist.sp800_53.system_information_integrity.evaluated_controls)
	every id in data.nist.sp800_53.system_information_integrity.evaluated_controls {
		count(_flagged(r.violations, id)) == 1
	}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.system_information_integrity.evaluated_controls == {"SI-1", "SI-2", "SI-2(2)", "SI-2(3)", "SI-3", "SI-4", "SI-4(1)", "SI-4(2)", "SI-4(4)", "SI-4(5)", "SI-4(10)", "SI-4(11)", "SI-4(12)", "SI-4(14)", "SI-4(16)", "SI-4(18)", "SI-4(19)", "SI-4(20)", "SI-4(22)", "SI-4(23)", "SI-5", "SI-5(1)", "SI-6", "SI-7", "SI-7(1)", "SI-7(2)", "SI-7(5)", "SI-7(7)", "SI-7(15)", "SI-8", "SI-8(2)", "SI-10", "SI-11", "SI-12", "SI-13", "SI-14", "SI-15", "SI-16", "SI-17", "SI-18", "SI-19", "SI-20", "SI-21", "SI-22", "SI-23", "SI-12(1)", "SI-12(2)", "SI-12(3)", "SI-18(4)"}
}

test_enhancement_missing_does_not_fail_base if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"automated_status": null}, "system_monitoring": {"real_time_analysis": null, "traffic_monitoring": null, "alerts": null}, "software_firmware_integrity": {"integrity_checks": null, "incident_response_integration": null}, "spam_protection": {"automatic_updates": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 7
	every id in {"SI-2", "SI-4", "SI-7", "SI-8"} {
		count(_flagged(v, id)) == 0
	}
}

test_si1_false_keeps_original_text if {
	inp := object.union(_pass, {"si_controls": {"policy": {"documented": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-1")
	count(f) == 1
	contains(f[0], "policy not documented")
}

test_si1_absent_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"policy": null}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si2_false_keeps_original_text if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"timely": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2")
	count(f) == 1
	contains(f[0], "not performed within defined timeframes")
}

test_si2_absent_is_evidence_missing if {
	inp := json.remove(_pass, ["si_controls/flaw_remediation/timely"])
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si3_false_fails if {
	inp := object.union(_pass, {"si_controls": {"malicious_code_protection": {"deployed": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-3")
	count(f) == 1
	contains(f[0], "Malicious code protection")
}

test_si4_false_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"continuous": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4")
	count(f) == 1
	contains(f[0], "not continuous")
}

test_si5_false_fails if {
	inp := object.union(_pass, {"si_controls": {"security_alerts": {"acted_upon": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-5")
	count(f) == 1
	contains(f[0], "not received and acted upon")
}

test_si6_false_fails if {
	inp := object.union(_pass, {"si_controls": {"security_function_verification": {"tested": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-6")
	count(f) == 1
	contains(f[0], "not periodically tested")
}

test_si7_false_fails if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"verified": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7")
	count(f) == 1
	contains(f[0], "not verified")
}

test_si8_false_fails if {
	inp := object.union(_pass, {"si_controls": {"spam_protection": {"enabled": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-8")
	count(f) == 1
	contains(f[0], "Spam protection not enabled")
}

test_si10_false_fails if {
	inp := object.union(_pass, {"si_controls": {"input_validation": {"enforced": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-10")
	count(f) == 1
	contains(f[0], "input validation")
}

test_si11_false_fails if {
	inp := object.union(_pass, {"si_controls": {"error_handling": {"no_info_disclosure": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-11")
	count(f) == 1
	contains(f[0], "discloses")
}

test_si12_false_fails if {
	inp := object.union(_pass, {"si_controls": {"information_management_retention": {"policy_enforced": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-12")
	count(f) == 1
	contains(f[0], "retention")
}

test_si16_false_fails if {
	inp := object.union(_pass, {"si_controls": {"memory_protection": {"enabled": false}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-16")
	count(f) == 1
	contains(f[0], "Memory protection")
}

test_si16_path_through_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"memory_protection": "on"}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-16")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si2_2_manual_fails if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"automated_status": {"automated": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2(2)")
	count(f) == 1
	contains(f[0], "not determined by automated mechanisms")
}

test_si2_2_overdue_fails if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"automated_status": {"days_since_last": 8}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2(2)")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 7")
}

test_si2_2_days_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"automated_status": {"days_since_last": "1"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2(2)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si2_2_days_null_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"automated_status": {"days_since_last": null}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2(2)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si2_2_automated_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"automated_status": {"automated": "true"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2(2)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_2_no_tools_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"real_time_analysis": {"automated_tools_enabled": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(2)")
	count(f) == 1
	contains(f[0], "near real-time")
}

test_si4_2_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"real_time_analysis": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(2)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_4_outbound_not_monitored_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"traffic_monitoring": {"outbound_monitored": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(4)")
	count(f) == 1
	contains(f[0], "outbound communications traffic")
}

test_si4_4_overdue_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"traffic_monitoring": {"days_since_last": 3}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(4)")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 1")
}

test_si4_4_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"traffic_monitoring": {"odp": null}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(4)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_5_no_recipients_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"alerts": {"recipients_configured": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(5)")
	count(f) == 1
	contains(f[0], "not routed")
}

test_si4_5_indicators_without_alert_fail if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"alerts": {"indicators_without_alert": 2}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(5)")
	count(f) == 1
	contains(f[0], "2 organization-defined compromise indicators")
}

test_si4_5_count_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"alerts": {"indicators_without_alert": "0"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(5)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si7_1_unchecked_items_fail if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"integrity_checks": {"unchecked_items": 4}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(1)")
	count(f) == 1
	contains(f[0], "4 organization-defined")
}

test_si7_1_overdue_fails if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"integrity_checks": {"days_since_last": 10}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(1)")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 7")
}

test_si7_1_null_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"integrity_checks": {"unchecked_items": null}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si7_7_not_routed_fails if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"incident_response_integration": {"unauthorized_changes_routed": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(7)")
	count(f) == 1
	contains(f[0], "incident response capability")
}

test_si7_7_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"incident_response_integration": {"unauthorized_changes_routed": "true"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(7)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si8_2_not_automatic_fails if {
	inp := object.union(_pass, {"si_controls": {"spam_protection": {"automatic_updates": {"enabled": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-8(2)")
	count(f) == 1
	contains(f[0], "not updated automatically")
}

test_si8_2_overdue_fails if {
	inp := object.union(_pass, {"si_controls": {"spam_protection": {"automatic_updates": {"days_since_last": 2}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-8(2)")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 1")
}

test_si8_2_odp_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"spam_protection": {"automatic_updates": {"odp": {"frequency_days": "1"}}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-8(2)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si1_documented_string_true_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"policy": {"documented": "true"}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-1")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si3_deployed_one_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"malicious_code_protection": {"deployed": 1}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-3")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si11_null_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"error_handling": {"no_info_disclosure": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-11")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si16_yes_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"memory_protection": {"enabled": "yes"}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-16")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si12_object_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"information_management_retention": {"policy_enforced": {"value": true}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-12")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si5_string_false_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"security_alerts": {"acted_upon": "false"}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-5")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si2_3_over_benchmark_fails if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"time_to_remediate": {"max_days_to_remediate": 45}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2(3)")
	count(f) == 1
	contains(f[0], "organization-defined limit is 30")
}

test_si2_3_benchmark_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"time_to_remediate": {"odp": null}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2(3)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si2_3_days_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"time_to_remediate": {"max_days_to_remediate": "1"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2(3)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si2_3_measured_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"time_to_remediate": {"measured": "true"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-2(3)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_1_tool_not_connected_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"system_wide_ids": {"tools_not_connected": 2}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(1)")
	count(f) == 1
	contains(f[0], "2 intrusion detection tools")
}

test_si4_1_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"system_wide_ids": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_10_not_visible_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"encrypted_traffic_visibility": {"traffic_types_not_visible": 1}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(10)")
	count(f) == 1
	contains(f[0], "not visible")
}

test_si4_10_null_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"encrypted_traffic_visibility": {"traffic_types_not_visible": null}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(10)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_11_interior_not_analyzed_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"outbound_anomaly_analysis": {"interior_points_not_analyzed": 3}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(11)")
	count(f) == 1
	contains(f[0], "3 organization-defined interior points")
}

test_si4_11_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"outbound_anomaly_analysis": {"external_interfaces_not_analyzed": "0"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(11)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_12_not_automated_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"organization_alerts": {"automated": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(12)")
	count(f) == 1
	contains(f[0], "not raised by automated mechanisms")
}

test_si4_12_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"organization_alerts": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(12)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_14_no_rogue_detection_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"wireless_ids": {"rogue_device_detection": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(14)")
	count(f) == 1
	contains(f[0], "rogue wireless devices")
}

test_si4_14_one_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"wireless_ids": {"deployed": 1}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(14)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_16_not_correlated_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"correlation": {"sources_not_correlated": 1}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(16)")
	count(f) == 1
	contains(f[0], "not correlated")
}

test_si4_16_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"correlation": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(16)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_18_external_not_analyzed_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"covert_exfiltration": {"external_interfaces_not_analyzed": 1}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(18)")
	count(f) == 1
	contains(f[0], "covert exfiltration")
}

test_si4_18_null_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"covert_exfiltration": {"interior_points_not_analyzed": null}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(18)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_19_unmonitored_individuals_fail if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"individual_risk": {"individuals_without_additional_monitoring": 2}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(19)")
	count(f) == 1
	contains(f[0], "increased level of risk")
}

test_si4_19_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"individual_risk": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(19)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_20_unmonitored_privileged_fail if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"privileged_users": {"accounts_without_additional_monitoring": 4}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(20)")
	count(f) == 1
	contains(f[0], "4 privileged accounts")
}

test_si4_20_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"privileged_users": {"accounts_without_additional_monitoring": "none"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(20)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_22_unhandled_detection_fails if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"unauthorized_services": {"unhandled_detections": 1}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(22)")
	count(f) == 1
	contains(f[0], "neither audited nor alerted")
}

test_si4_22_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"unauthorized_services": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(22)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si4_23_components_unmonitored_fail if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"host_based": {"components_without_monitoring": 5}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(23)")
	count(f) == 1
	contains(f[0], "host-based monitoring")
}

test_si4_23_null_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"system_monitoring": {"host_based": {"components_without_monitoring": null}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-4(23)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si5_1_not_automated_fails if {
	inp := object.union(_pass, {"si_controls": {"security_alerts": {"automated_broadcast": {"automated": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-5(1)")
	count(f) == 1
	contains(f[0], "not broadcast")
}

test_si5_1_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"security_alerts": {"automated_broadcast": {"automated": "true"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-5(1)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si7_2_no_recipients_fails if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"automated_notifications": {"recipients_configured": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(2)")
	count(f) == 1
	contains(f[0], "not routed")
}

test_si7_2_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"automated_notifications": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(2)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si7_5_no_response_fails if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"automated_response": {"enabled": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(5)")
	count(f) == 1
	contains(f[0], "automated response")
}

test_si7_5_count_null_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"automated_response": {"components_without_response": null}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(5)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si7_15_unauthenticated_installs_fail if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"code_authentication": {"unauthenticated_installations": 3}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(15)")
	count(f) == 1
	contains(f[0], "not cryptographically authenticated")
}

test_si7_15_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"software_firmware_integrity": {"code_authentication": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-7(15)")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si13_no_mttf_fails if {
	inp := object.union(_pass, {"si_controls": {"predictable_failure_prevention": {"components_without_mttf": 2}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-13")
	count(f) == 1
	contains(f[0], "mean time to failure")
}

test_si13_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"predictable_failure_prevention": null}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-13")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si14_instance_too_old_fails if {
	inp := object.union(_pass, {"si_controls": {"non_persistence": {"oldest_instance_age_days": 9}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-14")
	count(f) == 1
	contains(f[0], "organization-defined limit is 1")
}

test_si14_odp_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"non_persistence": {"odp": {"max_lifetime_days": "1"}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-14")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si15_no_validation_fails if {
	inp := object.union(_pass, {"si_controls": {"output_filtering": {"applications_without_validation": 1}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-15")
	count(f) == 1
	contains(f[0], "no output validation")
}

test_si15_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"output_filtering": null}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-15")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si17_condition_without_procedure_fails if {
	inp := object.union(_pass, {"si_controls": {"fail_safe": {"conditions_without_procedure": 1}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-17")
	count(f) == 1
	contains(f[0], "no implemented fail-safe procedure")
}

test_si17_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"fail_safe": null}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-17")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si18_check_overdue_fails if {
	inp := object.union(_pass, {"si_controls": {"pii_quality": {"days_since_last": 120}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-18")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 90")
}

test_si18_odp_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"pii_quality": {"odp": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-18")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si19_identifying_datasets_fail if {
	inp := object.union(_pass, {"si_controls": {"de_identification": {"datasets_with_identifying_elements": 2}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-19")
	count(f) == 1
	contains(f[0], "still contain")
}

test_si19_days_null_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"de_identification": {"days_since_last": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-19")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si20_no_taint_fails if {
	inp := object.union(_pass, {"si_controls": {"tainting": {"components_without_taint": 1}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-20")
	count(f) == 1
	contains(f[0], "tainting")
}

test_si20_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"tainting": null}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-20")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si21_refresh_overdue_fails if {
	inp := object.union(_pass, {"si_controls": {"information_refresh": {"days_since_last": 8}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-21")
	count(f) == 1
	contains(f[0], "organization-defined frequency is 7")
}

test_si21_days_string_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"information_refresh": {"days_since_last": "1"}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-21")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si22_no_alternative_source_fails if {
	inp := object.union(_pass, {"si_controls": {"information_diversity": {"functions_without_alternative_source": 1}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-22")
	count(f) == 1
	contains(f[0], "no identified alternative information source")
}

test_si22_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"information_diversity": null}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-22")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si23_attested_false_fails if {
	inp := object.union(_pass, {"si_controls": {"information_fragmentation": {"attestation": {"attested": false}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-23")
	count(f) == 1
	contains(f[0], "not attested")
}

test_si23_empty_by_fails if {
	inp := object.union(_pass, {"si_controls": {"information_fragmentation": {"attestation": {"by": ""}}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-23")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_si23_missing_is_evidence_missing if {
	inp := object.union(_pass, {"si_controls": {"information_fragmentation": null}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 1
	f := _flagged(v, "SI-23")
	count(f) == 1
	contains(f[0], "not attested")
}

test_si1_true_still_passes if {
	inp := object.union(_pass, {"si_controls": {"policy": {"documented": true}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 0
}

test_high_enhancements_missing_do_not_fail_base if {
	inp := object.union(_pass, {"si_controls": {"flaw_remediation": {"time_to_remediate": null}, "system_monitoring": {"system_wide_ids": null, "encrypted_traffic_visibility": null, "outbound_anomaly_analysis": null, "organization_alerts": null, "wireless_ids": null, "correlation": null, "covert_exfiltration": null, "individual_risk": null, "privileged_users": null, "unauthorized_services": null, "host_based": null}, "security_alerts": {"automated_broadcast": null}, "software_firmware_integrity": {"automated_notifications": null, "automated_response": null, "code_authentication": null}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 16
	every id in {"SI-2", "SI-4", "SI-5", "SI-7", "SI-4(2)", "SI-4(4)", "SI-4(5)", "SI-7(1)", "SI-7(7)"} {
		count(_flagged(v, id)) == 0
	}
	every x in v {
		contains(x, "evidence missing")
	}
}

# The all-pass fixture with the facts of the Privacy-baseline enhancements.
_pass := object.union(_pass_base, {"si_controls": {"information_management_retention": {"pii_elements": {"odp": {"permitted_elements": ["name", "email"]}, "elements_processed": ["name"]}, "pii_minimization": {"odp": {"techniques": ["masking"]}, "techniques_applied": ["masking", "synthetic data"], "unminimized_datasets": 0}, "disposal": {"odp": {"techniques": ["crypto-erase"]}, "techniques_applied": ["crypto-erase"], "records_past_retention": 0}}, "pii_quality": {"individual_requests": {"process_implemented": true, "requests_not_actioned": 0}}}})

# --- Privacy-baseline enhancements and count type traps: each case flips exactly one id ---

test_privacy_si12_1_fails_1 if {
	v := data.nist.sp800_53.system_information_integrity.violation with input as object.union(_pass, {"si_controls": {"information_management_retention": {"pii_elements": {"elements_processed": ["name", "ssn"]}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"SI-12(1)"}
	some x in v
	contains(x, "outside the organization-defined list")
}

test_privacy_si12_1_evidence_missing_2 if {
	v := data.nist.sp800_53.system_information_integrity.violation with input as object.union(_pass, {"si_controls": {"information_management_retention": {"pii_elements": {"elements_processed": null}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"SI-12(1)"}
	some x in v
	contains(x, "evidence missing")
}

test_privacy_si12_2_fails_1 if {
	v := data.nist.sp800_53.system_information_integrity.violation with input as object.union(_pass, {"si_controls": {"information_management_retention": {"pii_minimization": {"techniques_applied": ["synthetic data"]}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"SI-12(2)"}
	some x in v
	contains(x, "minimization techniques not used")
}

test_privacy_si12_2_evidence_missing_2 if {
	v := data.nist.sp800_53.system_information_integrity.violation with input as object.union(_pass, {"si_controls": {"information_management_retention": {"pii_minimization": {"unminimized_datasets": 2.5}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"SI-12(2)"}
	some x in v
	contains(x, "evidence missing")
}

test_privacy_si12_3_fails_1 if {
	v := data.nist.sp800_53.system_information_integrity.violation with input as object.union(_pass, {"si_controls": {"information_management_retention": {"disposal": {"records_past_retention": 7}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"SI-12(3)"}
	some x in v
	contains(x, "beyond their retention period")
}

test_privacy_si12_3_evidence_missing_2 if {
	v := data.nist.sp800_53.system_information_integrity.violation with input as object.union(_pass, {"si_controls": {"information_management_retention": {"disposal": {"records_past_retention": -1}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"SI-12(3)"}
	some x in v
	contains(x, "evidence missing")
}

test_privacy_si18_4_fails_1 if {
	v := data.nist.sp800_53.system_information_integrity.violation with input as object.union(_pass, {"si_controls": {"pii_quality": {"individual_requests": {"requests_not_actioned": 2}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"SI-18(4)"}
	some x in v
	contains(x, "not actioned")
}

test_privacy_si18_4_evidence_missing_2 if {
	v := data.nist.sp800_53.system_information_integrity.violation with input as object.union(_pass, {"si_controls": {"pii_quality": {"individual_requests": {"process_implemented": "true"}}}})
	{trim_prefix(split(x, ":")[0], "NIST ") | some x in v} == {"SI-18(4)"}
	some x in v
	contains(x, "evidence missing")
}
