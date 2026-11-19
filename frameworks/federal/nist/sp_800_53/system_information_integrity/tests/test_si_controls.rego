package nist.sp800_53.system_information_integrity_logic_test

import rego.v1

# Logic tests for system_information_integrity/si_controls.rego. Every case states its input inline (no helper
# does `with input as`, which the wasm build rejects); each failing case changes one fact of the all-pass fixture
# and must flip exactly that control id.

_pass := {"si_controls": {"policy": {"documented": true}, "flaw_remediation": {"timely": true, "automated_status": {"automated": true, "days_since_last": 1, "odp": {"frequency_days": 7}}}, "malicious_code_protection": {"deployed": true}, "system_monitoring": {"continuous": true, "real_time_analysis": {"automated_tools_enabled": true}, "traffic_monitoring": {"criteria_defined": true, "inbound_monitored": true, "outbound_monitored": true, "days_since_last": 0, "odp": {"frequency_days": 1}}, "alerts": {"recipients_configured": true, "indicators_without_alert": 0}}, "security_alerts": {"acted_upon": true}, "security_function_verification": {"tested": true}, "software_firmware_integrity": {"verified": true, "integrity_checks": {"unchecked_items": 0, "days_since_last": 1, "odp": {"frequency_days": 7}}, "incident_response_integration": {"unauthorized_changes_routed": true}}, "spam_protection": {"enabled": true, "automatic_updates": {"enabled": true, "days_since_last": 1, "odp": {"frequency_days": 1}}}, "input_validation": {"enforced": true}, "error_handling": {"no_info_disclosure": true}, "information_management_retention": {"policy_enforced": true}, "memory_protection": {"enabled": true}}}

_flagged(v, id) := [x | some x in v; startswith(x, concat("", ["NIST ", id, ":"]))]

test_all_pass_fixture_is_compliant if {
	r := data.nist.sp800_53.system_information_integrity.compliance_report with input as _pass
	r.compliant == true
	r.violation_count == 0
}

test_empty_input_one_finding_per_control if {
	r := data.nist.sp800_53.system_information_integrity.compliance_report with input as {}
	r.controls_evaluated == 19
	count(r.violations) == count(data.nist.sp800_53.system_information_integrity.evaluated_controls)
	every id in data.nist.sp800_53.system_information_integrity.evaluated_controls {
		count(_flagged(r.violations, id)) == 1
	}
	every v in r.violations {
		contains(v, "evidence missing")
	}
}

test_evaluated_controls_match_catalog if {
	data.nist.sp800_53.system_information_integrity.evaluated_controls == {"SI-1", "SI-2", "SI-2(2)", "SI-3", "SI-4", "SI-4(2)", "SI-4(4)", "SI-4(5)", "SI-5", "SI-6", "SI-7", "SI-7(1)", "SI-7(7)", "SI-8", "SI-8(2)", "SI-10", "SI-11", "SI-12", "SI-16"}
}

# The original checks kept their pass condition: a truthy non-boolean still passes them (unchanged behaviour).
test_legacy_pass_condition_unchanged if {
	inp := object.union(_pass, {"si_controls": {"memory_protection": {"enabled": "yes"}}})
	v := data.nist.sp800_53.system_information_integrity.violation with input as inp
	count(v) == 0
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
