package cmmc.system_information_integrity_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_system_information_integrity.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_system_information_integrity_loads_on_empty_input if {
	m := data.cmmc.system_information_integrity with input as {}
	is_object(m)
}

test_cmmc_system_information_integrity_report_wellformed_on_empty_input if {
	report := data.cmmc.system_information_integrity.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_system_information_integrity_fail_closed_on_empty_input if {
	report := data.cmmc.system_information_integrity.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# --- semantic review 2026-11-13: domain verdict must agree with practices ---

good_input_review := {"integrity": {"flaw_remediation_policy": true, "patch_management_program": true, "critical_patch_days": 30, "antimalware_installed": true, "antimalware_realtime_enabled": true, "antimalware_covers_entry_exit_points": true, "security_alerts_monitored": true, "threat_intel_feeds_subscribed": true, "alerts_actioned": true, "antimalware_auto_update": true, "signature_update_frequency_hours": 24, "periodic_system_scans": true, "scan_frequency_days": 7, "realtime_file_scanning": true, "download_scanning_enabled": true, "ids_ips_deployed": true, "inbound_traffic_monitored": true, "outbound_traffic_monitored": true, "attack_indicators_detected": true, "unauthorized_use_detection": true, "baseline_behavior_established": true, "anomaly_detection_enabled": true, "unauthorized_access_alerted": true}}

test_review_good_input_compliant if {
	r := data.cmmc.system_information_integrity.compliance_report with input as good_input_review
	r.compliant
	r.failing == 0
}

test_review_critical_patch_days_missing if {
	r := data.cmmc.system_information_integrity.compliance_report with input as {"integrity": {"flaw_remediation_policy": true, "patch_management_program": true, "antimalware_installed": true, "antimalware_realtime_enabled": true, "antimalware_covers_entry_exit_points": true, "security_alerts_monitored": true, "threat_intel_feeds_subscribed": true, "alerts_actioned": true, "antimalware_auto_update": true, "signature_update_frequency_hours": 24, "periodic_system_scans": true, "scan_frequency_days": 7, "realtime_file_scanning": true, "download_scanning_enabled": true, "ids_ips_deployed": true, "inbound_traffic_monitored": true, "outbound_traffic_monitored": true, "attack_indicators_detected": true, "unauthorized_use_detection": true, "baseline_behavior_established": true, "anomaly_detection_enabled": true, "unauthorized_access_alerted": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.14.")
}
