package cmmc.audit_accountability_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_audit_accountability.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_audit_accountability_loads_on_empty_input if {
	m := data.cmmc.audit_accountability with input as {}
	is_object(m)
}

test_cmmc_audit_accountability_report_wellformed_on_empty_input if {
	report := data.cmmc.audit_accountability.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_audit_accountability_fail_closed_on_empty_input if {
	report := data.cmmc.audit_accountability.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# --- semantic review 2026-11-13: domain verdict must agree with practices ---

good_input_review := {"audit": {"logging_enabled": true, "log_retention_days": 90, "auditd_active": true, "user_activity_tracked": true, "audit_rules_configured": true, "event_review_process": true, "last_review_days_ago": 365, "failure_alerting_enabled": true, "space_left_action": "ok", "admin_space_left_action": "ok", "centralized_logging": true, "siem_integrated": true, "report_generation_capability": true, "log_analysis_tool": "ok", "ntp_configured": true, "time_sync_active": true, "log_file_permissions_correct": true, "log_dir_permissions_correct": true, "auditd_immutable_config": true, "management_restricted": true, "privileged_command_rules": ["x"], "ntp_servers": ["a"], "audit_admins": ["a", "b"]}}

test_review_good_input_compliant if {
	r := data.cmmc.audit_accountability.compliance_report with input as good_input_review
	r.compliant
	r.failing == 0
}

test_review_too_many_audit_admins if {
	r := data.cmmc.audit_accountability.compliance_report with input as {"audit": {"logging_enabled": true, "log_retention_days": 90, "auditd_active": true, "user_activity_tracked": true, "audit_rules_configured": true, "event_review_process": true, "last_review_days_ago": 365, "failure_alerting_enabled": true, "space_left_action": "ok", "admin_space_left_action": "ok", "centralized_logging": true, "siem_integrated": true, "report_generation_capability": true, "log_analysis_tool": "ok", "ntp_configured": true, "time_sync_active": true, "log_file_permissions_correct": true, "log_dir_permissions_correct": true, "auditd_immutable_config": true, "management_restricted": true, "privileged_command_rules": ["x"], "ntp_servers": ["a"], "audit_admins": ["a", "b", "c", "d", "e", "f", "g", "h"]}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.3.9")
}

test_review_log_retention_missing if {
	r := data.cmmc.audit_accountability.compliance_report with input as {"audit": {"logging_enabled": true, "auditd_active": true, "user_activity_tracked": true, "audit_rules_configured": true, "event_review_process": true, "last_review_days_ago": 365, "failure_alerting_enabled": true, "space_left_action": "ok", "admin_space_left_action": "ok", "centralized_logging": true, "siem_integrated": true, "report_generation_capability": true, "log_analysis_tool": "ok", "ntp_configured": true, "time_sync_active": true, "log_file_permissions_correct": true, "log_dir_permissions_correct": true, "auditd_immutable_config": true, "management_restricted": true, "privileged_command_rules": ["x"], "ntp_servers": ["a"], "audit_admins": ["a", "b"]}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.3.1")
}
