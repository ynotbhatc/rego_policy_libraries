package stig.apache_2_4_unix_test

import rego.v1
import data.stig.apache_2_4_unix

test_report_wellformed_on_empty_input if {
	report := apache_2_4_unix.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
}

green_fixture := {
	 "apache": {
	  "remote_session_crypto_enabled": true,
	  "log_files_privileged_only": true,
	  "modules_reviewed_and_signed": true,
	  "documentation_excluded": true,
	  "unused_script_mappings_removed": true,
	  "app_dirs_admin_only": true,
	  "session_id_full_charset": true,
	  "session_inactive_timeout_set": true,
	  "service_account_no_login_shell": true,
	  "vendor_supported_version": true
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := apache_2_4_unix.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
}

test_main_alias_fail_closed_on_empty if {
	rep := data.stig.apache_2_4_unix.main.compliance_report with input as {}
	rep.compliant == false
	rep.facts_supplied == false
}
