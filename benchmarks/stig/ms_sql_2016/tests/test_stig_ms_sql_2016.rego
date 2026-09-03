package stig.ms_sql_2016_test

import rego.v1
import data.stig.ms_sql_2016

test_report_wellformed_on_empty_input if {
	report := ms_sql_2016.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
}

green_fixture := {
	 "sql": {
	  "org_level_auth_integrated": true,
	  "authorizations_enforced": true,
	  "install_account_restricted": true,
	  "password_standards_enforced": true,
	  "encrypted_password_transmission": true,
	  "tls_for_transmission": true,
	  "pki_keys_access_enforced": true,
	  "fips_modules_in_use": true,
	  "data_at_rest_protected": true,
	  "sa_account_disabled": true,
	  "sqlcmd_no_cleartext_credentials": true,
	  "auth_feedback_obscured": true,
	  "vendor_supported_version": true
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := ms_sql_2016.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
}

test_main_alias_fail_closed_on_empty if {
	rep := data.stig.ms_sql_2016.main.compliance_report with input as {}
	rep.compliant == false
	rep.facts_supplied == false
}
