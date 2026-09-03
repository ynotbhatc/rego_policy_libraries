package stig.cisco_ios_xe_router_test

import rego.v1
import data.stig.cisco_ios_xe_router

test_report_wellformed_on_empty_input if {
	report := cisco_ios_xe_router.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
}

green_fixture := {
	 "cisco": {
	  "nonsecure_services_disabled": true,
	  "min_15_char_password_enforced": true,
	  "passwords_stored_hashed": true,
	  "session_timeout_configured": true,
	  "ssh_fips_hmac_configured": true,
	  "ssh_fips_ciphers_configured": true,
	  "two_authentication_servers": true,
	  "config_backup_on_change": true,
	  "two_syslog_servers": true,
	  "supported_ios_release": true
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := cisco_ios_xe_router.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
}

test_main_alias_fail_closed_on_empty if {
	rep := data.stig.cisco_ios_xe_router.main.compliance_report with input as {}
	rep.compliant == false
	rep.facts_supplied == false
}
