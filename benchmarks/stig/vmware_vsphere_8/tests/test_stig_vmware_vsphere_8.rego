package stig.vmware_vsphere_8_test

import rego.v1
import data.stig.vmware_vsphere_8

test_report_wellformed_on_empty_input if {
	report := vmware_vsphere_8.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
}

green_fixture := {
	 "esxi": {
	  "lockdown_mode_enabled": true,
	  "ssh_fips_140_2_enabled": true,
	  "password_quality_policy_configured": true,
	  "shell_idle_timeout_15min": true,
	  "audit_storage_one_week_allocated": true,
	  "ntp_authoritative_source_configured": true,
	  "vib_acceptance_partner_or_stricter": true,
	  "mgmt_traffic_isolated_or_encrypted": true,
	  "vswitch_mac_changes_rejected": true,
	  "patches_current": true
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := vmware_vsphere_8.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
}

test_main_alias_fail_closed_on_empty if {
	rep := data.stig.vmware_vsphere_8.main.compliance_report with input as {}
	rep.compliant == false
	rep.facts_supplied == false
}
