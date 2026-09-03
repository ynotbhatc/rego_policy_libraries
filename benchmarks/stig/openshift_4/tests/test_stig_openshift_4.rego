package stig.openshift_4_test

import rego.v1
import data.stig.openshift_4

test_report_wellformed_on_empty_input if {
	report := openshift_4.stig_assessment with input as {}
	is_object(report)
	report.summary.total_findings > 0
}

green_fixture := {
	 "openshift": {
	  "oauth_idle_timeout_configured": true,
	  "cluster_logging_forwarding_configured": true,
	  "rbac_enforced": true,
	  "api_server_audit_profile_set": true,
	  "root_sessions_disabled": true,
	  "identity_provider_fips_validated": true,
	  "fips_mode_enabled": true,
	  "etcd_encryption_enabled": true,
	  "default_scc_least_privilege": true,
	  "image_source_policy_configured": true,
	  "network_policy_default_deny": true
	 },
	 "rhcos": {
	  "audit_at_startup": true,
	  "chrony_configured": true,
	  "sshd_disabled": true
	 }
	}

test_fully_compliant_on_green_fixture if {
	report := openshift_4.stig_assessment with input as green_fixture
	report.summary.fully_compliant == true
}
