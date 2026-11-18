package stig.openshift_4_test

import data.stig.openshift_4
import rego.v1

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
		"network_policy_default_deny": true,
	},
	"rhcos": {
		"audit_at_startup": true,
		"chrony_configured": true,
		"sshd_disabled": true,
	},
}

# Semantic review 2026-11-13: six CAT II controls have no matching fact in the contract yet, so
# they report Open on every input (fail closed) instead of passing on an unrelated fact.
unevidenced := {"CNTR-OS-000010", "CNTR-OS-000030", "CNTR-OS-000320", "CNTR-OS-000560", "CNTR-OS-000720", "CNTR-OS-000860"}
