package cmmc.system_communications_protection_test

import rego.v1

# Generated smoke test for frameworks/federal/cmmc/cmmc_system_communications_protection.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cmmc_system_communications_protection_loads_on_empty_input if {
	m := data.cmmc.system_communications_protection with input as {}
	is_object(m)
}

test_cmmc_system_communications_protection_report_wellformed_on_empty_input if {
	report := data.cmmc.system_communications_protection.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_cmmc_system_communications_protection_fail_closed_on_empty_input if {
	report := data.cmmc.system_communications_protection.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

# --- semantic review 2026-11-13: domain verdict must agree with practices ---

good_input_review := {"scp": {"external_boundary_monitoring": true, "internal_boundary_controls": true, "network_traffic_controlled": true, "secure_architecture_principles": true, "defense_in_depth_implemented": true, "least_functionality_enforced": true, "admin_interface_separated": true, "user_mgmt_plane_separated": true, "shared_resource_controls": true, "memory_protection_enabled": true, "covert_channel_controls": true, "dmz_implemented": true, "public_systems_isolated": true, "cui_network_segregated": true, "default_deny_policy": true, "explicit_allow_rules": true, "firewall_rules_reviewed_annually": true, "split_tunneling_prevented": true, "vpn_enforces_all_traffic": true, "encryption_in_transit": true, "fips_validated_tls": true, "tls_min_version": "1.2", "session_timeout_enabled": true, "network_session_timeout_minutes": 30, "key_management_policy": true, "key_generation_secure": true, "key_rotation_policy": true, "key_storage_protected": true, "fips_140_2_validated": true, "non_fips_algorithms_prohibited": true, "remote_activation_prohibited": true, "camera_mic_indicator_present": true, "mobile_code_policy": true, "unauthorized_mobile_code_blocked": true, "mobile_code_usage_monitored": true, "voip_policy": true, "voip_traffic_encrypted": true, "voip_usage_monitored": true, "session_authentication_enforced": true, "anti_replay_protection": true, "session_hijacking_prevention": true, "encryption_at_rest": true, "fips_validated_storage_encryption": true, "database_encryption_enabled": true}}

test_review_good_input_compliant if {
	r := data.cmmc.system_communications_protection.compliance_report with input as good_input_review
	r.compliant
	r.failing == 0
}

test_review_session_timeout_missing if {
	r := data.cmmc.system_communications_protection.compliance_report with input as {"scp": {"external_boundary_monitoring": true, "internal_boundary_controls": true, "network_traffic_controlled": true, "secure_architecture_principles": true, "defense_in_depth_implemented": true, "least_functionality_enforced": true, "admin_interface_separated": true, "user_mgmt_plane_separated": true, "shared_resource_controls": true, "memory_protection_enabled": true, "covert_channel_controls": true, "dmz_implemented": true, "public_systems_isolated": true, "cui_network_segregated": true, "default_deny_policy": true, "explicit_allow_rules": true, "firewall_rules_reviewed_annually": true, "split_tunneling_prevented": true, "vpn_enforces_all_traffic": true, "encryption_in_transit": true, "fips_validated_tls": true, "tls_min_version": "1.2", "session_timeout_enabled": true, "key_management_policy": true, "key_generation_secure": true, "key_rotation_policy": true, "key_storage_protected": true, "fips_140_2_validated": true, "non_fips_algorithms_prohibited": true, "remote_activation_prohibited": true, "camera_mic_indicator_present": true, "mobile_code_policy": true, "unauthorized_mobile_code_blocked": true, "mobile_code_usage_monitored": true, "voip_policy": true, "voip_traffic_encrypted": true, "voip_usage_monitored": true, "session_authentication_enforced": true, "anti_replay_protection": true, "session_hijacking_prevention": true, "encryption_at_rest": true, "fips_validated_storage_encryption": true, "database_encryption_enabled": true}}
	r.failing > 0
	not r.compliant
	count(r.violations) > 0
	some v in r.violations
	startswith(v, "3.13.")
}

test_review_tls_1_3_is_compliant if {
	r := data.cmmc.system_communications_protection.compliance_report with input as {"scp": {"external_boundary_monitoring": true, "internal_boundary_controls": true, "network_traffic_controlled": true, "secure_architecture_principles": true, "defense_in_depth_implemented": true, "least_functionality_enforced": true, "admin_interface_separated": true, "user_mgmt_plane_separated": true, "shared_resource_controls": true, "memory_protection_enabled": true, "covert_channel_controls": true, "dmz_implemented": true, "public_systems_isolated": true, "cui_network_segregated": true, "default_deny_policy": true, "explicit_allow_rules": true, "firewall_rules_reviewed_annually": true, "split_tunneling_prevented": true, "vpn_enforces_all_traffic": true, "encryption_in_transit": true, "fips_validated_tls": true, "tls_min_version": "1.3", "session_timeout_enabled": true, "network_session_timeout_minutes": 30, "key_management_policy": true, "key_generation_secure": true, "key_rotation_policy": true, "key_storage_protected": true, "fips_140_2_validated": true, "non_fips_algorithms_prohibited": true, "remote_activation_prohibited": true, "camera_mic_indicator_present": true, "mobile_code_policy": true, "unauthorized_mobile_code_blocked": true, "mobile_code_usage_monitored": true, "voip_policy": true, "voip_traffic_encrypted": true, "voip_usage_monitored": true, "session_authentication_enforced": true, "anti_replay_protection": true, "session_hijacking_prevention": true, "encryption_at_rest": true, "fips_validated_storage_encryption": true, "database_encryption_enabled": true}}
	r.compliant
	r.failing == 0
}
