package cis_arista_eos_test

import rego.v1

# Tests for the CIS Arista EOS Benchmark v1.0.0 rewrite: a pass and a fail test per recommendation,
# plus a fire / no-fire pair for every running-config contradiction check.

attest := {
	"mgmt_vrf_exists": true,
	"control_plane_acl_applied": true,
	"control_plane_policy_map_applied": true,
	"ntp_configured": true,
	"ntp_authentication_configured": true,
	"dns_configured": true,
	"syslog_host_configured": true,
	"vlan1_suspended_and_pruned": true,
	"syslog_tls_configured": true,
	"secrets_aes_gcm_encryption": true,
	"no_passwordless_remote_login": true,
	"enable_password_set": true,
	"password_policy_applied": true,
	"root_login_disabled": true,
	"roles_reviewed": true,
	"console_idle_timeout": true,
	"emergency_local_account": true,
	"aaa_servers_configured": true,
	"aaa_server_groups_configured": true,
	"aaa_methods_configured": true,
	"ssh_restricted_to_mgmt_vrf": true,
	"ssh_idle_timeout": true,
	"ssh_weak_algorithms_removed": true,
	"snmp_restricted_to_mgmt_vrf": true,
	"snmp_community_hardened": true,
	"snmpv3_only": true,
	"telnet_disabled": true,
	"api_https_only": true,
	"login_banner_configured": true,
	"ospf_authentication": true,
	"isis_authentication": true,
	"bgp_neighbor_authentication": true,
	"bgp_tcp_ao": true,
}

good := {"eos_config": {
	"attest": attest,
	"management": {
		"security": {"password_encryption_reversible": "aes-256-gcm"},
		"console": {"idle_timeout": 5},
		"ssh": {"idle_timeout": 10},
		"telnet": {"shutdown": true},
	},
	"control_plane": {"service_policy": {"input": "copp-system-policy"}},
	"logging": {"hosts": ["10.0.0.5"]},
	"aaa": {
		"allow_nopassword_remote_login": false,
		"root_enabled": false,
		"authentication": {"default": ["group TACPLUS", "local"]},
	},
}}

unattest(key) := json.patch(good, [{"op": "replace", "path": sprintf("/eos_config/attest/%s", [key]), "value": false}])

with_cfg(path, value) := json.patch(good, [{"op": "add", "path": path, "value": value}])

drop_cfg(path) := json.remove(good, [path])

# ── whole-module behaviour (existing test names kept) ──
test_full_config_compliant if data.cis_arista_eos.compliant with input as good

test_partial_facts_not_compliant if {
	inp := {"eos_config": {"attest": {"mgmt_vrf_exists": true}, "logging": {"hosts": ["10.0.0.5"]}}}
	not data.cis_arista_eos.compliant with input as inp
}

test_compliant_is_false_not_undefined if {
	data.cis_arista_eos.compliant == false with input as {}
}

test_missing_interfaces_fail_closed if {
	# No eos_config at all: the device is not evaluated, every control fails.
	v := data.cis_arista_eos.violations with input as {}
	"CIS Arista EOS: evidence missing — eos_config not collected; the device was not evaluated" in v
	f := data.cis_arista_eos.failed_controls with input as {}
	count(f) == 33
}

test_long_vty_timeout_flagged if {
	inp := with_cfg("/eos_config/management/console/idle_timeout", 60)
	v := data.cis_arista_eos.violations with input as inp
	"2.4.1: running config contradicts the control — console idle timeout is 60 minutes (0 = never; must be 1-10)" in v
}

test_dhcp_snooping_missing_flagged if {
	# Old 3.3.1 (DHCP snooping) is not in v1.0.0; repointed to an unattested control.
	v := data.cis_arista_eos.violations with input as unattest("vlan1_suspended_and_pruned")
	"1.1.8: manual review not attested — VLAN Management (attest.vlan1_suspended_and_pruned)" in v
}

test_attestation_must_be_true_boolean if {
	inp := with_cfg("/eos_config/attest/telnet_disabled", "yes")
	f := data.cis_arista_eos.failed_controls with input as inp
	"2.8" in f
}

test_summary_counts_distinct_controls if {
	# 2.8 unattested AND contradicted, and 2.4.1 unattested: two failing controls, not three.
	inp := json.patch(good, [
		{"op": "replace", "path": "/eos_config/attest/telnet_disabled", "value": false},
		{"op": "replace", "path": "/eos_config/management/telnet/shutdown", "value": false},
		{"op": "replace", "path": "/eos_config/attest/console_idle_timeout", "value": false},
	])
	s := data.cis_arista_eos.compliance_summary with input as inp
	s.total_controls == 33
	s.failing_controls == 2
	s.passing_controls == 31
	s.sections.device_access.violations == 2
	s.sections.eos_services.violations == 0
}

test_summary_empty_input_never_negative if {
	s := data.cis_arista_eos.compliance_summary with input as {}
	s.passing_controls == 0
	s.failing_controls == 33
}

test_section_totals if {
	s := data.cis_arista_eos.compliance_summary with input as good
	s.sections.eos_services.total == 10
	s.sections.device_access.total == 19
	s.sections.routing_protocols.total == 4
	s.compliance_percentage == 100
}

test_report_shape if {
	r := data.cis_arista_eos.compliance_report with input as good
	r.benchmark == "CIS Arista EOS Benchmark v1.0.0"
	r.total_controls == 33
	r.standard_total == 33
	r.compliant == true
	r.violation_count == 0
}

test_report_populated_when_failing if {
	r := data.cis_arista_eos.compliance_report with input as unattest("bgp_tcp_ao")
	r.compliant == false
	r.failed_controls == ["3.2.2"]
	d := data.cis_arista_eos.detailed_findings with input as unattest("bgp_tcp_ao")
	count(d.routing_protocols_violations) == 1
	count(d.device_access_violations) == 0
}

# ── per recommendation: pass / fail ──

test_1_1_1_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.1.1.1" in f
}

test_1_1_1_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("mgmt_vrf_exists")
	"1.1.1.1: manual review not attested — Ensure the Management VRF Exists (attest.mgmt_vrf_exists)" in v
	not data.cis_arista_eos.compliant with input as unattest("mgmt_vrf_exists")
}

test_1_1_2_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.1.2" in f
}

test_1_1_2_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("control_plane_acl_applied")
	"1.1.2: manual review not attested — Control Plane ACL (attest.control_plane_acl_applied)" in v
	not data.cis_arista_eos.compliant with input as unattest("control_plane_acl_applied")
}

test_1_1_3_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.1.3" in f
}

test_1_1_3_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("control_plane_policy_map_applied")
	"1.1.3: manual review not attested — Control Plane Policy Map (attest.control_plane_policy_map_applied)" in v
	not data.cis_arista_eos.compliant with input as unattest("control_plane_policy_map_applied")
}

test_1_1_4_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.1.4" in f
}

test_1_1_4_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("ntp_configured")
	"1.1.4: manual review not attested — Network Time Protocol (attest.ntp_configured)" in v
	not data.cis_arista_eos.compliant with input as unattest("ntp_configured")
}

test_1_1_5_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.1.5" in f
}

test_1_1_5_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("ntp_authentication_configured")
	"1.1.5: manual review not attested — NTP authentication (attest.ntp_authentication_configured)" in v
	not data.cis_arista_eos.compliant with input as unattest("ntp_authentication_configured")
}

test_1_1_6_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.1.6" in f
}

test_1_1_6_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("dns_configured")
	"1.1.6: manual review not attested — DNS Configuration (attest.dns_configured)" in v
	not data.cis_arista_eos.compliant with input as unattest("dns_configured")
}

test_1_1_7_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.1.7" in f
}

test_1_1_7_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("syslog_host_configured")
	"1.1.7: manual review not attested — Logging (attest.syslog_host_configured)" in v
	not data.cis_arista_eos.compliant with input as unattest("syslog_host_configured")
}

test_1_1_8_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.1.8" in f
}

test_1_1_8_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("vlan1_suspended_and_pruned")
	"1.1.8: manual review not attested — VLAN Management (attest.vlan1_suspended_and_pruned)" in v
	not data.cis_arista_eos.compliant with input as unattest("vlan1_suspended_and_pruned")
}

test_1_1_9_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.1.9" in f
}

test_1_1_9_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("syslog_tls_configured")
	"1.1.9: manual review not attested — Syslog with TLS support (attest.syslog_tls_configured)" in v
	not data.cis_arista_eos.compliant with input as unattest("syslog_tls_configured")
}

test_1_2_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "1.2" in f
}

test_1_2_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("secrets_aes_gcm_encryption")
	"1.2: manual review not attested — Enable AES-GCM Encryption of EOS Secrets (attest.secrets_aes_gcm_encryption)" in v
	not data.cis_arista_eos.compliant with input as unattest("secrets_aes_gcm_encryption")
}

test_2_1_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.1.1" in f
}

test_2_1_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("no_passwordless_remote_login")
	"2.1.1: manual review not attested — Do not allow remote login without a password (attest.no_passwordless_remote_login)" in v
	not data.cis_arista_eos.compliant with input as unattest("no_passwordless_remote_login")
}

test_2_1_2_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.1.2" in f
}

test_2_1_2_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("enable_password_set")
	"2.1.2: manual review not attested — Configure an enable password (attest.enable_password_set)" in v
	not data.cis_arista_eos.compliant with input as unattest("enable_password_set")
}

test_2_1_3_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.1.3" in f
}

test_2_1_3_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("password_policy_applied")
	"2.1.3: manual review not attested — Create a password complexity policy (attest.password_policy_applied)" in v
	not data.cis_arista_eos.compliant with input as unattest("password_policy_applied")
}

test_2_1_4_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.1.4" in f
}

test_2_1_4_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("root_login_disabled")
	"2.1.4: manual review not attested — Verify root login is disabled (attest.root_login_disabled)" in v
	not data.cis_arista_eos.compliant with input as unattest("root_login_disabled")
}

test_2_3_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.3.1" in f
}

test_2_3_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("roles_reviewed")
	"2.3.1: manual review not attested — Roles (attest.roles_reviewed)" in v
	not data.cis_arista_eos.compliant with input as unattest("roles_reviewed")
}

test_2_4_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.4.1" in f
}

test_2_4_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("console_idle_timeout")
	"2.4.1: manual review not attested — Idle Timeout (attest.console_idle_timeout)" in v
	not data.cis_arista_eos.compliant with input as unattest("console_idle_timeout")
}

test_2_4_2_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.4.2" in f
}

test_2_4_2_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("emergency_local_account")
	"2.4.2: manual review not attested — Emergency Console Access (attest.emergency_local_account)" in v
	not data.cis_arista_eos.compliant with input as unattest("emergency_local_account")
}

test_2_5_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.5.1" in f
}

test_2_5_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("aaa_servers_configured")
	"2.5.1: manual review not attested — Configure TACACS+/RADIUS server (attest.aaa_servers_configured)" in v
	not data.cis_arista_eos.compliant with input as unattest("aaa_servers_configured")
}

test_2_5_2_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.5.2" in f
}

test_2_5_2_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("aaa_server_groups_configured")
	"2.5.2: manual review not attested — Server Groups (attest.aaa_server_groups_configured)" in v
	not data.cis_arista_eos.compliant with input as unattest("aaa_server_groups_configured")
}

test_2_5_3_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.5.3" in f
}

test_2_5_3_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("aaa_methods_configured")
	"2.5.3: manual review not attested — Authentication, Authorization, and Accounting (attest.aaa_methods_configured)" in v
	not data.cis_arista_eos.compliant with input as unattest("aaa_methods_configured")
}

test_2_6_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.6.1" in f
}

test_2_6_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("ssh_restricted_to_mgmt_vrf")
	"2.6.1: manual review not attested — Limit SSH Access Only To The Network Management Segment (attest.ssh_restricted_to_mgmt_vrf)" in v
	not data.cis_arista_eos.compliant with input as unattest("ssh_restricted_to_mgmt_vrf")
}

test_2_6_2_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.6.2" in f
}

test_2_6_2_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("ssh_idle_timeout")
	"2.6.2: manual review not attested — Set Idle Timeout for SSH to 10 Minutes or Less (attest.ssh_idle_timeout)" in v
	not data.cis_arista_eos.compliant with input as unattest("ssh_idle_timeout")
}

test_2_6_3_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.6.3" in f
}

test_2_6_3_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("ssh_weak_algorithms_removed")
	"2.6.3: manual review not attested — Remove cryptographically weak algorithms (attest.ssh_weak_algorithms_removed)" in v
	not data.cis_arista_eos.compliant with input as unattest("ssh_weak_algorithms_removed")
}

test_2_7_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.7.1" in f
}

test_2_7_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("snmp_restricted_to_mgmt_vrf")
	"2.7.1: manual review not attested — Limit SNMP Access To Management VRF (attest.snmp_restricted_to_mgmt_vrf)" in v
	not data.cis_arista_eos.compliant with input as unattest("snmp_restricted_to_mgmt_vrf")
}

test_2_7_2_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.7.2" in f
}

test_2_7_2_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("snmp_community_hardened")
	"2.7.2: manual review not attested — Ensure SNMP Community (attest.snmp_community_hardened)" in v
	not data.cis_arista_eos.compliant with input as unattest("snmp_community_hardened")
}

test_2_7_3_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.7.3" in f
}

test_2_7_3_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("snmpv3_only")
	"2.7.3: manual review not attested — Use SNMPv3 Instead of Earlier Versions (attest.snmpv3_only)" in v
	not data.cis_arista_eos.compliant with input as unattest("snmpv3_only")
}

test_2_8_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.8" in f
}

test_2_8_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("telnet_disabled")
	"2.8: manual review not attested — Telnet access (attest.telnet_disabled)" in v
	not data.cis_arista_eos.compliant with input as unattest("telnet_disabled")
}

test_2_9_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.9" in f
}

test_2_9_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("api_https_only")
	"2.9: manual review not attested — API access using https (attest.api_https_only)" in v
	not data.cis_arista_eos.compliant with input as unattest("api_https_only")
}

test_2_9_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "2.9.1" in f
}

test_2_9_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("login_banner_configured")
	"2.9.1: manual review not attested — Login Banner (attest.login_banner_configured)" in v
	not data.cis_arista_eos.compliant with input as unattest("login_banner_configured")
}

test_3_1_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "3.1.1" in f
}

test_3_1_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("ospf_authentication")
	"3.1.1: manual review not attested — OSPF Interface Authentication (attest.ospf_authentication)" in v
	not data.cis_arista_eos.compliant with input as unattest("ospf_authentication")
}

test_3_1_2_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "3.1.2" in f
}

test_3_1_2_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("isis_authentication")
	"3.1.2: manual review not attested — ISIS Interface and Instance Authentication (attest.isis_authentication)" in v
	not data.cis_arista_eos.compliant with input as unattest("isis_authentication")
}

test_3_2_1_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "3.2.1" in f
}

test_3_2_1_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("bgp_neighbor_authentication")
	"3.2.1: manual review not attested — BGP Authentication (attest.bgp_neighbor_authentication)" in v
	not data.cis_arista_eos.compliant with input as unattest("bgp_neighbor_authentication")
}

test_3_2_2_pass if {
	f := data.cis_arista_eos.failed_controls with input as good
	not "3.2.2" in f
}

test_3_2_2_fail_not_attested if {
	v := data.cis_arista_eos.violations with input as unattest("bgp_tcp_ao")
	"3.2.2: manual review not attested — BGP TCP Authentication Option (TCP-AO) (attest.bgp_tcp_ao)" in v
	not data.cis_arista_eos.compliant with input as unattest("bgp_tcp_ao")
}

# ── running-config contradictions: fire on bad value, silent when not collected ──

test_1_2_config_contradiction if {
	inp := with_cfg("/eos_config/management/security/password_encryption_reversible", "sha512")
	v := data.cis_arista_eos.violations with input as inp
	"1.2: running config contradicts the control — secrets are not stored with reversible aes-256-gcm encryption" in v
	f := data.cis_arista_eos.failed_controls with input as inp
	"1.2" in f
}

test_1_2_config_absent_no_veto if {
	f := data.cis_arista_eos.failed_controls with input as drop_cfg("/eos_config/management/security/password_encryption_reversible")
	not "1.2" in f
}

test_1_1_3_config_contradiction if {
	inp := with_cfg("/eos_config/control_plane", {"ip_access_group": "default-control-plane-acl"})
	v := data.cis_arista_eos.violations with input as inp
	"1.1.3: running config contradicts the control — no control-plane service-policy is applied" in v
	f := data.cis_arista_eos.failed_controls with input as inp
	"1.1.3" in f
}

test_1_1_3_config_absent_no_veto if {
	f := data.cis_arista_eos.failed_controls with input as drop_cfg("/eos_config/control_plane")
	not "1.1.3" in f
}

test_1_1_7_config_contradiction if {
	inp := with_cfg("/eos_config/logging/hosts", [])
	v := data.cis_arista_eos.violations with input as inp
	"1.1.7: running config contradicts the control — no remote syslog host is configured" in v
	f := data.cis_arista_eos.failed_controls with input as inp
	"1.1.7" in f
}

test_1_1_7_config_absent_no_veto if {
	f := data.cis_arista_eos.failed_controls with input as drop_cfg("/eos_config/logging/hosts")
	not "1.1.7" in f
}

test_2_1_1_config_contradiction if {
	inp := with_cfg("/eos_config/aaa/allow_nopassword_remote_login", true)
	v := data.cis_arista_eos.violations with input as inp
	"2.1.1: running config contradicts the control — passwordless remote login is allowed by the AAA policy" in v
	f := data.cis_arista_eos.failed_controls with input as inp
	"2.1.1" in f
}

test_2_1_1_config_absent_no_veto if {
	f := data.cis_arista_eos.failed_controls with input as drop_cfg("/eos_config/aaa/allow_nopassword_remote_login")
	not "2.1.1" in f
}

test_2_1_4_config_contradiction if {
	inp := with_cfg("/eos_config/aaa/root_enabled", true)
	v := data.cis_arista_eos.violations with input as inp
	"2.1.4: running config contradicts the control — the root account is enabled" in v
	f := data.cis_arista_eos.failed_controls with input as inp
	"2.1.4" in f
}

test_2_1_4_config_absent_no_veto if {
	f := data.cis_arista_eos.failed_controls with input as drop_cfg("/eos_config/aaa/root_enabled")
	not "2.1.4" in f
}

test_2_4_1_config_contradiction if {
	inp := with_cfg("/eos_config/management/console/idle_timeout", 0)
	v := data.cis_arista_eos.violations with input as inp
	"2.4.1: running config contradicts the control — console idle timeout is 0 minutes (0 = never; must be 1-10)" in v
	f := data.cis_arista_eos.failed_controls with input as inp
	"2.4.1" in f
}

test_2_4_1_config_absent_no_veto if {
	f := data.cis_arista_eos.failed_controls with input as drop_cfg("/eos_config/management/console/idle_timeout")
	not "2.4.1" in f
}

test_2_5_3_config_contradiction if {
	inp := with_cfg("/eos_config/aaa/authentication/default", ["local"])
	v := data.cis_arista_eos.violations with input as inp
	"2.5.3: running config contradicts the control — default login authentication does not use a TACACS+/RADIUS server group" in v
	f := data.cis_arista_eos.failed_controls with input as inp
	"2.5.3" in f
}

test_2_5_3_config_absent_no_veto if {
	f := data.cis_arista_eos.failed_controls with input as drop_cfg("/eos_config/aaa/authentication/default")
	not "2.5.3" in f
}

test_2_6_2_config_contradiction if {
	inp := with_cfg("/eos_config/management/ssh/idle_timeout", 11)
	v := data.cis_arista_eos.violations with input as inp
	"2.6.2: running config contradicts the control — SSH idle timeout is 11 minutes (0 = never; must be 1-10)" in v
	f := data.cis_arista_eos.failed_controls with input as inp
	"2.6.2" in f
}

test_2_6_2_config_absent_no_veto if {
	f := data.cis_arista_eos.failed_controls with input as drop_cfg("/eos_config/management/ssh/idle_timeout")
	not "2.6.2" in f
}

test_2_8_config_contradiction if {
	inp := with_cfg("/eos_config/management/telnet/shutdown", false)
	v := data.cis_arista_eos.violations with input as inp
	"2.8: running config contradicts the control — telnet management is not shut down" in v
	f := data.cis_arista_eos.failed_controls with input as inp
	"2.8" in f
}

test_2_8_config_absent_no_veto if {
	f := data.cis_arista_eos.failed_controls with input as drop_cfg("/eos_config/management/telnet/shutdown")
	not "2.8" in f
}
