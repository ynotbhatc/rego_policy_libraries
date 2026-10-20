# METADATA
# title: "CIS Arista EOS Benchmark v1.0.0"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, arista]
#   coverage:
#     checks: 36
#     cited: 34
#     expected: 33
#     found: 34
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_arista_eos

# CIS Arista EOS Benchmark v1.0.0
# 33 recommendations, every one in the benchmark (25 Level 1, 8 Level 2). IDs, titles and levels are
# taken from the official CIS workbook. The benchmark marks all 33 as Manual, so each control passes
# only when the review is attested (input.eos_config.attest.<key> == true). Where the collected running
# config can prove an attestation wrong, that config is checked too and a contradiction fails the control.
# A missing config field never vetoes (manual review is the evidence), but a missing attestation never passes.
#
# Input contract:
#   input.eos_config.attest.<key>                              : attestation booleans, one per recommendation
#   input.eos_config.management.security.password_encryption_reversible : "aes-256-gcm" expected     (1.2)
#   input.eos_config.control_plane.service_policy.input         : CoPP policy map name             (1.1.3)
#   input.eos_config.logging.hosts[]                            : syslog hosts                      (1.1.7)
#   input.eos_config.aaa.allow_nopassword_remote_login          : boolean                           (2.1.1)
#   input.eos_config.aaa.root_enabled                           : boolean ("no aaa root" => false)  (2.1.4)
#   input.eos_config.management.console.idle_timeout            : minutes, 0 = never                (2.4.1)
#   input.eos_config.aaa.authentication.default[]               : login methods                     (2.5.3)
#   input.eos_config.management.ssh.idle_timeout                : minutes, 0 = never                (2.6.2)
#   input.eos_config.management.telnet.shutdown                 : boolean                           (2.8)

import rego.v1

# ── control table ────────────────────────────────────────────────────────────
sections := {
	"1": "EOS Services",
	"2": "Device Access",
	"3": "Routing Protocols",
}

section_keys := {"1": "eos_services", "2": "device_access", "3": "routing_protocols"}

controls := {
	"1.1.1.1": {"title": "Ensure the Management VRF Exists", "level": 1, "attest": "mgmt_vrf_exists"},
	"1.1.2": {"title": "Control Plane ACL", "level": 1, "attest": "control_plane_acl_applied"},
	"1.1.3": {"title": "Control Plane Policy Map", "level": 1, "attest": "control_plane_policy_map_applied"},
	"1.1.4": {"title": "Network Time Protocol", "level": 1, "attest": "ntp_configured"},
	"1.1.5": {"title": "NTP authentication", "level": 2, "attest": "ntp_authentication_configured"},
	"1.1.6": {"title": "DNS Configuration", "level": 1, "attest": "dns_configured"},
	"1.1.7": {"title": "Logging", "level": 1, "attest": "syslog_host_configured"},
	"1.1.8": {"title": "VLAN Management", "level": 1, "attest": "vlan1_suspended_and_pruned"},
	"1.1.9": {"title": "Syslog with TLS support", "level": 2, "attest": "syslog_tls_configured"},
	"1.2": {"title": "Enable AES-GCM Encryption of EOS Secrets", "level": 1, "attest": "secrets_aes_gcm_encryption"},
	"2.1.1": {"title": "Do not allow remote login without a password", "level": 1, "attest": "no_passwordless_remote_login"},
	"2.1.2": {"title": "Configure an enable password", "level": 1, "attest": "enable_password_set"},
	"2.1.3": {"title": "Create a password complexity policy", "level": 1, "attest": "password_policy_applied"},
	"2.1.4": {"title": "Verify root login is disabled", "level": 1, "attest": "root_login_disabled"},
	"2.3.1": {"title": "Roles", "level": 1, "attest": "roles_reviewed"},
	"2.4.1": {"title": "Idle Timeout", "level": 1, "attest": "console_idle_timeout"},
	"2.4.2": {"title": "Emergency Console Access", "level": 1, "attest": "emergency_local_account"},
	"2.5.1": {"title": "Configure TACACS+/RADIUS server", "level": 1, "attest": "aaa_servers_configured"},
	"2.5.2": {"title": "Server Groups", "level": 1, "attest": "aaa_server_groups_configured"},
	"2.5.3": {"title": "Authentication, Authorization, and Accounting", "level": 1, "attest": "aaa_methods_configured"},
	"2.6.1": {"title": "Limit SSH Access Only To The Network Management Segment", "level": 1, "attest": "ssh_restricted_to_mgmt_vrf"},
	"2.6.2": {"title": "Set Idle Timeout for SSH to 10 Minutes or Less", "level": 1, "attest": "ssh_idle_timeout"},
	"2.6.3": {"title": "Remove cryptographically weak algorithms", "level": 2, "attest": "ssh_weak_algorithms_removed"},
	"2.7.1": {"title": "Limit SNMP Access To Management VRF", "level": 1, "attest": "snmp_restricted_to_mgmt_vrf"},
	"2.7.2": {"title": "Ensure SNMP Community", "level": 1, "attest": "snmp_community_hardened"},
	"2.7.3": {"title": "Use SNMPv3 Instead of Earlier Versions", "level": 1, "attest": "snmpv3_only"},
	"2.8": {"title": "Telnet access", "level": 1, "attest": "telnet_disabled"},
	"2.9": {"title": "API access using https", "level": 2, "attest": "api_https_only"},
	"2.9.1": {"title": "Login Banner", "level": 1, "attest": "login_banner_configured"},
	"3.1.1": {"title": "OSPF Interface Authentication", "level": 2, "attest": "ospf_authentication"},
	"3.1.2": {"title": "ISIS Interface and Instance Authentication", "level": 2, "attest": "isis_authentication"},
	"3.2.1": {"title": "BGP Authentication", "level": 2, "attest": "bgp_neighbor_authentication"},
	"3.2.2": {"title": "BGP TCP Authentication Option (TCP-AO)", "level": 2, "attest": "bgp_tcp_ao"},
}

section_of(id) := substring(id, 0, 1)

# ── evidence ─────────────────────────────────────────────────────────────────
eos_config_collected if is_object(input.eos_config)

attested(key) if input.eos_config.attest[key] == true

# Config contradictions: fire only when the field was collected AND shows a non-compliant setting.
veto contains {"id": "1.2", "why": "secrets are not stored with reversible aes-256-gcm encryption"} if {
	v := input.eos_config.management.security.password_encryption_reversible
	v != "aes-256-gcm"
}

veto contains {"id": "1.1.3", "why": "no control-plane service-policy is applied"} if {
	is_object(input.eos_config.control_plane)
	not copp_applied
}

copp_applied if {
	p := input.eos_config.control_plane.service_policy.input
	is_string(p)
	p != ""
}

veto contains {"id": "1.1.7", "why": "no remote syslog host is configured"} if {
	is_array(input.eos_config.logging.hosts)
	count(input.eos_config.logging.hosts) == 0
}

veto contains {"id": "2.1.1", "why": "passwordless remote login is allowed by the AAA policy"} if {
	input.eos_config.aaa.allow_nopassword_remote_login == true
}

veto contains {"id": "2.1.4", "why": "the root account is enabled"} if {
	input.eos_config.aaa.root_enabled == true
}

veto contains {"id": "2.4.1", "why": sprintf("console idle timeout is %v minutes (0 = never; must be 1-10)", [t])} if {
	t := input.eos_config.management.console.idle_timeout
	is_number(t)
	not timeout_ok(t)
}

veto contains {"id": "2.5.3", "why": "default login authentication does not use a TACACS+/RADIUS server group"} if {
	is_array(input.eos_config.aaa.authentication["default"])
	not login_uses_server_group
}

login_uses_server_group if {
	some m in input.eos_config.aaa.authentication["default"]
	is_string(m)
	startswith(m, "group")
}

veto contains {"id": "2.6.2", "why": sprintf("SSH idle timeout is %v minutes (0 = never; must be 1-10)", [t])} if {
	t := input.eos_config.management.ssh.idle_timeout
	is_number(t)
	not timeout_ok(t)
}

veto contains {"id": "2.8", "why": "telnet management is not shut down"} if {
	input.eos_config.management.telnet.shutdown == false
}

timeout_ok(t) if {
	t > 0
	t <= 10
}

# ── findings ─────────────────────────────────────────────────────────────────
findings contains {"id": "eos_config", "msg": "CIS Arista EOS: evidence missing — eos_config not collected; the device was not evaluated"} if {
	not eos_config_collected
}

findings contains {"id": id, "msg": sprintf("%s: manual review not attested — %s (attest.%s)", [id, c.title, c.attest])} if {
	some id, c in controls
	not attested(c.attest)
}

findings contains {"id": v.id, "msg": sprintf("%s: running config contradicts the control — %s", [v.id, v.why])} if {
	some v in veto
}

violations := sort([f.msg | some f in findings])

failed_controls := {f.id | some f in findings; controls[f.id]}

default compliant := false

compliant if {
	eos_config_collected
	count(findings) == 0
}

# ── reporting ────────────────────────────────────────────────────────────────
total_controls := count(controls)

section_failed(s) := {id | some id in failed_controls; section_of(id) == s}

compliance_summary := {
	"total_controls": total_controls,
	"passing_controls": total_controls - count(failed_controls),
	"failing_controls": count(failed_controls),
	"compliance_percentage": ((total_controls - count(failed_controls)) * 100) / total_controls,
	"sections": {section_keys[s]: {
		"total": count({id | some id, _ in controls; section_of(id) == s}),
		"violations": count(section_failed(s)),
	} |
		some s, _ in sections
	},
}

detailed_findings := {sprintf("%s_violations", [section_keys[s]]): sort([f.msg |
	some f in findings
	controls[f.id]
	section_of(f.id) == s
]) |
	some s, _ in sections
}

compliance_report := {
	"benchmark": "CIS Arista EOS Benchmark v1.0.0",
	"total_controls": total_controls,
	"standard_total": 33,
	"standard_total_source": "CIS Arista EOS Benchmark v1.0.0, recommendations counted from the official workbook",
	"sections": sections,
	"compliant": compliant,
	"failed_controls": sort([id | some id in failed_controls]),
	"violation_count": count(violations),
	"violations": violations,
}
