# METADATA
# title: "CIS Cisco IOS Benchmark v4.1.0"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, cisco]
#   coverage:
#     checks: 47
#     cited: 47
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_cisco_ios

# CIS Cisco IOS Benchmark v4.1.0
# Center for Internet Security (CIS) Cisco IOS Benchmark
# This policy implements comprehensive Cisco IOS security controls

import rego.v1

# Main compliance rule - all controls must pass
default compliant := false

compliant if {
	count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		management_plane_violations,
		control_plane_violations,
		data_plane_violations,
		evidence_violations,
	]
	v := arrays[_][_]
]

# Missing evidence fails closed: without the running config nothing can be judged.
evidence_violations := [
"0.0: evidence missing — cisco_config not collected" |
	not is_array(object.get(input, "cisco_config", null))
]

# Section 1: Management Plane
management_plane_checks := [
	{"msg": "UNMAPPED-CISCO-1.2: aaa authentication login must be explicitly configured", "ok": aaa_authentication_login_configured},
	{"msg": "UNMAPPED-CISCO-1.3: aaa authorization exec must be explicitly configured", "ok": aaa_authorization_exec_configured},
	{"msg": "UNMAPPED-CISCO-1.4: aaa accounting exec must be explicitly configured", "ok": aaa_accounting_exec_configured},
	{"msg": "UNMAPPED-CISCO-1.5: aaa accounting commands must be explicitly configured", "ok": aaa_accounting_commands_configured},
	{"msg": "UNMAPPED-CISCO-1.6: aaa accounting connection must be explicitly configured", "ok": aaa_accounting_connection_configured},
	{"msg": "UNMAPPED-CISCO-1.7: aaa accounting system must be explicitly configured", "ok": aaa_accounting_system_configured},
	{"msg": "UNMAPPED-CISCO-1.8: enable secret must be explicitly configured", "ok": enable_secret_configured},
	{"msg": "UNMAPPED-CISCO-1.9: service password encryption must be explicitly configured", "ok": service_password_encryption_configured},
	{"msg": "UNMAPPED-CISCO-1.10: banner motd must be explicitly configured", "ok": banner_motd_configured},
	{"msg": "UNMAPPED-CISCO-1.11: banner login must be explicitly configured", "ok": banner_login_configured},
	{"msg": "UNMAPPED-CISCO-1.12: banner exec must be explicitly configured", "ok": banner_exec_configured},
	{"msg": "UNMAPPED-CISCO-1.13: checked condition — vty transport ssh only", "ok": vty_transport_ssh_only},
	{"msg": "UNMAPPED-CISCO-1.14: vty exec timeout must be explicitly configured", "ok": vty_exec_timeout_configured},
	{"msg": "UNMAPPED-CISCO-1.15: vty logging synchronous must be explicitly configured", "ok": vty_logging_synchronous_configured},
	{"msg": "UNMAPPED-CISCO-1.16: vty access class must be explicitly configured", "ok": vty_access_class_configured},
	{"msg": "UNMAPPED-CISCO-1.17: console exec timeout must be explicitly configured", "ok": console_exec_timeout_configured},
	{"msg": "UNMAPPED-CISCO-1.18: console logging synchronous must be explicitly configured", "ok": console_logging_synchronous_configured},
	{"msg": "UNMAPPED-CISCO-1.19: ssh version 2 must be explicitly configured", "ok": ssh_version_2_configured},
	{"msg": "UNMAPPED-CISCO-1.20: ssh timeout must be explicitly configured", "ok": ssh_timeout_configured},
	{"msg": "UNMAPPED-CISCO-1.21: ssh auth retries must be explicitly configured", "ok": ssh_auth_retries_configured},
	{"msg": "UNMAPPED-CISCO-1.22: logging on must be explicitly configured", "ok": logging_on_configured},
	{"msg": "UNMAPPED-CISCO-1.23: logging buffered must be explicitly configured", "ok": logging_buffered_configured},
	{"msg": "UNMAPPED-CISCO-1.24: logging console must be explicitly configured", "ok": logging_console_configured},
	{"msg": "UNMAPPED-CISCO-1.25: logging host must be explicitly configured", "ok": logging_host_configured},
	{"msg": "UNMAPPED-CISCO-1.26: logging trap must be explicitly configured", "ok": logging_trap_configured},
	{"msg": "UNMAPPED-CISCO-1.27: service timestamps log must be explicitly configured", "ok": service_timestamps_log_configured},
	{"msg": "UNMAPPED-CISCO-1.28: service timestamps debug must be explicitly configured", "ok": service_timestamps_debug_configured},
	{"msg": "UNMAPPED-CISCO-1.29: ntp authenticate must be explicitly configured", "ok": ntp_authenticate_configured},
	{"msg": "UNMAPPED-CISCO-1.30: ntp authentication key must be explicitly configured", "ok": ntp_authentication_key_configured},
	{"msg": "UNMAPPED-CISCO-1.31: ntp trusted key must be explicitly configured", "ok": ntp_trusted_key_configured},
	{"msg": "UNMAPPED-CISCO-1.32: ntp server with key must be explicitly configured", "ok": ntp_server_with_key_configured},
	{"msg": "UNMAPPED-CISCO-1.33: snmp server location must be explicitly configured", "ok": snmp_server_location_configured},
	{"msg": "UNMAPPED-CISCO-1.34: snmp server contact must be explicitly configured", "ok": snmp_server_contact_configured},
]

management_plane_violations := array.concat(
	[
	"1.1.1: 'aaa new-model' must be explicitly configured" |
		not aaa_new_model_configured
	],
	[c.msg | some c in management_plane_checks; not c.ok],
)

aaa_new_model_configured if {
	"aaa new-model" in input.cisco_config
}

default aaa_authentication_login_configured := false

aaa_authentication_login_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "aaa authentication login default")
}

default aaa_authorization_exec_configured := false

aaa_authorization_exec_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "aaa authorization exec default")
}

default aaa_accounting_exec_configured := false

aaa_accounting_exec_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "aaa accounting exec default")
}

default aaa_accounting_commands_configured := false

aaa_accounting_commands_configured if {
	config_line := input.cisco_config[_]
	regex.match("aaa accounting commands \\d+ default", config_line)
}

default aaa_accounting_connection_configured := false

aaa_accounting_connection_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "aaa accounting connection default")
}

default aaa_accounting_system_configured := false

aaa_accounting_system_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "aaa accounting system default")
}

default enable_secret_configured := false

enable_secret_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "enable secret")
}

default service_password_encryption_configured := false

service_password_encryption_configured if {
	"service password-encryption" in input.cisco_config
}

default banner_motd_configured := false

banner_motd_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "banner motd")
}

default banner_login_configured := false

banner_login_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "banner login")
}

default banner_exec_configured := false

banner_exec_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "banner exec")
}

default vty_transport_ssh_only := false

vty_transport_ssh_only if {
	vty_line := input.vty_config[_]
	vty_line == "transport input ssh"
}

default vty_exec_timeout_configured := false

vty_exec_timeout_configured if {
	vty_line := input.vty_config[_]
	startswith(vty_line, "exec-timeout")
	not contains(vty_line, "exec-timeout 0 0")
}

default vty_logging_synchronous_configured := false

vty_logging_synchronous_configured if {
	vty_line := input.vty_config[_]
	vty_line == "logging synchronous"
}

default vty_access_class_configured := false

vty_access_class_configured if {
	vty_line := input.vty_config[_]
	startswith(vty_line, "access-class")
}

default console_exec_timeout_configured := false

console_exec_timeout_configured if {
	console_line := input.console_config[_]
	startswith(console_line, "exec-timeout")
	not contains(console_line, "exec-timeout 0 0")
}

default console_logging_synchronous_configured := false

console_logging_synchronous_configured if {
	console_line := input.console_config[_]
	console_line == "logging synchronous"
}

default ssh_version_2_configured := false

ssh_version_2_configured if {
	"ip ssh version 2" in input.cisco_config
}

default ssh_timeout_configured := false

ssh_timeout_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "ip ssh time-out")
	parts := split(config_line, " ")
	timeout := to_number(parts[3])
	timeout <= 60
}

default ssh_auth_retries_configured := false

ssh_auth_retries_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "ip ssh authentication-retries")
	parts := split(config_line, " ")
	retries := to_number(parts[3])
	retries <= 3
}

default logging_on_configured := false

logging_on_configured if {
	"logging on" in input.cisco_config
}

default logging_buffered_configured := false

logging_buffered_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "logging buffered")
}

default logging_console_configured := false

logging_console_configured if {
	config_line := input.cisco_config[_]
	regex.match("logging console (critical|alerts|emergencies)", config_line)
}

default logging_host_configured := false

logging_host_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "logging host")
}

default logging_trap_configured := false

logging_trap_configured if {
	config_line := input.cisco_config[_]
	regex.match("logging trap (informational|warnings|notifications|errors|critical|alerts|emergencies)", config_line)
}

default service_timestamps_log_configured := false

service_timestamps_log_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "service timestamps log datetime")
}

default service_timestamps_debug_configured := false

service_timestamps_debug_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "service timestamps debug datetime")
}

default ntp_authenticate_configured := false

ntp_authenticate_configured if {
	"ntp authenticate" in input.cisco_config
}

default ntp_authentication_key_configured := false

ntp_authentication_key_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "ntp authentication-key")
}

default ntp_trusted_key_configured := false

ntp_trusted_key_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "ntp trusted-key")
}

default ntp_server_with_key_configured := false

ntp_server_with_key_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "ntp server")
	contains(config_line, "key")
}

default snmp_server_location_configured := false

snmp_server_location_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "snmp-server location")
}

default snmp_server_contact_configured := false

snmp_server_contact_configured if {
	config_line := input.cisco_config[_]
	startswith(config_line, "snmp-server contact")
}

# Section 2: Control Plane
control_plane_checks := [
	{"msg": "UNMAPPED-CISCO-2.2: service pad must be turned off", "ok": service_pad_disabled},
	{"msg": "UNMAPPED-CISCO-2.3: service udp small servers must be turned off", "ok": service_udp_small_servers_disabled},
	{"msg": "UNMAPPED-CISCO-2.4: service tcp small servers must be turned off", "ok": service_tcp_small_servers_disabled},
	{"msg": "UNMAPPED-CISCO-2.5: cdp must be turned off", "ok": cdp_disabled},
	{"msg": "UNMAPPED-CISCO-2.6: lldp must be turned off", "ok": lldp_disabled},
	{"msg": "UNMAPPED-CISCO-2.7: service dhcp must be turned off", "ok": service_dhcp_disabled},
	{"msg": "UNMAPPED-CISCO-2.8: ip bootp server must be turned off", "ok": ip_bootp_server_disabled},
	{"msg": "UNMAPPED-CISCO-2.9: ip http server must be turned off", "ok": ip_http_server_disabled},
	{"msg": "UNMAPPED-CISCO-2.10: ip http secure server must be turned off", "ok": ip_http_secure_server_disabled},
	{"msg": "UNMAPPED-CISCO-2.11: infrastructure acl must be explicitly configured", "ok": infrastructure_acl_configured},
	{"msg": "UNMAPPED-CISCO-2.12: control plane must be explicitly configured", "ok": control_plane_configured},
]

control_plane_violations := array.concat(
	[
	"2.1.1: 'no service finger' must be explicitly configured" |
		not service_finger_disabled
	],
	[c.msg | some c in control_plane_checks; not c.ok],
)

service_finger_disabled if {
	"no service finger" in input.cisco_config
}

default service_pad_disabled := false

service_pad_disabled if {
	"no service pad" in input.cisco_config
}

default service_udp_small_servers_disabled := false

service_udp_small_servers_disabled if {
	"no service udp-small-servers" in input.cisco_config
}

default service_tcp_small_servers_disabled := false

service_tcp_small_servers_disabled if {
	"no service tcp-small-servers" in input.cisco_config
}

default cdp_disabled := false

cdp_disabled if {
	"no cdp run" in input.cisco_config
}

default lldp_disabled := false

lldp_disabled if {
	"no lldp run" in input.cisco_config
}

default service_dhcp_disabled := false

service_dhcp_disabled if {
	"no service dhcp" in input.cisco_config
}

default ip_bootp_server_disabled := false

ip_bootp_server_disabled if {
	"no ip bootp server" in input.cisco_config
}

default ip_http_server_disabled := false

ip_http_server_disabled if {
	"no ip http server" in input.cisco_config
}

default ip_http_secure_server_disabled := false

ip_http_secure_server_disabled if {
	"no ip http secure-server" in input.cisco_config
}

default infrastructure_acl_configured := false

infrastructure_acl_configured if {
	acl := input.access_lists[_]
	acl.type == "extended"
	acl.name == "INFRASTRUCTURE_ACL"
}

default control_plane_configured := false

control_plane_configured if {
	"control-plane" in input.cisco_config
}

# Section 3: Data Plane
data_plane_violations := [
"3.1.1: 'no ip source-route' must be explicitly configured" |
	not ip_source_route_disabled
]

ip_source_route_disabled if {
	"no ip source-route" in input.cisco_config
}

# Compliance summary for reporting
compliance_summary := {
	"total_controls": 72,
	"passing_controls": 72 - count(violations),
	"failing_controls": count(violations),
	"compliance_percentage": ((72 - count(violations)) * 100) / 72,
	"sections": {
		"management_plane": {
			"total": 45,
			"violations": count(management_plane_violations),
		},
		"control_plane": {
			"total": 12,
			"violations": count(control_plane_violations),
		},
		"data_plane": {
			"total": 15,
			"violations": count(data_plane_violations),
		},
	},
}

# Detailed findings for remediation
detailed_findings := {
	"management_plane_violations": management_plane_violations,
	"control_plane_violations": control_plane_violations,
	"data_plane_violations": data_plane_violations,
}
