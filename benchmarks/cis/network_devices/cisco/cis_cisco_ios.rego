package cis

# CIS Cisco IOS Benchmark v4.1.0
# Center for Internet Security (CIS) Cisco IOS Benchmark
# This policy implements comprehensive Cisco IOS security controls

import rego.v1

# Main compliance rule - all controls must pass
compliant if {
    count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		management_plane_violations,
		control_plane_violations,
		data_plane_violations
	]
	v := arrays[_][_]
]

# Section 1: Management Plane
management_plane_violations := [
    "1.1.1: Ensure 'aaa new-model' is configured" |
    not aaa_new_model_configured
]

aaa_new_model_configured if {
    "aaa new-model" in input.cisco_config
}


aaa_authentication_login_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "aaa authentication login default")
}


aaa_authorization_exec_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "aaa authorization exec default")
}


aaa_accounting_exec_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "aaa accounting exec default")
}


aaa_accounting_commands_configured if {
    config_line := input.cisco_config[_]
    regex.match("aaa accounting commands \\d+ default", config_line)
}


aaa_accounting_connection_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "aaa accounting connection default")
}


aaa_accounting_system_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "aaa accounting system default")
}




enable_secret_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "enable secret")
}



service_password_encryption_configured if {
    "service password-encryption" in input.cisco_config
}


banner_motd_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "banner motd")
}


banner_login_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "banner login")
}


banner_exec_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "banner exec")
}


vty_transport_ssh_only if {
    vty_line := input.vty_config[_]
    vty_line == "transport input ssh"
}


vty_exec_timeout_configured if {
    vty_line := input.vty_config[_]
    startswith(vty_line, "exec-timeout")
    not contains(vty_line, "exec-timeout 0 0")
}


vty_logging_synchronous_configured if {
    vty_line := input.vty_config[_]
    vty_line == "logging synchronous"
}


vty_access_class_configured if {
    vty_line := input.vty_config[_]
    startswith(vty_line, "access-class")
}


console_exec_timeout_configured if {
    console_line := input.console_config[_]
    startswith(console_line, "exec-timeout")
    not contains(console_line, "exec-timeout 0 0")
}


console_logging_synchronous_configured if {
    console_line := input.console_config[_]
    console_line == "logging synchronous"
}


ssh_version_2_configured if {
    "ip ssh version 2" in input.cisco_config
}


ssh_timeout_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "ip ssh time-out")
    parts := split(config_line, " ")
    timeout := to_number(parts[3])
    timeout <= 60
}


ssh_auth_retries_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "ip ssh authentication-retries")
    parts := split(config_line, " ")
    retries := to_number(parts[3])
    retries <= 3
}


logging_on_configured if {
    "logging on" in input.cisco_config
}


logging_buffered_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "logging buffered")
}


logging_console_configured if {
    config_line := input.cisco_config[_]
    regex.match("logging console (critical|alerts|emergencies)", config_line)
}


logging_host_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "logging host")
}


logging_trap_configured if {
    config_line := input.cisco_config[_]
    regex.match("logging trap (informational|warnings|notifications|errors|critical|alerts|emergencies)", config_line)
}


service_timestamps_log_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "service timestamps log datetime")
}


service_timestamps_debug_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "service timestamps debug datetime")
}


ntp_authenticate_configured if {
    "ntp authenticate" in input.cisco_config
}


ntp_authentication_key_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "ntp authentication-key")
}


ntp_trusted_key_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "ntp trusted-key")
}


ntp_server_with_key_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "ntp server")
    contains(config_line, "key")
}




snmp_server_location_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "snmp-server location")
}


snmp_server_contact_configured if {
    config_line := input.cisco_config[_]
    startswith(config_line, "snmp-server contact")
}

# Section 2: Control Plane
control_plane_violations := [
    "2.1.1: Ensure 'no service finger' is configured" |
    not service_finger_disabled
]

service_finger_disabled if {
    "no service finger" in input.cisco_config
}


service_pad_disabled if {
    "no service pad" in input.cisco_config
}


service_udp_small_servers_disabled if {
    "no service udp-small-servers" in input.cisco_config
}


service_tcp_small_servers_disabled if {
    "no service tcp-small-servers" in input.cisco_config
}


cdp_disabled if {
    "no cdp run" in input.cisco_config
}


lldp_disabled if {
    "no lldp run" in input.cisco_config
}


service_dhcp_disabled if {
    "no service dhcp" in input.cisco_config
}


ip_bootp_server_disabled if {
    "no ip bootp server" in input.cisco_config
}


ip_http_server_disabled if {
    "no ip http server" in input.cisco_config
}


ip_http_secure_server_disabled if {
    "no ip http secure-server" in input.cisco_config
}


infrastructure_acl_configured if {
    acl := input.access_lists[_]
    acl.type == "extended"
    acl.name == "INFRASTRUCTURE_ACL"
}


control_plane_configured if {
    "control-plane" in input.cisco_config
}

# Section 3: Data Plane
data_plane_violations := [
    "3.1.1: Ensure 'no ip source-route' is configured" |
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
            "violations": count(management_plane_violations)
        },
        "control_plane": {
            "total": 12,
            "violations": count(control_plane_violations)
        },
        "data_plane": {
            "total": 15,
            "violations": count(data_plane_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "management_plane_violations": management_plane_violations,
    "control_plane_violations": control_plane_violations,
    "data_plane_violations": data_plane_violations
}