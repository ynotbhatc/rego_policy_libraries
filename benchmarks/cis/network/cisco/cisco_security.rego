# METADATA
# title: "CIS Cisco IOS Benchmark"
# custom:
#   class: security
#   framework: cis_network
#   source: cis
#   domains: [network, cisco]
#   coverage:
#     checks: 42
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.network.cisco

import rego.v1

# Every rule used as a value in the report object needs a neutral default,
# otherwise a single failing check leaves the whole report undefined.
default aaa_new_model_configured := false
default aaa_authentication_configured := false
default aaa_authorization_configured := false
default aaa_accounting_configured := false
default local_users_secret_configured := false
default local_users_not_privilege_15 := false
default enable_secret_configured := false
default enable_password_not_configured := false
default service_password_encryption := false
default banner_motd_configured := false
default banner_login_configured := false
default banner_exec_configured := false
default ip_source_route_disabled := false
default ip_proxy_arp_disabled := false
default ip_unreachables_disabled := false
default ip_mask_reply_disabled := false
default ip_redirects_disabled := false
default ip_directed_broadcast_disabled := false
default service_pad_disabled := false
default service_finger_disabled := false
default udp_small_servers_disabled := false
default tcp_small_servers_disabled := false
default cdp_disabled := false
default lldp_disabled := false
default logging_enabled := false
default logging_buffered_configured := false
default logging_console_configured := false
default logging_host_configured := false
default logging_trap_configured := false
default ntp_authenticate_configured := false
default ntp_authentication_key_configured := false
default ntp_trusted_key_configured := false
default ntp_server_configured := false
default vty_access_list_configured := false
default vty_exec_timeout_configured := false
default vty_transport_ssh_only := false
default ssh_version_2_configured := false
default ssh_timeout_configured := false
default ssh_auth_retries_configured := false
default service_config_disabled := false
default boot_network_not_configured := false
default service_timestamps_debug_configured := false
default service_timestamps_log_configured := false
default file_privilege_configured := false
default cisco_device_compliant := false

# Normalised configuration lines. cisco_config may be a list of lines or one
# multi-line string; both are handled. Matching is against whole trimmed lines,
# so "no logging console critical" can never satisfy "logging console critical".
default cfg_lines := []

cfg_lines := [trim_space(l) | some l in input.cisco_config] if is_array(input.cisco_config)

cfg_lines := [trim_space(l) | some l in split(input.cisco_config, "\n")] if is_string(input.cisco_config)

# CIS Cisco IOS Benchmark
# Network Device Security Configuration

# CIS 1.1.1 - 'aaa new-model' must be explicitly configured
aaa_new_model_configured if {
    "aaa new-model" in cfg_lines
}

# CIS 1.1.2 - 'aaa authentication login default group' must be explicitly configured
aaa_authentication_configured if {
    some line in cfg_lines
    startswith(line, "aaa authentication login default group")
}

# CIS 1.1.3 - 'aaa authorization exec default group' must be explicitly configured
aaa_authorization_configured if {
    some line in cfg_lines
    startswith(line, "aaa authorization exec default group")
}

# CIS 1.1.4 - 'aaa accounting exec default start-stop group' must be explicitly configured
aaa_accounting_configured if {
    some line in cfg_lines
    startswith(line, "aaa accounting exec default start-stop group")
}

# CIS 1.2.1 - 'username secret' must be explicitly configured for all local users
local_users_secret_configured if {
    every user in input.local_users {
        startswith(user.config, "username")
        contains(user.config, "secret")
    }
}

# CIS 1.2.2 - 'username privilege 15' must be left unconfigured for local users
local_users_not_privilege_15 if {
    count([
        user | user := input.local_users[_]; 
        contains(user.config, "privilege 15")
    ]) == 0
}

# CIS 1.3.1 - 'enable secret' must be explicitly configured
enable_secret_configured if {
    some line in cfg_lines
    startswith(line, "enable secret")
}

# CIS 1.3.2 - 'enable password' must be left unconfigured
enable_password_not_configured if {
    count([
        line | line := cfg_lines[_]; 
        startswith(line, "enable password")
    ]) == 0
}

# CIS 1.3.3 - 'service password-encryption' must be explicitly configured
service_password_encryption if {
    "service password-encryption" in cfg_lines
}

# CIS 1.4.1 - 'banner motd' must be explicitly configured
banner_motd_configured if {
    some line in cfg_lines
    startswith(line, "banner motd")
}

# CIS 1.4.2 - 'banner login' must be explicitly configured
banner_login_configured if {
    some line in cfg_lines
    startswith(line, "banner login")
}

# CIS 1.4.3 - 'banner exec' must be explicitly configured
banner_exec_configured if {
    some line in cfg_lines
    startswith(line, "banner exec")
}

# CIS 2.1.1 - 'no ip source-route' must be explicitly configured
ip_source_route_disabled if {
    "no ip source-route" in cfg_lines
}

# CIS 2.1.2 - 'no ip proxy-arp' must be explicitly configured on all interfaces
ip_proxy_arp_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip proxy-arp")
    }
}

# CIS 2.1.3 - 'no ip unreachables' must be explicitly configured on all interfaces
ip_unreachables_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip unreachables")
    }
}

# CIS 2.1.4 - 'no ip mask-reply' must be explicitly configured on all interfaces
ip_mask_reply_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip mask-reply")
    }
}

# CIS 2.1.5 - 'no ip redirects' must be explicitly configured on all interfaces
ip_redirects_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip redirects")
    }
}

# CIS 2.1.6 - 'no ip directed-broadcast' must be explicitly configured on all interfaces
ip_directed_broadcast_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip directed-broadcast")
    }
}

# CIS 2.2.1 - 'no service pad' must be explicitly configured
service_pad_disabled if {
    "no service pad" in cfg_lines
}

# CIS 2.2.2 - 'no service finger' must be explicitly configured
service_finger_disabled if {
    "no service finger" in cfg_lines
}

# CIS 2.2.3 - 'no service udp-small-servers' must be explicitly configured
udp_small_servers_disabled if {
    "no service udp-small-servers" in cfg_lines
}

# CIS 2.2.4 - 'no service tcp-small-servers' must be explicitly configured
tcp_small_servers_disabled if {
    "no service tcp-small-servers" in cfg_lines
}

# CIS 2.2.5 - 'no cdp run' must be explicitly configured if CDP is not required
cdp_disabled if {
    "no cdp run" in cfg_lines
}

# CIS 2.2.6 - 'no lldp run' must be explicitly configured if LLDP is not required
lldp_disabled if {
    "no lldp run" in cfg_lines
}

# CIS 2.3.1 - 'logging on' must be explicitly configured
logging_enabled if {
    "logging on" in cfg_lines
}

# CIS 2.3.2 - 'logging buffered' must be explicitly configured with appropriate size
logging_buffered_configured if {
    some line in cfg_lines
    startswith(line, "logging buffered")
}

# CIS 2.3.3 - 'logging console critical' must be explicitly configured
logging_console_configured if {
    some line in cfg_lines
    regex.match(`^logging console (critical|alerts|emergencies)\b`, line)
}

# CIS 2.3.4 - 'logging host' must be explicitly configured
logging_host_configured if {
    some line in cfg_lines
    startswith(line, "logging host")
}

# CIS 2.3.5 - 'logging trap informational' must be explicitly configured
logging_trap_configured if {
    some line in cfg_lines
    regex.match(`^logging trap (informational|warnings|notifications|errors|critical|alerts|emergencies)\b`, line)
}

# CIS 2.4.1 - 'ntp authenticate' must be explicitly configured
ntp_authenticate_configured if {
    "ntp authenticate" in cfg_lines
}

# CIS 2.4.2 - 'ntp authentication-key' must be explicitly configured
ntp_authentication_key_configured if {
    some line in cfg_lines
    startswith(line, "ntp authentication-key")
}

# CIS 2.4.3 - 'ntp trusted-key' must be explicitly configured
ntp_trusted_key_configured if {
    some line in cfg_lines
    startswith(line, "ntp trusted-key")
}

# CIS 2.4.4 - 'ntp server' must be explicitly configured
ntp_server_configured if {
    some line in cfg_lines
    startswith(line, "ntp server")
}

# CIS 2.5.1 - 'access-list' must be explicitly configured for vty lines
vty_access_list_configured if {
    some line in cfg_lines
    startswith(line, "line vty")
    # Check if there's an access-class configured for vty
    some vty_line in input.vty_config
    startswith(vty_line, "access-class")
}

# CIS 2.5.2 - 'exec-timeout' must be explicitly configured for vty lines
vty_exec_timeout_configured if {
    some vty_line in input.vty_config
    startswith(vty_line, "exec-timeout")
    not contains(vty_line, "exec-timeout 0 0")
}

# CIS 2.5.3 - 'transport input ssh' must be explicitly configured for vty lines
vty_transport_ssh_only if {
    some vty_line in input.vty_config
    vty_line == "transport input ssh"
}

# CIS 2.6.1 - 'ip ssh version 2' must be explicitly configured
ssh_version_2_configured if {
    "ip ssh version 2" in cfg_lines
}

# CIS 2.6.2 - 'ip ssh time-out' must be explicitly configured to 60 seconds or less
ssh_timeout_configured if {
    some line in cfg_lines
    startswith(line, "ip ssh time-out")
    timeout_parts := split(line, " ")
    timeout_value := to_number(timeout_parts[3])
    timeout_value <= 60
}

# CIS 2.6.3 - 'ip ssh authentication-retries' must be explicitly configured to 3 or less
ssh_auth_retries_configured if {
    some line in cfg_lines
    startswith(line, "ip ssh authentication-retries")
    retry_parts := split(line, " ")
    retry_value := to_number(retry_parts[3])
    retry_value <= 3
}

# CIS 3.1.1 - 'no service config' must be explicitly configured
service_config_disabled if {
    "no service config" in cfg_lines
}

# CIS 3.1.2 - 'boot network' must be left unconfigured
boot_network_not_configured if {
    count([
        line | line := cfg_lines[_]; 
        startswith(line, "boot network")
    ]) == 0
}

# CIS 3.2.1 - 'service timestamps debug datetime' must be explicitly configured
service_timestamps_debug_configured if {
    some line in cfg_lines
    regex.match(`^service timestamps debug datetime\b`, line)
}

# CIS 3.2.2 - 'service timestamps log datetime' must be explicitly configured
service_timestamps_log_configured if {
    some line in cfg_lines
    regex.match(`^service timestamps log datetime\b`, line)
}

# CIS 3.3.1 - 'file privilege' must be explicitly configured
file_privilege_configured if {
    some line in cfg_lines
    startswith(line, "file privilege")
}

# Aggregate Cisco device compliance
cisco_device_compliant if {
    aaa_new_model_configured
    aaa_authentication_configured
    aaa_authorization_configured
    aaa_accounting_configured
    local_users_secret_configured
    local_users_not_privilege_15
    enable_secret_configured
    enable_password_not_configured
    service_password_encryption
    banner_motd_configured
    banner_login_configured
    banner_exec_configured
    ip_source_route_disabled
    ip_proxy_arp_disabled
    ip_unreachables_disabled
    ip_mask_reply_disabled
    ip_redirects_disabled
    ip_directed_broadcast_disabled
    service_pad_disabled
    service_finger_disabled
    udp_small_servers_disabled
    tcp_small_servers_disabled
    cdp_disabled
    lldp_disabled
    logging_enabled
    logging_buffered_configured
    logging_console_configured
    logging_host_configured
    logging_trap_configured
    ntp_authenticate_configured
    ntp_authentication_key_configured
    ntp_trusted_key_configured
    ntp_server_configured
    vty_access_list_configured
    vty_exec_timeout_configured
    vty_transport_ssh_only
    ssh_version_2_configured
    ssh_timeout_configured
    ssh_auth_retries_configured
    service_config_disabled
    boot_network_not_configured
    service_timestamps_debug_configured
    service_timestamps_log_configured
    file_privilege_configured
}

# Detailed Cisco device compliance report
cisco_device_compliance := {
    "aaa_new_model_configured": aaa_new_model_configured,
    "aaa_authentication_configured": aaa_authentication_configured,
    "aaa_authorization_configured": aaa_authorization_configured,
    "aaa_accounting_configured": aaa_accounting_configured,
    "local_users_secret_configured": local_users_secret_configured,
    "local_users_not_privilege_15": local_users_not_privilege_15,
    "enable_secret_configured": enable_secret_configured,
    "enable_password_not_configured": enable_password_not_configured,
    "service_password_encryption": service_password_encryption,
    "banner_motd_configured": banner_motd_configured,
    "banner_login_configured": banner_login_configured,
    "banner_exec_configured": banner_exec_configured,
    "ip_source_route_disabled": ip_source_route_disabled,
    "ip_proxy_arp_disabled": ip_proxy_arp_disabled,
    "ip_unreachables_disabled": ip_unreachables_disabled,
    "ip_mask_reply_disabled": ip_mask_reply_disabled,
    "ip_redirects_disabled": ip_redirects_disabled,
    "ip_directed_broadcast_disabled": ip_directed_broadcast_disabled,
    "service_pad_disabled": service_pad_disabled,
    "service_finger_disabled": service_finger_disabled,
    "udp_small_servers_disabled": udp_small_servers_disabled,
    "tcp_small_servers_disabled": tcp_small_servers_disabled,
    "cdp_disabled": cdp_disabled,
    "lldp_disabled": lldp_disabled,
    "logging_enabled": logging_enabled,
    "logging_buffered_configured": logging_buffered_configured,
    "logging_console_configured": logging_console_configured,
    "logging_host_configured": logging_host_configured,
    "logging_trap_configured": logging_trap_configured,
    "ntp_authenticate_configured": ntp_authenticate_configured,
    "ntp_authentication_key_configured": ntp_authentication_key_configured,
    "ntp_trusted_key_configured": ntp_trusted_key_configured,
    "ntp_server_configured": ntp_server_configured,
    "vty_access_list_configured": vty_access_list_configured,
    "vty_exec_timeout_configured": vty_exec_timeout_configured,
    "vty_transport_ssh_only": vty_transport_ssh_only,
    "ssh_version_2_configured": ssh_version_2_configured,
    "ssh_timeout_configured": ssh_timeout_configured,
    "ssh_auth_retries_configured": ssh_auth_retries_configured,
    "service_config_disabled": service_config_disabled,
    "boot_network_not_configured": boot_network_not_configured,
    "service_timestamps_debug_configured": service_timestamps_debug_configured,
    "service_timestamps_log_configured": service_timestamps_log_configured,
    "file_privilege_configured": file_privilege_configured,
    "overall_compliant": cisco_device_compliant
}