package cis.network.cisco

import rego.v1

# CIS Cisco IOS Benchmark
# Network Device Security Configuration

# CIS 1.1.1 - Ensure 'aaa new-model' is configured
aaa_new_model_configured if {
    contains(input.cisco_config, "aaa new-model")
}

# CIS 1.1.2 - Ensure 'aaa authentication login default group' is configured
aaa_authentication_configured if {
    some line in input.cisco_config
    startswith(line, "aaa authentication login default group")
}

# CIS 1.1.3 - Ensure 'aaa authorization exec default group' is configured
aaa_authorization_configured if {
    some line in input.cisco_config
    startswith(line, "aaa authorization exec default group")
}

# CIS 1.1.4 - Ensure 'aaa accounting exec default start-stop group' is configured
aaa_accounting_configured if {
    some line in input.cisco_config
    startswith(line, "aaa accounting exec default start-stop group")
}

# CIS 1.2.1 - Ensure 'username secret' is configured for all local users
local_users_secret_configured if {
    every user in input.local_users {
        startswith(user.config, "username")
        contains(user.config, "secret")
    }
}

# CIS 1.2.2 - Ensure 'username privilege 15' is not configured for local users
local_users_not_privilege_15 if {
    count([
        user | user := input.local_users[_]; 
        contains(user.config, "privilege 15")
    ]) == 0
}

# CIS 1.3.1 - Ensure 'enable secret' is configured
enable_secret_configured if {
    some line in input.cisco_config
    startswith(line, "enable secret")
}

# CIS 1.3.2 - Ensure 'enable password' is not configured
enable_password_not_configured if {
    count([
        line | line := input.cisco_config[_]; 
        startswith(line, "enable password")
    ]) == 0
}

# CIS 1.3.3 - Ensure 'service password-encryption' is configured
service_password_encryption if {
    contains(input.cisco_config, "service password-encryption")
}

# CIS 1.4.1 - Ensure 'banner motd' is configured
banner_motd_configured if {
    some line in input.cisco_config
    startswith(line, "banner motd")
}

# CIS 1.4.2 - Ensure 'banner login' is configured  
banner_login_configured if {
    some line in input.cisco_config
    startswith(line, "banner login")
}

# CIS 1.4.3 - Ensure 'banner exec' is configured
banner_exec_configured if {
    some line in input.cisco_config
    startswith(line, "banner exec")
}

# CIS 2.1.1 - Ensure 'no ip source-route' is configured
ip_source_route_disabled if {
    contains(input.cisco_config, "no ip source-route")
}

# CIS 2.1.2 - Ensure 'no ip proxy-arp' is configured on all interfaces
ip_proxy_arp_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip proxy-arp")
    }
}

# CIS 2.1.3 - Ensure 'no ip unreachables' is configured on all interfaces
ip_unreachables_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip unreachables")
    }
}

# CIS 2.1.4 - Ensure 'no ip mask-reply' is configured on all interfaces
ip_mask_reply_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip mask-reply")
    }
}

# CIS 2.1.5 - Ensure 'no ip redirects' is configured on all interfaces
ip_redirects_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip redirects")
    }
}

# CIS 2.1.6 - Ensure 'no ip directed-broadcast' is configured on all interfaces
ip_directed_broadcast_disabled if {
    every interface in input.interfaces {
        contains(interface.config, "no ip directed-broadcast")
    }
}

# CIS 2.2.1 - Ensure 'no service pad' is configured
service_pad_disabled if {
    contains(input.cisco_config, "no service pad")
}

# CIS 2.2.2 - Ensure 'no service finger' is configured
service_finger_disabled if {
    contains(input.cisco_config, "no service finger")
}

# CIS 2.2.3 - Ensure 'no service udp-small-servers' is configured
udp_small_servers_disabled if {
    contains(input.cisco_config, "no service udp-small-servers")
}

# CIS 2.2.4 - Ensure 'no service tcp-small-servers' is configured
tcp_small_servers_disabled if {
    contains(input.cisco_config, "no service tcp-small-servers")
}

# CIS 2.2.5 - Ensure 'no cdp run' is configured if CDP is not required
cdp_disabled if {
    contains(input.cisco_config, "no cdp run")
}

# CIS 2.2.6 - Ensure 'no lldp run' is configured if LLDP is not required
lldp_disabled if {
    contains(input.cisco_config, "no lldp run")
}

# CIS 2.3.1 - Ensure 'logging on' is configured
logging_enabled if {
    contains(input.cisco_config, "logging on")
}

# CIS 2.3.2 - Ensure 'logging buffered' is configured with appropriate size
logging_buffered_configured if {
    some line in input.cisco_config
    startswith(line, "logging buffered")
}

# CIS 2.3.3 - Ensure 'logging console critical' is configured
logging_console_configured if {
    some line in input.cisco_config
    regex.match("logging console (critical|alerts|emergencies)", line)
}

# CIS 2.3.4 - Ensure 'logging host' is configured
logging_host_configured if {
    some line in input.cisco_config
    startswith(line, "logging host")
}

# CIS 2.3.5 - Ensure 'logging trap informational' is configured
logging_trap_configured if {
    some line in input.cisco_config
    regex.match("logging trap (informational|warnings|notifications|errors|critical|alerts|emergencies)", line)
}

# CIS 2.4.1 - Ensure 'ntp authenticate' is configured
ntp_authenticate_configured if {
    contains(input.cisco_config, "ntp authenticate")
}

# CIS 2.4.2 - Ensure 'ntp authentication-key' is configured
ntp_authentication_key_configured if {
    some line in input.cisco_config
    startswith(line, "ntp authentication-key")
}

# CIS 2.4.3 - Ensure 'ntp trusted-key' is configured
ntp_trusted_key_configured if {
    some line in input.cisco_config
    startswith(line, "ntp trusted-key")
}

# CIS 2.4.4 - Ensure 'ntp server' is configured
ntp_server_configured if {
    some line in input.cisco_config
    startswith(line, "ntp server")
}

# CIS 2.5.1 - Ensure 'access-list' is configured for vty lines
vty_access_list_configured if {
    some line in input.cisco_config
    startswith(line, "line vty")
    # Check if there's an access-class configured for vty
    some vty_line in input.vty_config
    startswith(vty_line, "access-class")
}

# CIS 2.5.2 - Ensure 'exec-timeout' is configured for vty lines
vty_exec_timeout_configured if {
    some vty_line in input.vty_config
    startswith(vty_line, "exec-timeout")
    not contains(vty_line, "exec-timeout 0 0")
}

# CIS 2.5.3 - Ensure 'transport input ssh' is configured for vty lines
vty_transport_ssh_only if {
    some vty_line in input.vty_config
    vty_line == "transport input ssh"
}

# CIS 2.6.1 - Ensure 'ip ssh version 2' is configured
ssh_version_2_configured if {
    contains(input.cisco_config, "ip ssh version 2")
}

# CIS 2.6.2 - Ensure 'ip ssh time-out' is configured to 60 seconds or less
ssh_timeout_configured if {
    some line in input.cisco_config
    startswith(line, "ip ssh time-out")
    timeout_parts := split(line, " ")
    timeout_value := to_number(timeout_parts[3])
    timeout_value <= 60
}

# CIS 2.6.3 - Ensure 'ip ssh authentication-retries' is configured to 3 or less
ssh_auth_retries_configured if {
    some line in input.cisco_config
    startswith(line, "ip ssh authentication-retries")
    retry_parts := split(line, " ")
    retry_value := to_number(retry_parts[3])
    retry_value <= 3
}

# CIS 3.1.1 - Ensure 'no service config' is configured
service_config_disabled if {
    contains(input.cisco_config, "no service config")
}

# CIS 3.1.2 - Ensure 'boot network' is not configured
boot_network_not_configured if {
    count([
        line | line := input.cisco_config[_]; 
        startswith(line, "boot network")
    ]) == 0
}

# CIS 3.2.1 - Ensure 'service timestamps debug datetime' is configured
service_timestamps_debug_configured if {
    some line in input.cisco_config
    regex.match("service timestamps debug datetime.*", line)
}

# CIS 3.2.2 - Ensure 'service timestamps log datetime' is configured
service_timestamps_log_configured if {
    some line in input.cisco_config
    regex.match("service timestamps log datetime.*", line)
}

# CIS 3.3.1 - Ensure 'file privilege' is configured
file_privilege_configured if {
    some line in input.cisco_config
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