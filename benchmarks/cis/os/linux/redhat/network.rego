# METADATA
# title: "CIS Benchmark - Network Configuration"
# custom:
#   class: security
#   framework: cis_os
#   source: cis
#   domains: [linux]
#   coverage:
#     checks: 15
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.network

import rego.v1

# CIS Benchmark - Network Configuration
# Section 3: Network Configuration

# Sysctl facts arrive as numbers or strings ("0"); compare numerically.
sysctl_eq(actual, want) if to_number(actual) == want

# CIS 3.1.1 - Disable IPv6
default ipv6_disabled := false

ipv6_disabled if {
    input.ipv6_disabled == true
}

# CIS 3.1.2 - Ensure wireless interfaces are disabled
default wireless_disabled := false

wireless_disabled if {
    count(input.wireless_interfaces) == 0
}

# CIS 3.2.1 - Ensure packet redirect sending is disabled
default packet_redirect_disabled := false

packet_redirect_disabled if {
    sysctl_eq(input.net_ipv4_conf_all_send_redirects, 0)
    sysctl_eq(input.net_ipv4_conf_default_send_redirects, 0)
}

# CIS 3.2.2 - Ensure IP forwarding is disabled
default ip_forwarding_disabled := false

ip_forwarding_disabled if {
    sysctl_eq(input.net_ipv4_ip_forward, 0)
}

# CIS 3.2.3 - Ensure source routed packets are not accepted
default source_routing_disabled := false

source_routing_disabled if {
    sysctl_eq(input.net_ipv4_conf_all_accept_source_route, 0)
    sysctl_eq(input.net_ipv4_conf_default_accept_source_route, 0)
}

# CIS 3.2.4 - Ensure ICMP redirects are not accepted
default icmp_redirects_disabled := false

icmp_redirects_disabled if {
    sysctl_eq(input.net_ipv4_conf_all_accept_redirects, 0)
    sysctl_eq(input.net_ipv4_conf_default_accept_redirects, 0)
}

# CIS 3.2.5 - Ensure secure ICMP redirects are not accepted
default secure_icmp_redirects_disabled := false

secure_icmp_redirects_disabled if {
    sysctl_eq(input.net_ipv4_conf_all_secure_redirects, 0)
    sysctl_eq(input.net_ipv4_conf_default_secure_redirects, 0)
}

# CIS 3.2.6 - Ensure suspicious packets are logged
default suspicious_packets_logged := false

suspicious_packets_logged if {
    sysctl_eq(input.net_ipv4_conf_all_log_martians, 1)
    sysctl_eq(input.net_ipv4_conf_default_log_martians, 1)
}

# CIS 3.2.7 - Ensure broadcast ICMP requests are ignored
default broadcast_icmp_ignored := false

broadcast_icmp_ignored if {
    sysctl_eq(input.net_ipv4_icmp_echo_ignore_broadcasts, 1)
}

# CIS 3.2.8 - Ensure bogus ICMP responses are ignored
default bogus_icmp_ignored := false

bogus_icmp_ignored if {
    sysctl_eq(input.net_ipv4_icmp_ignore_bogus_error_responses, 1)
}

# CIS 3.2.9 - Ensure Reverse Path Filtering is enabled
default reverse_path_filtering := false

reverse_path_filtering if {
    sysctl_eq(input.net_ipv4_conf_all_rp_filter, 1)
    sysctl_eq(input.net_ipv4_conf_default_rp_filter, 1)
}

# CIS 3.2.10 - Ensure TCP SYN Cookies is enabled
default tcp_syn_cookies := false

tcp_syn_cookies if {
    sysctl_eq(input.net_ipv4_tcp_syncookies, 1)
}

# CIS 3.3.1 - Ensure source routed packets are not accepted (IPv6)
default ipv6_source_routing_disabled := false

ipv6_source_routing_disabled if {
    sysctl_eq(input.net_ipv6_conf_all_accept_source_route, 0)
    sysctl_eq(input.net_ipv6_conf_default_accept_source_route, 0)
}

# CIS 3.3.2 - Ensure ICMP redirects are not accepted (IPv6)
default ipv6_icmp_redirects_disabled := false

ipv6_icmp_redirects_disabled if {
    sysctl_eq(input.net_ipv6_conf_all_accept_redirects, 0)
    sysctl_eq(input.net_ipv6_conf_default_accept_redirects, 0)
}

# CIS 3.3.3 - Ensure IPv6 router advertisements are not accepted
default ipv6_router_advertisements_disabled := false

ipv6_router_advertisements_disabled if {
    sysctl_eq(input.net_ipv6_conf_all_accept_ra, 0)
    sysctl_eq(input.net_ipv6_conf_default_accept_ra, 0)
}

# Aggregate network compliance
default network_compliant := false

network_compliant if {
    packet_redirect_disabled
    ip_forwarding_disabled
    source_routing_disabled
    icmp_redirects_disabled
    secure_icmp_redirects_disabled
    suspicious_packets_logged
    broadcast_icmp_ignored
    bogus_icmp_ignored
    reverse_path_filtering
    tcp_syn_cookies
    wireless_disabled
    ipv6_hardened
}

# IPv6 hardening: either IPv6 is disabled outright, or its redirect, source-routing and
# router-advertisement settings are all locked down. (Whether IPv6 must be disabled,
# CIS 3.1.1, is a site decision and is reported separately via ipv6_disabled.)
default ipv6_hardened := false

ipv6_hardened if ipv6_disabled

ipv6_hardened if {
    ipv6_source_routing_disabled
    ipv6_icmp_redirects_disabled
    ipv6_router_advertisements_disabled
}

# Detailed network compliance report
network_compliance := {
    "ipv6_disabled": ipv6_disabled,
    "wireless_disabled": wireless_disabled,
    "packet_redirect_disabled": packet_redirect_disabled,
    "ip_forwarding_disabled": ip_forwarding_disabled,
    "source_routing_disabled": source_routing_disabled,
    "icmp_redirects_disabled": icmp_redirects_disabled,
    "secure_icmp_redirects_disabled": secure_icmp_redirects_disabled,
    "suspicious_packets_logged": suspicious_packets_logged,
    "broadcast_icmp_ignored": broadcast_icmp_ignored,
    "bogus_icmp_ignored": bogus_icmp_ignored,
    "reverse_path_filtering": reverse_path_filtering,
    "tcp_syn_cookies": tcp_syn_cookies,
    "ipv6_source_routing_disabled": ipv6_source_routing_disabled,
    "ipv6_icmp_redirects_disabled": ipv6_icmp_redirects_disabled,
    "ipv6_router_advertisements_disabled": ipv6_router_advertisements_disabled,
    "overall_compliant": network_compliant
}