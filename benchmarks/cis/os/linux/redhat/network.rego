package cis.network

import rego.v1

# CIS Benchmark - Network Configuration
# Section 3: Network Configuration

# CIS 3.1.1 - Disable IPv6
ipv6_disabled if {
    input.ipv6_disabled == true
}

# CIS 3.1.2 - Ensure wireless interfaces are disabled
wireless_disabled if {
    count(input.wireless_interfaces) == 0
}

# CIS 3.2.1 - Ensure packet redirect sending is disabled
packet_redirect_disabled if {
    input.net_ipv4_conf_all_send_redirects == 0
    input.net_ipv4_conf_default_send_redirects == 0
}

# CIS 3.2.2 - Ensure IP forwarding is disabled
ip_forwarding_disabled if {
    input.net_ipv4_ip_forward == 0
}

# CIS 3.2.3 - Ensure source routed packets are not accepted
source_routing_disabled if {
    input.net_ipv4_conf_all_accept_source_route == 0
    input.net_ipv4_conf_default_accept_source_route == 0
}

# CIS 3.2.4 - Ensure ICMP redirects are not accepted
icmp_redirects_disabled if {
    input.net_ipv4_conf_all_accept_redirects == 0
    input.net_ipv4_conf_default_accept_redirects == 0
}

# CIS 3.2.5 - Ensure secure ICMP redirects are not accepted
secure_icmp_redirects_disabled if {
    input.net_ipv4_conf_all_secure_redirects == 0
    input.net_ipv4_conf_default_secure_redirects == 0
}

# CIS 3.2.6 - Ensure suspicious packets are logged
suspicious_packets_logged if {
    input.net_ipv4_conf_all_log_martians == 1
    input.net_ipv4_conf_default_log_martians == 1
}

# CIS 3.2.7 - Ensure broadcast ICMP requests are ignored
broadcast_icmp_ignored if {
    input.net_ipv4_icmp_echo_ignore_broadcasts == 1
}

# CIS 3.2.8 - Ensure bogus ICMP responses are ignored
bogus_icmp_ignored if {
    input.net_ipv4_icmp_ignore_bogus_error_responses == 1
}

# CIS 3.2.9 - Ensure Reverse Path Filtering is enabled
reverse_path_filtering if {
    input.net_ipv4_conf_all_rp_filter == 1
    input.net_ipv4_conf_default_rp_filter == 1
}

# CIS 3.2.10 - Ensure TCP SYN Cookies is enabled
tcp_syn_cookies if {
    input.net_ipv4_tcp_syncookies == 1
}

# CIS 3.3.1 - Ensure source routed packets are not accepted (IPv6)
ipv6_source_routing_disabled if {
    input.net_ipv6_conf_all_accept_source_route == 0
    input.net_ipv6_conf_default_accept_source_route == 0
}

# CIS 3.3.2 - Ensure ICMP redirects are not accepted (IPv6)
ipv6_icmp_redirects_disabled if {
    input.net_ipv6_conf_all_accept_redirects == 0
    input.net_ipv6_conf_default_accept_redirects == 0
}

# CIS 3.3.3 - Ensure IPv6 router advertisements are not accepted
ipv6_router_advertisements_disabled if {
    input.net_ipv6_conf_all_accept_ra == 0
    input.net_ipv6_conf_default_accept_ra == 0
}

# Aggregate network compliance
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