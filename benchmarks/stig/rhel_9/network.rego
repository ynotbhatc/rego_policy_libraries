package stig.rhel_9.network

# DISA STIG for RHEL 9 - Network Configuration Module
# STIG Version: V2R2 | Released: October 2024
# Covers: Firewall, network parameters, IPv6, ICMP redirects

import rego.v1

default compliant := false

# =============================================================================
# CAT I - HIGH SEVERITY
# =============================================================================

# RHEL-09-251010 | V-258100 | CAT I
# Firewall must be active
default firewall_active := false

firewall_active if {
	input.firewall.active == true
}

firewall_active if {
	input.services.firewalld == "active"
}

firewall_active if {
	input.services.nftables == "active"
}

status_rhel_09_251010 := "Not_a_Finding" if { firewall_active } else := "Open"

finding_rhel_09_251010 := {
	"vuln_id": "V-258100",
	"stig_id": "RHEL-09-251010",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must have the firewall package installed",
	"status": status_rhel_09_251010,
	"fix_text": "Enable firewalld: systemctl enable --now firewalld",
}

# RHEL-09-251015 | V-258101 | CAT I
# IP forwarding must be disabled
default ip_forwarding_disabled := false

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
	input.network_config.ipv4_forwarding == false
}

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
}

status_rhel_09_251015 := "Not_a_Finding" if { ip_forwarding_disabled } else := "Open"

finding_rhel_09_251015 := {
	"vuln_id": "V-258101",
	"stig_id": "RHEL-09-251015",
	"severity": "CAT I",
	"rule_title": "RHEL 9 must not enable IPv4 packet forwarding unless the system is a router",
	"status": status_rhel_09_251015,
	"fix_text": "Disable IP forwarding: Set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-stig.conf",
}

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# RHEL-09-251020 | V-258102 | CAT II
# ICMP redirects must not be accepted (IPv4)
default icmp_redirect_accept_disabled := false

icmp_redirect_accept_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_redirects"] == "0"
}

status_rhel_09_251020 := "Not_a_Finding" if { icmp_redirect_accept_disabled } else := "Open"

finding_rhel_09_251020 := {
	"vuln_id": "V-258102",
	"stig_id": "RHEL-09-251020",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not accept ICMP redirects on any interface",
	"status": status_rhel_09_251020,
	"fix_text": "Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-251025 | V-258103 | CAT II
# ICMP redirects must not be sent
default icmp_redirect_send_disabled := false

icmp_redirect_send_disabled if {
	input.kernel_params["net.ipv4.conf.all.send_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.send_redirects"] == "0"
}

status_rhel_09_251025 := "Not_a_Finding" if { icmp_redirect_send_disabled } else := "Open"

finding_rhel_09_251025 := {
	"vuln_id": "V-258103",
	"stig_id": "RHEL-09-251025",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not send ICMP redirects on any interface",
	"status": status_rhel_09_251025,
	"fix_text": "Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-251030 | V-258104 | CAT II
# Source routing must be disabled
default source_routing_disabled := false

source_routing_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_source_route"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_source_route"] == "0"
}

status_rhel_09_251030 := "Not_a_Finding" if { source_routing_disabled } else := "Open"

finding_rhel_09_251030 := {
	"vuln_id": "V-258104",
	"stig_id": "RHEL-09-251030",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not forward IPv4 source-routed packets",
	"status": status_rhel_09_251030,
	"fix_text": "Set net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-251035 | V-258105 | CAT II
# Bogus ICMP responses must be ignored
default icmp_bogus_error_responses := false

icmp_bogus_error_responses if {
	input.kernel_params["net.ipv4.icmp_ignore_bogus_error_responses"] == "1"
}

status_rhel_09_251035 := "Not_a_Finding" if { icmp_bogus_error_responses } else := "Open"

finding_rhel_09_251035 := {
	"vuln_id": "V-258105",
	"stig_id": "RHEL-09-251035",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must ignore bogus ICMP errors",
	"status": status_rhel_09_251035,
	"fix_text": "Set net.ipv4.icmp_ignore_bogus_error_responses=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-251040 | V-258106 | CAT II
# IPv4 TCP syncookies must be enabled
default tcp_syncookies_enabled := false

tcp_syncookies_enabled if {
	input.kernel_params["net.ipv4.tcp_syncookies"] == "1"
}

status_rhel_09_251040 := "Not_a_Finding" if { tcp_syncookies_enabled } else := "Open"

finding_rhel_09_251040 := {
	"vuln_id": "V-258106",
	"stig_id": "RHEL-09-251040",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must use a reverse-path filter for IPv4 network traffic when possible",
	"status": status_rhel_09_251040,
	"fix_text": "Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-251045 | V-258107 | CAT II
# Reverse path filter must be enabled
default rp_filter_enabled := false

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "1"
}

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "2"
}

status_rhel_09_251045 := "Not_a_Finding" if { rp_filter_enabled } else := "Open"

finding_rhel_09_251045 := {
	"vuln_id": "V-258107",
	"stig_id": "RHEL-09-251045",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must enable the use of reverse path filtering",
	"status": status_rhel_09_251045,
	"fix_text": "Set net.ipv4.conf.all.rp_filter=1 in /etc/sysctl.d/99-stig.conf",
}

# RHEL-09-251050 | V-258108 | CAT II
# IPv6 must be disabled unless required
default ipv6_disabled_or_configured := false

ipv6_disabled_or_configured if {
	input.network_config.ipv6_disabled == true
}

ipv6_disabled_or_configured if {
	input.kernel_params["net.ipv6.conf.all.disable_ipv6"] == "1"
}

ipv6_disabled_or_configured if {
	# IPv6 enabled but properly configured
	input.network_config.ipv6_required == true
	input.kernel_params["net.ipv6.conf.all.accept_redirects"] == "0"
	input.kernel_params["net.ipv6.conf.all.accept_source_route"] == "0"
}

status_rhel_09_251050 := "Not_a_Finding" if { ipv6_disabled_or_configured } else := "Open"

finding_rhel_09_251050 := {
	"vuln_id": "V-258108",
	"stig_id": "RHEL-09-251050",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must not accept IPv6 ICMP redirect messages",
	"status": status_rhel_09_251050,
	"fix_text": "Disable IPv6 or configure: Set net.ipv6.conf.all.disable_ipv6=1",
}

# RHEL-09-251055 | V-258109 | CAT II
# Wireless interfaces must be disabled unless mission requires
default wireless_disabled := false

wireless_disabled if {
	input.network_config.wireless_disabled == true
}

wireless_disabled if {
	count(input.wireless_interfaces) == 0
}

wireless_disabled if {
	not input.wireless_interfaces
}

status_rhel_09_251055 := "Not_a_Finding" if { wireless_disabled } else := "Open"

finding_rhel_09_251055 := {
	"vuln_id": "V-258109",
	"stig_id": "RHEL-09-251055",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable wireless network adapters unless mission requires",
	"status": status_rhel_09_251055,
	"fix_text": "Disable wireless: nmcli radio wifi off or disable in NetworkManager",
}

# RHEL-09-251060 | V-258110 | CAT II
# Bluetooth kernel module must be disabled
default bluetooth_module_disabled := false

bluetooth_module_disabled if {
	input.kernel_modules["bluetooth"].blacklisted == true
}

bluetooth_module_disabled if {
	input.kernel_modules["bluetooth"].status == "disabled"
}

status_rhel_09_251060 := "Not_a_Finding" if { bluetooth_module_disabled } else := "Open"

finding_rhel_09_251060 := {
	"vuln_id": "V-258110",
	"stig_id": "RHEL-09-251060",
	"severity": "CAT II",
	"rule_title": "RHEL 9 must disable the bluetooth kernel module",
	"status": status_rhel_09_251060,
	"fix_text": "Blacklist bluetooth: echo 'install bluetooth /bin/false' >> /etc/modprobe.d/bluetooth.conf",
}

# RHEL-09-251065 | V-258111 | CAT II
# Network interfaces must not be in promiscuous mode
default no_promiscuous_interfaces := false

no_promiscuous_interfaces if {
	count(input.promiscuous_interfaces) == 0
}

no_promiscuous_interfaces if {
	not input.promiscuous_interfaces
}

status_rhel_09_251065 := "Not_a_Finding" if { no_promiscuous_interfaces } else := "Open"

finding_rhel_09_251065 := {
	"vuln_id": "V-258111",
	"stig_id": "RHEL-09-251065",
	"severity": "CAT II",
	"rule_title": "RHEL 9 network interfaces must not be in promiscuous mode",
	"status": status_rhel_09_251065,
	"fix_text": "Disable promiscuous mode: ip link set <interface> promisc off",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_09_251010,
	finding_rhel_09_251015,
]

cat_ii_findings := [
	finding_rhel_09_251020,
	finding_rhel_09_251025,
	finding_rhel_09_251030,
	finding_rhel_09_251035,
	finding_rhel_09_251040,
	finding_rhel_09_251045,
	finding_rhel_09_251050,
	finding_rhel_09_251055,
	finding_rhel_09_251060,
	finding_rhel_09_251065,
]

findings := array.concat(cat_i_findings, cat_ii_findings)

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if {
	count(open_cat_i) == 0
}

compliance_report := {
	"module": "network",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
