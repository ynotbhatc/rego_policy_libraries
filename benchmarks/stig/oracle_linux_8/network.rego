# METADATA
# title: "DISA STIG for Oracle Linux 8 - Network Configuration Module"
# custom:
#   class: security
#   framework: stig_oracle_linux_8
#   source: disa
#   domains: [linux, oracle]
#   coverage:
#     checks: 10
#     cited: 9
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.oracle_linux_8.network

# DISA STIG for Oracle Linux 8 - Network Configuration Module
# STIG Version: V2R10 | Released: 30 Sep 2026
# Derived from stig/oracle_linux_9/network.rego by DISA rule title: Oracle Linux 8 and Oracle Linux 9 share the rule text;
# ids, vuln ids, severities and titles are the Oracle Linux 8 XCCDF's (tools/stig_generators/gen_oracle_linux.py).
# Covers: Firewall, network parameters, IPv6, ICMP redirects

import rego.v1

default compliant := false

# =============================================================================
# CAT II - MEDIUM SEVERITY
# =============================================================================

# OL08-00-040259 | V-252662 | CAT II
# IP forwarding must be disabled
default ip_forwarding_disabled := false

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
	input.network_config.ipv4_forwarding == false
}

ip_forwarding_disabled if {
	input.kernel_params["net.ipv4.ip_forward"] == "0"
}

status_ol08_00_040259 := "Not_a_Finding" if { ip_forwarding_disabled } else := "Open"

finding_ol08_00_040259 := {
	"vuln_id": "V-252662",
	"stig_id": "OL08-00-040259",
	"severity": "CAT II",
	"rule_title": "OL 8 must not enable IPv4 packet forwarding unless the system is a router.",
	"status": status_ol08_00_040259,
	"fix_text": "Disable IP forwarding: Set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-stig.conf",
}

# OL08-00-040279 | V-248887 | CAT II
# ICMP redirects must not be accepted (IPv4)
default icmp_redirect_accept_disabled := false

icmp_redirect_accept_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_redirects"] == "0"
}

status_ol08_00_040279 := "Not_a_Finding" if { icmp_redirect_accept_disabled } else := "Open"

finding_ol08_00_040279 := {
	"vuln_id": "V-248887",
	"stig_id": "OL08-00-040279",
	"severity": "CAT II",
	"rule_title": "OL 8 must ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages.",
	"status": status_ol08_00_040279,
	"fix_text": "Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# OL08-00-040220 | V-248877 | CAT II
# ICMP redirects must not be sent
default icmp_redirect_send_disabled := false

icmp_redirect_send_disabled if {
	input.kernel_params["net.ipv4.conf.all.send_redirects"] == "0"
	input.kernel_params["net.ipv4.conf.default.send_redirects"] == "0"
}

status_ol08_00_040220 := "Not_a_Finding" if { icmp_redirect_send_disabled } else := "Open"

finding_ol08_00_040220 := {
	"vuln_id": "V-248877",
	"stig_id": "OL08-00-040220",
	"severity": "CAT II",
	"rule_title": "OL 8 must not send Internet Control Message Protocol (ICMP) redirects.",
	"status": status_ol08_00_040220,
	"fix_text": "Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.d/99-stig.conf",
}

# OL08-00-040240 | V-248880 | CAT II
# Source routing must be disabled
default source_routing_disabled := false

source_routing_disabled if {
	input.kernel_params["net.ipv4.conf.all.accept_source_route"] == "0"
	input.kernel_params["net.ipv4.conf.default.accept_source_route"] == "0"
}

status_ol08_00_040240 := "Not_a_Finding" if { source_routing_disabled } else := "Open"

finding_ol08_00_040240 := {
	"vuln_id": "V-248880",
	"stig_id": "OL08-00-040240",
	"severity": "CAT II",
	"rule_title": "OL 8 must not forward IPv6 source-routed packets.",
	"status": status_ol08_00_040240,
	"fix_text": "Set net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.d/99-stig.conf",
}

# OL08-00-040285 | V-248893 | CAT II
# Reverse path filter must be enabled
default rp_filter_enabled := false

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "1"
}

rp_filter_enabled if {
	input.kernel_params["net.ipv4.conf.all.rp_filter"] == "2"
}

status_ol08_00_040285 := "Not_a_Finding" if { rp_filter_enabled } else := "Open"

finding_ol08_00_040285 := {
	"vuln_id": "V-248893",
	"stig_id": "OL08-00-040285",
	"severity": "CAT II",
	"rule_title": "OL 8 must use reverse path filtering on all IPv4 interfaces.",
	"status": status_ol08_00_040285,
	"fix_text": "Set net.ipv4.conf.all.rp_filter=1 in /etc/sysctl.d/99-stig.conf",
}

# OL08-00-040280 | V-248888 | CAT II
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

status_ol08_00_040280 := "Not_a_Finding" if { ipv6_disabled_or_configured } else := "Open"

finding_ol08_00_040280 := {
	"vuln_id": "V-248888",
	"stig_id": "OL08-00-040280",
	"severity": "CAT II",
	"rule_title": "OL 8 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages.",
	"status": status_ol08_00_040280,
	"fix_text": "Disable IPv6 or configure: Set net.ipv6.conf.all.disable_ipv6=1",
}

# OL08-00-040110 | V-248842 | CAT II
# Wireless interfaces must be disabled unless mission requires
default wireless_disabled := false

wireless_disabled if {
	input.network_config.wireless_disabled == true
}

# Missing evidence is not a pass: the interface list must be collected (empty = none found).
wireless_disabled if {
	is_array(input.wireless_interfaces)
	count(input.wireless_interfaces) == 0
}

status_ol08_00_040110 := "Not_a_Finding" if { wireless_disabled } else := "Open"

finding_ol08_00_040110 := {
	"vuln_id": "V-248842",
	"stig_id": "OL08-00-040110",
	"severity": "CAT II",
	"rule_title": "OL 8 wireless network adapters must be disabled.",
	"status": status_ol08_00_040110,
	"fix_text": "Disable wireless: nmcli radio wifi off or disable in NetworkManager",
}

# OL08-00-040111 | V-248843 | CAT II
# Bluetooth kernel module must be disabled
default bluetooth_module_disabled := false

bluetooth_module_disabled if {
	input.kernel_modules["bluetooth"].blacklisted == true
}

bluetooth_module_disabled if {
	input.kernel_modules["bluetooth"].status == "disabled"
}

status_ol08_00_040111 := "Not_a_Finding" if { bluetooth_module_disabled } else := "Open"

finding_ol08_00_040111 := {
	"vuln_id": "V-248843",
	"stig_id": "OL08-00-040111",
	"severity": "CAT II",
	"rule_title": "OL 8 Bluetooth must be disabled.",
	"status": status_ol08_00_040111,
	"fix_text": "Blacklist bluetooth: echo 'install bluetooth /bin/false' >> /etc/modprobe.d/bluetooth.conf",
}

# OL08-00-040330 | V-248899 | CAT II
# Network interfaces must not be in promiscuous mode
default no_promiscuous_interfaces := false

# Missing evidence is not a pass: the interface list must be collected (empty = none found).
no_promiscuous_interfaces if {
	is_array(input.promiscuous_interfaces)
	count(input.promiscuous_interfaces) == 0
}

status_ol08_00_040330 := "Not_a_Finding" if { no_promiscuous_interfaces } else := "Open"

finding_ol08_00_040330 := {
	"vuln_id": "V-248899",
	"stig_id": "OL08-00-040330",
	"severity": "CAT II",
	"rule_title": "OL 8 network interfaces must not be in promiscuous mode.",
	"status": status_ol08_00_040330,
	"fix_text": "Disable promiscuous mode: ip link set <interface> promisc off",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := []

cat_ii_findings := [
	finding_ol08_00_040259,
	finding_ol08_00_040279,
	finding_ol08_00_040220,
	finding_ol08_00_040240,
	finding_ol08_00_040285,
	finding_ol08_00_040280,
	finding_ol08_00_040110,
	finding_ol08_00_040111,
	finding_ol08_00_040330,
]

cat_iii_findings := []

findings := array.concat(cat_i_findings, array.concat(cat_ii_findings, cat_iii_findings))

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

# Evidence gate: a module with none of its facts collected is unevaluated, not compliant.
evidence_present if {
	some key in {"kernel_params", "network_config", "wireless_interfaces", "promiscuous_interfaces", "kernel_modules"}
	object.get(input, key, null) != null
}

# NOTE: `compliant` is scoped to CAT I findings only (module convention), and this module carries
# no CAT I findings. Whether CAT II should also gate it is an open scope decision, see the
# validation 2026-10-17 report.
compliant if {
	evidence_present
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
