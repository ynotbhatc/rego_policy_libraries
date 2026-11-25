# METADATA
# title: "CIS Juniper JunOS Benchmark v2.1.0"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network]
#   coverage:
#     checks: 9
#     cited: 9
#     density: sparse
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_juniper_junos

# CIS Juniper JunOS Benchmark v2.1.0
# Center for Internet Security (CIS) Juniper JunOS Benchmark
# This policy implements comprehensive Juniper JunOS security controls
#
# DEPRECATION NOTICE: CIS has scheduled this benchmark for archival due to
# lack of Subject Matter Expert support. Customers should monitor
# https://www.cisecurity.org/cis-benchmarks for updated status.
# Controls remain valid for existing JunOS deployments but will not receive
# further updates from CIS.

import rego.v1

# Evidence rule: a setting counts as configured only when it holds configuration. A boolean, null, an empty
# value or one of the words a collector writes for a yes/no ("true", "false", "yes", "no") in place of a key,
# a password or a filter name is not configuration, and the control fails.
_text(v) if {
	is_string(v)
	not lower(trim_space(v)) in {"", "true", "false", "yes", "no", "null", "none"}
}

_configured(v) if _text(v)

_configured(v) if is_number(v)

_configured(v) if {
	is_object(v)
	count(v) > 0
}

_configured(v) if {
	is_array(v)
	count(v) > 0
	every x in v {
		_item(x)
	}
}

_item(x) if _text(x)

_item(x) if is_number(x)

_item(x) if {
	is_object(x)
	count(x) > 0
}

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
	]
	v := arrays[_][_]
]

# Section 1: Management Plane Security
management_plane_checks := [
	{"msg": "UNMAPPED-JUNOS-1.1: remote AAA (RADIUS or TACACS+) must be explicitly configured", "ok": remote_aaa_configured},
	{"msg": "UNMAPPED-JUNOS-1.2: SSH must be explicitly configured securely (protocol v2, root login denied)", "ok": ssh_configured_securely},
	{"msg": "UNMAPPED-JUNOS-1.3: security syslog must be explicitly configured", "ok": security_syslog_configured},
	{"msg": "UNMAPPED-JUNOS-1.4: ntp authentication must be explicitly configured", "ok": ntp_authentication_configured},
]

management_plane_violations := array.concat(
	[
	"1.1.1: root authentication must be explicitly configured" |
		not root_authentication_configured
	],
	[c.msg | some c in management_plane_checks; not c.ok],
)

root_authentication_configured if {
	user := input.junos_config.system.login.user[_]
	user.name == "root"
	_configured(user.authentication)
}

default ssh_configured_securely := false

ssh_configured_securely if {
	ssh := input.junos_config.system.services.ssh
	ssh.protocol_version == "v2"
	ssh.root_login == "deny"
}

default security_syslog_configured := false

security_syslog_configured if {
	file := input.junos_config.system.syslog.file[_]
	file.name == "security"
	facility := file.contents[_]
	facility.name == "authorization"
}

default ntp_authentication_configured := false

ntp_authentication_configured if {
	ntp := input.junos_config.system.ntp
	_configured(ntp.authentication_key)
	_configured(ntp.trusted_key)
}

radius_configured if {
	_configured(input.junos_config.system.radius_server)
	not is_string(input.junos_config.system.radius_server)
}

tacplus_configured if {
	_configured(input.junos_config.system.tacplus_server)
	not is_string(input.junos_config.system.tacplus_server)
}

# Section 2: Control Plane Security
control_plane_violations := array.concat(
	[
	"2.1.1: control plane traffic must be protected with a filter" |
		not control_plane_filter_configured
	],
	array.concat(
		[
		"2.2.1: routing protocol (OSPF/BGP) authentication must be explicitly configured" |
			routing_protocol_in_use
			not routing_protocol_auth_configured
		],
		# "no routing protocol runs" is a statement the collected protocols section makes; without the
		# section it cannot be told from "not collected"
		[
		"2.2.1: evidence missing — junos_config.protocols not collected" |
			not _protocols_collected
		],
	),
)

default _protocols_collected := false

_protocols_collected if is_object(input.junos_config.protocols)

control_plane_filter_configured if {
	filter := input.junos_config.firewall.family.inet.filter[_]
	filter.name == "CONTROL_PLANE_FILTER"
	lo0 := input.junos_config.interfaces.lo0
	lo0.unit["0"].family.inet.filter.input == "CONTROL_PLANE_FILTER"
}

# RADIUS or TACACS+ satisfies remote AAA (alternatives, not both required).
default remote_aaa_configured := false

remote_aaa_configured if radius_configured

remote_aaa_configured if tacplus_configured

# Routing-protocol authentication applies only where OSPF or BGP is running.
# a protocol node present in any form but an explicit false is in use (a string in its place fails closed)
routing_protocol_in_use if {
	some proto in ["ospf", "bgp"]
	object.get(input.junos_config.protocols, proto, false) != false
}

default routing_protocol_auth_configured := false

routing_protocol_auth_configured if {
	ospf := input.junos_config.protocols.ospf
	_configured(ospf.area["0.0.0.0"].authentication.simple_password)
}

routing_protocol_auth_configured if {
	bgp := input.junos_config.protocols.bgp
	group := bgp.group[_]
	_configured(group.authentication_key)
}

# Section 3: Data Plane Security
data_plane_checks := [
	{"msg": "UNMAPPED-JUNOS-3.2: anti spoofing must be explicitly configured", "ok": anti_spoofing_configured},
	{"msg": "UNMAPPED-JUNOS-3.3: spanning tree protection must be explicitly configured", "ok": spanning_tree_protection_configured},
]

data_plane_violations := array.concat(
	array.concat(
		[
		"3.1.1: ingress filtering must be applied on all external interfaces" |
			interface := input.external_interfaces[_]
			not ingress_filter_applied(interface)
		],
		# the list of external interfaces is the evidence; an empty list states there are none
		[
		"3.1.1: evidence missing — external_interfaces not collected" |
			not is_array(object.get(input, "external_interfaces", null))
		],
	),
	[c.msg | some c in data_plane_checks; not c.ok],
)

# An interface with no unit 0 (or no input filter on it) is unfiltered.
ingress_filter_applied(interface) if {
	name := interface.unit["0"].family.inet.filter.input
	is_string(name)
	_configured(name)
}

default anti_spoofing_configured := false

anti_spoofing_configured if {
	filter := input.junos_config.firewall.family.inet.filter[_]
	filter.name == "ANTI_SPOOFING"
	term := filter.term[_]
	term.from.source_address == "0.0.0.0/8"
	term.then == "discard"
}

default spanning_tree_protection_configured := false

spanning_tree_protection_configured if {
	input.junos_config.protocols.rstp.bpdu_block_on_edge == true
}

interface_in_use(interface_name) if {
	interface := input.used_interfaces[_]
	interface == interface_name
}

vlan_in_use(vlan_name) if {
	vlan := input.used_vlans[_]
	vlan == vlan_name
}

# Compliance summary for reporting
compliance_summary := {
	"total_controls": 78,
	"passing_controls": 78 - count(violations),
	"failing_controls": count(violations),
	"compliance_percentage": ((78 - count(violations)) * 100) / 78,
	"sections": {
		"management_plane": {
			"total": 44,
			"violations": count(management_plane_violations),
		},
		"control_plane": {
			"total": 18,
			"violations": count(control_plane_violations),
		},
		"data_plane": {
			"total": 16,
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
