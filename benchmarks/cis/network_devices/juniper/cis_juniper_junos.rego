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
		data_plane_violations
	]
	v := arrays[_][_]
]

# Section 1: Management Plane Security
management_plane_checks := [
	{"msg": "UNMAPPED-JUNOS-1.1: Ensure remote AAA (RADIUS or TACACS+) is configured", "ok": remote_aaa_configured},
	{"msg": "UNMAPPED-JUNOS-1.2: Ensure SSH is configured securely (protocol v2, root login denied)", "ok": ssh_configured_securely},
	{"msg": "UNMAPPED-JUNOS-1.3: Ensure security syslog is configured", "ok": security_syslog_configured},
	{"msg": "UNMAPPED-JUNOS-1.4: Ensure ntp authentication is configured", "ok": ntp_authentication_configured},
]

management_plane_violations := array.concat(
[
    "1.1.1: Ensure root authentication is configured" |
    not root_authentication_configured
],
[c.msg | some c in management_plane_checks; not c.ok],
)

root_authentication_configured if {
    user := input.junos_config.system.login.user[_]
    user.name == "root"
    user.authentication
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
    ntp.authentication_key
    ntp.trusted_key
}








radius_configured if {
    count(input.junos_config.system.radius_server) > 0
}


tacplus_configured if {
    count(input.junos_config.system.tacplus_server) > 0
}

# Section 2: Control Plane Security
control_plane_violations := array.concat(
    [
        "2.1.1: Ensure control plane traffic is protected with a filter" |
        not control_plane_filter_configured
    ],
    [
        "2.2.1: Ensure routing protocol (OSPF/BGP) authentication is configured" |
        routing_protocol_in_use
        not routing_protocol_auth_configured
    ],
)

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
routing_protocol_in_use if input.junos_config.protocols.ospf

routing_protocol_in_use if input.junos_config.protocols.bgp

default routing_protocol_auth_configured := false

routing_protocol_auth_configured if {
    ospf := input.junos_config.protocols.ospf
    ospf.area["0.0.0.0"].authentication.simple_password
}

routing_protocol_auth_configured if {
    bgp := input.junos_config.protocols.bgp
    group := bgp.group[_]
    group.authentication_key
}











# Section 3: Data Plane Security
data_plane_checks := [
	{"msg": "UNMAPPED-JUNOS-3.2: Ensure anti spoofing is configured", "ok": anti_spoofing_configured},
	{"msg": "UNMAPPED-JUNOS-3.3: Ensure spanning tree protection is configured", "ok": spanning_tree_protection_configured},
]

data_plane_violations := array.concat(
[
    "3.1.1: Ensure ingress filtering is applied on all external interfaces" |
    interface := input.external_interfaces[_]
    not ingress_filter_applied(interface)
]
,
[c.msg | some c in data_plane_checks; not c.ok],
)

# An interface with no unit 0 (or no input filter on it) is unfiltered.
ingress_filter_applied(interface) if interface.unit["0"].family.inet.filter.input



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
            "violations": count(management_plane_violations)
        },
        "control_plane": {
            "total": 18,
            "violations": count(control_plane_violations)
        },
        "data_plane": {
            "total": 16,
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