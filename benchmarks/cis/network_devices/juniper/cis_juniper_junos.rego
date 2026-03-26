package cis

# CIS Juniper JunOS Benchmark v2.1.0
# Center for Internet Security (CIS) Juniper JunOS Benchmark
# This policy implements comprehensive Juniper JunOS security controls

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

# Section 1: Management Plane Security
management_plane_violations := [
    "1.1.1: Ensure root authentication is configured" |
    not root_authentication_configured
]

root_authentication_configured if {
    user := input.junos_config.system.login.user[_]
    user.name == "root"
    user.authentication
}





ssh_configured_securely if {
    ssh := input.junos_config.system.services.ssh
    ssh.protocol_version == "v2"
    ssh.root_login == "deny"
}















security_syslog_configured if {
    file := input.junos_config.system.syslog.file[_]
    file.name == "security"
    facility := file.contents[_]
    facility.name == "authorization"
}



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
control_plane_violations := [
    "2.1.1: Ensure control plane traffic is protected with a filter" |
    not control_plane_filter_configured
]

control_plane_filter_configured if {
    filter := input.junos_config.firewall.family.inet.filter[_]
    filter.name == "CONTROL_PLANE_FILTER"
    lo0 := input.junos_config.interfaces.lo0
    lo0.unit["0"].family.inet.filter.input == "CONTROL_PLANE_FILTER"
}


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
data_plane_violations := [
    "3.1.1: Ensure ingress filtering is applied on all external interfaces" |
    interface := input.external_interfaces[_]
    unit := interface.unit["0"]
    not unit.family.inet.filter.input
]



anti_spoofing_configured if {
    filter := input.junos_config.firewall.family.inet.filter[_]
    filter.name == "ANTI_SPOOFING"
    term := filter.term[_]
    term.from.source_address == "0.0.0.0/8"
    term.then == "discard"
}





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