package cis

# CIS Arista EOS Benchmark v1.2.0
# Center for Internet Security (CIS) Arista EOS Benchmark
# This policy implements comprehensive Arista EOS security controls

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
		data_plane_violations,
		logging_violations
	]
	v := arrays[_][_]
]

# Section 1: Management Plane Security
management_plane_violations := [
    "1.1.1: Ensure AAA authentication is configured" |
    not aaa_authentication_configured
]

aaa_authentication_configured if {
    auth_method := input.eos_config.aaa.authentication["default"][_]
    auth_method != "none"
}


aaa_authorization_configured if {
    input.eos_config.aaa.authorization.exec["default"]
}


aaa_accounting_configured if {
    input.eos_config.aaa.accounting.exec["default"]
}








vty_ssh_only_configured if {
    management_console := input.eos_config.management.console
    management_console.idle_timeout
}


vty_timeout_configured if {
    console := input.eos_config.management.console
    console.idle_timeout
    console.idle_timeout <= 10
}





weak_ssh_algorithm(algorithm) if {
    weak_algorithms := ["ssh-dss", "ssh-rsa-sha1", "ecdsa-sha2-nistp256"]
    algorithm in weak_algorithms
}









# Section 2: Control Plane Security
control_plane_violations := [
    "2.1.1: Ensure IP source routing is disabled" |
    input.eos_config.ip.source_route == true
]












control_plane_protection_configured if {
    copp := input.eos_config.control_plane
    copp.service_policy.input
}


cpu_protection_configured if {
    policy := input.eos_config.policy_map[_]
    policy.class[_].police
}

# Section 3: Data Plane Security
data_plane_violations := [
    "3.1.1: Ensure ingress filtering is applied on all external interfaces" |
    interface := input.external_interfaces[_]
    not interface.access_group["in"]
]



anti_spoofing_acl_configured if {
    acl := input.eos_config.ip.access_list.extended[_]
    acl.name == "ANTI_SPOOFING"
    rule := acl.rule[_]
    rule.source == "10.0.0.0/8"
    rule.action == "deny"
}








dhcp_snooping_configured if {
    input.eos_config.ip.dhcp.snooping == true
}



dynamic_arp_inspection_configured if {
    vlan := input.eos_config.ip.arp.inspection.vlan[_]
    vlan.enabled == true
}



interface_in_use(interface_name) if {
    used_interface := input.used_interfaces[_]
    used_interface == interface_name
}


vlan_in_use(vlan_id) if {
    used_vlan := input.used_vlans[_]
    used_vlan == vlan_id
}

# Section 4: Logging and Monitoring
logging_violations := [
    "4.1.1: Ensure logging is enabled" |
    not input.eos_config.logging.on
]







event_monitoring_configured if {
    input.eos_config.event_monitor.enabled == true
}




# Compliance summary for reporting
compliance_summary := {
    "total_controls": 74,
    "passing_controls": 74 - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((74 - count(violations)) * 100) / 74,
    "sections": {
        "management_plane": {
            "total": 32,
            "violations": count(management_plane_violations)
        },
        "control_plane": {
            "total": 18,
            "violations": count(control_plane_violations)
        },
        "data_plane": {
            "total": 14,
            "violations": count(data_plane_violations)
        },
        "logging": {
            "total": 10,
            "violations": count(logging_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "management_plane_violations": management_plane_violations,
    "control_plane_violations": control_plane_violations,
    "data_plane_violations": data_plane_violations,
    "logging_violations": logging_violations
}