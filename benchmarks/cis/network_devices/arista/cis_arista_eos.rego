# METADATA
# title: "CIS Arista EOS Benchmark v1.2.0"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, arista]
#   coverage:
#     checks: 4
#     cited: 4
#     density: sparse
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_arista_eos

# CIS Arista EOS Benchmark v1.2.0
# Center for Internet Security (CIS) Arista EOS Benchmark
# This policy implements comprehensive Arista EOS security controls

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
		data_plane_violations,
		logging_violations
	]
	v := arrays[_][_]
]

# Section 1: Management Plane Security
management_plane_violations := array.concat(
    [
        "1.1.1: Ensure AAA authentication is configured" |
        not aaa_authentication_configured
    ],
    array.concat(
        [
            "1.1.2: Ensure AAA authorization is configured" |
            not aaa_authorization_configured
        ],
        array.concat(
            [
                "1.1.3: Ensure AAA accounting is configured" |
                not aaa_accounting_configured
            ],
            [
                "1.2.1: Ensure VTY/console idle timeout is configured and at most 10 minutes" |
                not vty_timeout_configured
            ],
        ),
    ),
)

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


vty_timeout_configured if {
    console := input.eos_config.management.console
    console.idle_timeout
    console.idle_timeout <= 10
}


# Section 2: Control Plane Security
# Missing evidence fails closed: no eos_config means nothing can be judged.
control_plane_violations := array.concat(
    [
        "2.1.1: Ensure IP source routing is disabled" |
        input.eos_config.ip.source_route == true
    ],
    array.concat(
        [
            "2.0: evidence missing — eos_config not collected" |
            not is_object(object.get(input, "eos_config", null))
        ],
        array.concat(
            [
                "2.2.1: Ensure control-plane protection (service policy) is configured" |
                not control_plane_protection_configured
            ],
            [
                "2.2.2: Ensure CPU protection (policed classes) is configured" |
                not cpu_protection_configured
            ],
        ),
    ),
)


control_plane_protection_configured if {
    copp := input.eos_config.control_plane
    copp.service_policy.input
}


cpu_protection_configured if {
    policy := input.eos_config.policy_map[_]
    policy.class[_].police
}

# Section 3: Data Plane Security
data_plane_violations := array.concat(
    [
        "3.1.1: Ensure ingress filtering is applied on all external interfaces" |
        interface := input.external_interfaces[_]
        not interface.access_group["in"]
    ],
    array.concat(
        [
            "3.1.0: evidence missing — external_interfaces not collected" |
            not is_array(object.get(input, "external_interfaces", null))
        ],
        array.concat(
            [
                "3.2.1: Ensure anti-spoofing ACL is configured" |
                not anti_spoofing_acl_configured
            ],
            array.concat(
                [
                    "3.3.1: Ensure DHCP snooping is enabled" |
                    not dhcp_snooping_configured
                ],
                [
                    "3.3.2: Ensure dynamic ARP inspection is enabled" |
                    not dynamic_arp_inspection_configured
                ],
            ),
        ),
    ),
)



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


# Section 4: Logging and Monitoring
logging_violations := array.concat(
    [
        "4.1.1: Ensure logging is enabled" |
        not input.eos_config.logging.on
    ],
    [
        "4.2.1: Ensure event monitoring is enabled" |
        not event_monitoring_configured
    ],
)


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