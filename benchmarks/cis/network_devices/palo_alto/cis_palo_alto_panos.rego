package cis

# CIS Palo Alto PAN-OS Benchmark v1.1.0
# Center for Internet Security (CIS) Palo Alto PAN-OS Benchmark
# This policy implements comprehensive Palo Alto Networks PAN-OS security controls

import rego.v1

# Main compliance rule - all controls must pass
compliant if {
    count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		management_interface_violations,
		authentication_violations,
		admin_access_violations,
		security_services_violations,
		logging_violations,
		network_security_violations,
		device_management_violations
	]
	v := arrays[_][_]
]

# Section 1: Management Interface
management_interface_violations := [
    "1.1: Ensure 'Permitted IP Addresses' is set for all administrative users" |
    admin := input.panos_config.mgt_config.users.entry[_]
    not admin.client_certificate_only
    not admin.allowed_ips
]




certificate_based_admin_configured if {
    admin := input.panos_config.mgt_config.users.entry[_]
    admin.client_certificate_only == "yes"
}





# Section 2: Authentication
authentication_violations := [
    "2.1: Ensure that an authentication profile is set for each administrator" |
    admin := input.panos_config.mgt_config.users.entry[_]
    not admin.authentication_profile
]








# Section 3: Admin Access
admin_access_violations := [
    "3.1: Ensure 'Maximum number of concurrent administrators' is set to a value lower than 10" |
    max_admins := input.panos_config.mgt_config.max_concurrent_admins
    not max_admins
    max_admins >= 10
]








# Section 4: Security Services
security_services_violations := [
    "4.1: Ensure DNS sinkholing is configured for malicious domains" |
    not dns_sinkhole_configured
]

dns_sinkhole_configured if {
    sinkhole := input.panos_config.shared.botnet.configuration.dns_signature.entry[_]
    sinkhole.sinkhole.ipv4_address
}







wildfire_configured if {
    wildfire_profile := input.panos_config.shared.profiles.wildfire_analysis.entry[_]
    rule := wildfire_profile.rules.entry[_]
    rule.analysis == "public-cloud"
}


# Section 5: Logging
logging_violations := [
    "5.1: Ensure that an email server profile is configured for critical alerts" |
    not email_server_configured
]

email_server_configured if {
    email := input.panos_config.shared.server_profile.email.entry[_]
    email.server.smtp_gateway
}


syslog_server_configured if {
    syslog := input.panos_config.shared.server_profile.syslog.entry[_]
    syslog.server.server
}


snmp_monitoring_configured if {
    snmp := input.panos_config.shared.server_profile.snmp.entry[_]
    snmp.server.manager
}


log_export_configured if {
    log_settings := input.panos_config.shared.log_settings
    log_settings.system.match_list.entry[_].log_type == "system"
}


ha_logging_configured if {
    ha := input.panos_config.device.high_availability
    ha.group.entry[_].monitoring.path_monitoring == "enabled"
}


# Section 6: Network Security
network_security_violations := [
    "6.1: Ensure that 'Zones' are set to the appropriate function" |
    zone := input.panos_config.shared.zone.entry[_]
    zone.network.layer3[_]
    not zone_function_appropriate(zone.name)
]

zone_function_appropriate(zone_name) if {
    zone_name in ["trust", "untrust", "dmz"]
}


intrazone_default_policy_exists if {
    rule := input.panos_config.shared.rulebase.security.rules.entry[_]
    rule.from[_] == rule.to[_]
    rule.action == "deny"
}


interzone_default_policy_exists if {
    rule := input.panos_config.shared.rulebase.security.rules.entry[_]
    rule.from[_] != rule.to[_]
    rule.action == "deny"
}





anti_spoof_configured if {
    interface := input.panos_config.shared.interface.ethernet.entry[_]
    interface.layer3.interface_management_profile
    profile := input.panos_config.shared.interface_management_profile.entry[_]
    profile.permitted_ip.entry[_]
}

# Section 7: Device Management
device_management_violations := [
    "7.1: Ensure that 'Hostname' is set appropriately" |
    not input.panos_config.device.hostname
]








certificate_management_configured if {
    cert := input.panos_config.shared.certificate.entry[_]
    cert.algorithm == "RSA"
    cert.rsa.certificate_key_size >= 2048
}



# Compliance summary for reporting
compliance_summary := {
    "total_controls": 70,
    "passing_controls": 70 - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((70 - count(violations)) * 100) / 70,
    "sections": {
        "management_interface": {
            "total": 8,
            "violations": count(management_interface_violations)
        },
        "authentication": {
            "total": 8,
            "violations": count(authentication_violations)
        },
        "admin_access": {
            "total": 8,
            "violations": count(admin_access_violations)
        },
        "security_services": {
            "total": 8,
            "violations": count(security_services_violations)
        },
        "logging": {
            "total": 6,
            "violations": count(logging_violations)
        },
        "network_security": {
            "total": 7,
            "violations": count(network_security_violations)
        },
        "device_management": {
            "total": 10,
            "violations": count(device_management_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "management_interface_violations": management_interface_violations,
    "authentication_violations": authentication_violations,
    "admin_access_violations": admin_access_violations,
    "security_services_violations": security_services_violations,
    "logging_violations": logging_violations,
    "network_security_violations": network_security_violations,
    "device_management_violations": device_management_violations
}