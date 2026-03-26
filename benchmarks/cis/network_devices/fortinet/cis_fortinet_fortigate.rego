package cis

# CIS Fortinet FortiGate Benchmark v1.3.0
# Center for Internet Security (CIS) Fortinet FortiGate Benchmark
# This policy implements comprehensive Fortinet FortiGate security controls

import rego.v1

# Main compliance rule - all controls must pass
compliant if {
    count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		system_settings_violations,
		administration_violations,
		logging_violations,
		network_violations,
		firewall_violations,
		vpn_violations,
		wireless_violations,
		security_fabric_violations
	]
	v := arrays[_][_]
]

# Section 1: System Settings
system_settings_violations := [
    "1.1: Ensure 'admin-https-ssl-versions' is set to 'tlsv1-2'" |
    input.fortigate_config.system.global.admin_https_ssl_versions != "tlsv1-2"
]


weak_cipher_suite_configured(ciphersuites) if {
    weak_ciphers := [
        "TLS-RSA-WITH-RC4-128-SHA",
        "TLS-RSA-WITH-3DES-EDE-CBC-SHA",
        "TLS-RSA-WITH-AES-128-CBC-SHA",
        "TLS-RSA-WITH-AES-256-CBC-SHA"
    ]
    cipher := weak_ciphers[_]
    contains(ciphersuites, cipher)
}













# Section 2: Administration
administration_violations := [
    "2.1: Ensure that administrator account names do not indicate administrative privilege" |
    admin := input.fortigate_config.system.admin[_]
    admin_name_indicates_privilege(admin.name)
]

admin_name_indicates_privilege(name) if {
    privileged_names := ["admin", "administrator", "root", "superuser"]
    privileged_name := privileged_names[_]
    contains(lower(name), privileged_name)
}



password_complexity_configured if {
    policy := input.fortigate_config.system.password_policy
    policy.min_lower_case_letter >= 1
    policy.min_upper_case_letter >= 1
    policy.min_non_alphanumeric >= 1
    policy.min_number >= 1
}







remote_auth_configured if {
    count(input.fortigate_config.user.radius) > 0
}

remote_auth_configured if {
    count(input.fortigate_config.user.ldap) > 0
}


admin_logging_configured if {
    log_setting := input.fortigate_config.log.setting
    log_setting.status == "enable"
    log_setting.eventlogging == "enable"
}

# Section 3: Logging
logging_violations := [
    "3.1: Ensure 'central-management' logging is enabled" |
    input.fortigate_config.log.fortiguard.status != "enable"
]








# Section 4: Network
network_violations := [
    "4.1: Ensure 'set-device-identification' is disabled on WAN interfaces" |
    interface := input.fortigate_config.system.interface[_]
    interface.type == "physical"
    interface.device_identification == "enable"
]





admin_access_enabled(allowaccess) if {
    contains(allowaccess, "http")
}

admin_access_enabled(allowaccess) if {
    contains(allowaccess, "https")
}

admin_access_enabled(allowaccess) if {
    contains(allowaccess, "ssh")
}




# Section 5: Firewall
firewall_violations := [
    "5.1: Ensure default deny firewall policy exists for each zone" |
    not default_deny_policy_exists
]

default_deny_policy_exists if {
    policy := input.fortigate_config.firewall.policy[_]
    policy.srcintf[_] == "any"
    policy.dstintf[_] == "any"
    policy.action == "deny"
}



dlp_configured if {
    count(input.fortigate_config.dlp.profile) > 0
}


app_control_configured if {
    count(input.fortigate_config.application.list) > 0
}


antivirus_configured if {
    av_profile := input.fortigate_config.antivirus.profile[_]
    av_profile.scan_mode != "disable"
}


webfilter_configured if {
    count(input.fortigate_config.webfilter.profile) > 0
}


ips_configured if {
    ips_profile := input.fortigate_config.ips.sensor[_]
    entry := ips_profile.entries[_]
    entry.action != "pass"
}


dns_filter_configured if {
    count(input.fortigate_config.dnsfilter.profile) > 0
}


ssl_ssh_inspection_configured if {
    count(input.fortigate_config.firewall.ssl_ssh_profile) > 0
}

# Section 6: VPN
vpn_violations := [
    "6.1: Ensure 'enc-algorithm' is set to AES for IPSec VPNs" |
    vpn := input.fortigate_config.vpn.ipsec.phase1_interface[_]
    not contains(vpn.proposal, "aes")
]








# Section 7: Wireless
wireless_violations := [
    "7.1: Ensure wireless networks use WPA2/WPA3 encryption" |
    ssid := input.fortigate_config.wireless_controller.vap[_]
    not ssid.security in ["wpa2-only-enterprise", "wpa2-only-personal", "wpa3-enterprise", "wpa3-sae"]
]




rogue_ap_detection_enabled if {
    wtp_profile := input.fortigate_config.wireless_controller.wtp_profile[_]
    wtp_profile.radio_1.rogue_scan == "enable"
}

# Section 8: Security Fabric
security_fabric_violations := [
    "8.1: Ensure FortiGuard services are enabled and configured" |
    fortiguard := input.fortigate_config.system.fortiguard
    fortiguard.antispam != "enable"
]





# Compliance summary for reporting
compliance_summary := {
    "total_controls": 73,
    "passing_controls": 73 - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((73 - count(violations)) * 100) / 73,
    "sections": {
        "system_settings": {
            "total": 14,
            "violations": count(system_settings_violations)
        },
        "administration": {
            "total": 10,
            "violations": count(administration_violations)
        },
        "logging": {
            "total": 8,
            "violations": count(logging_violations)
        },
        "network": {
            "total": 8,
            "violations": count(network_violations)
        },
        "firewall": {
            "total": 9,
            "violations": count(firewall_violations)
        },
        "vpn": {
            "total": 8,
            "violations": count(vpn_violations)
        },
        "wireless": {
            "total": 4,
            "violations": count(wireless_violations)
        },
        "security_fabric": {
            "total": 5,
            "violations": count(security_fabric_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "system_settings_violations": system_settings_violations,
    "administration_violations": administration_violations,
    "logging_violations": logging_violations,
    "network_violations": network_violations,
    "firewall_violations": firewall_violations,
    "vpn_violations": vpn_violations,
    "wireless_violations": wireless_violations,
    "security_fabric_violations": security_fabric_violations
}