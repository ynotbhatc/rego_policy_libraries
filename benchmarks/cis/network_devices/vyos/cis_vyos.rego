package cis_vyos

# CIS VyOS Router Hardening Benchmark v1.0.0
# Based on CIS principles applied to VyOS 1.3/1.4 (Equuleus/Sagitta)
#
# Input structure (from `show configuration json` via SSH):
#   input.system      — hostname, login users, NTP, timezone, name-servers
#   input.service     — ssh, https, snmp, telnet, dns-forwarding
#   input.firewall    — name groups, interface assignments, default-actions
#   input.interfaces  — ethernet/loopback definitions
#   input.protocols   — BGP, OSPF, routing
#   input.policy      — route-maps, prefix-lists
#   input.version     — VyOS version string  e.g. "VyOS 1.4.0"
#   input.platform    — "vyos"
#
# OPA endpoint: POST http://192.168.4.62:8181/v1/data/cis_vyos/compliance_assessment

import rego.v1

default compliant := false

# ── Section 1: SSH / Remote Access ───────────────────────────────────────────

# 1.1.1  SSH must be enabled (management access must be SSH, not telnet)
ssh_enabled if {
    input.service.ssh
}

# 1.1.2  Only SSH v2 allowed
ssh_version_2 if {
    not input.service.ssh["disable-host-validation"]
    # VyOS defaults to v2; flag if older is forced
    not input.service.ssh["v1-enabled"]
}

# 1.1.3  Password-only auth disabled — keys required
ssh_no_password_auth if {
    input.service.ssh["disable-password-authentication"]
}

# 1.1.4  SSH idle timeout ≤ 300 seconds
ssh_timeout_ok if {
    timeout_str := input.service.ssh["client-keepalive-interval"]
    timeout := to_number(timeout_str)
    timeout > 0
    timeout <= 300
}

# 1.1.5  Root login explicitly disabled
ssh_no_root_login if {
    not input.service.ssh["allow-root"]
}

# 1.1.6  Login banner configured
login_banner_configured if {
    input.system.login.banner
    count(trim_space(input.system.login.banner)) > 0
}

section_1_violations contains msg if {
    not ssh_enabled
    msg := "1.1.1 SSH service not configured — telnet or no remote access"
}

section_1_violations contains msg if {
    ssh_enabled
    not ssh_version_2
    msg := "1.1.2 SSH v1 explicitly enabled — disable immediately"
}

section_1_violations contains msg if {
    ssh_enabled
    not ssh_no_password_auth
    msg := "1.1.3 SSH password authentication enabled — require key-based auth"
}

section_1_violations contains msg if {
    ssh_enabled
    not ssh_timeout_ok
    msg := "1.1.4 SSH client-keepalive-interval not set or exceeds 300s"
}

section_1_violations contains msg if {
    ssh_enabled
    not ssh_no_root_login
    msg := "1.1.5 SSH root login not explicitly disabled"
}

section_1_violations contains msg if {
    not login_banner_configured
    msg := "1.1.6 Login banner not configured (required for legal notice)"
}

# ── Section 2: Management Services ───────────────────────────────────────────

# 2.1.1  Telnet explicitly disabled
telnet_disabled if {
    not input.service.telnet
}

# 2.1.2  HTTP management disabled (HTTPS only if GUI in use)
http_disabled if {
    not input.service["http"]
}

# 2.1.3  SNMP disabled or v3 only
snmp_secure if {
    not input.service.snmp
}

snmp_secure if {
    input.service.snmp.v3
    not input.service.snmp.community   # no v1/v2c communities
}

# 2.1.4  NTP configured with at least one server
ntp_configured if {
    count(input.system.ntp.server) >= 1
}

# 2.1.5  Remote syslog configured
syslog_remote if {
    some server, _ in input.system.syslog.host
    count(server) > 0
}

# 2.1.6  DNS name-servers configured
dns_configured if {
    count(input.system["name-server"]) >= 1
}

section_2_violations contains msg if {
    not telnet_disabled
    msg := "2.1.1 Telnet service enabled — disable immediately"
}

section_2_violations contains msg if {
    not http_disabled
    msg := "2.1.2 HTTP management service enabled — use HTTPS only"
}

section_2_violations contains msg if {
    not snmp_secure
    msg := "2.1.3 SNMP v1/v2c community configured — use SNMPv3 or disable SNMP"
}

section_2_violations contains msg if {
    not ntp_configured
    msg := "2.1.4 NTP not configured — time synchronization required"
}

section_2_violations contains msg if {
    not syslog_remote
    msg := "2.1.5 Remote syslog not configured — logs must be sent off-device"
}

section_2_violations contains msg if {
    not dns_configured
    msg := "2.1.6 No DNS name-servers configured"
}

# ── Section 3: Firewall ───────────────────────────────────────────────────────

# 3.1.1  At least one firewall ruleset exists
firewall_defined if {
    count(input.firewall.name) >= 1
}

# 3.1.2  WAN-facing interface has a firewall applied
wan_firewall_applied if {
    some iface, config in input.interfaces.ethernet
    config.description
    lower(config.description) == "wan"
    config.firewall["in"].name
}

wan_firewall_applied if {
    some iface, config in input.interfaces.ethernet
    config.description
    lower(config.description) == "wan"
    config.firewall["local"].name
}

# 3.1.3  At least one ruleset uses default-action drop
default_deny_exists if {
    some name, ruleset in input.firewall.name
    ruleset["default-action"] == "drop"
}

# 3.1.4  State-based connection tracking enabled (stateful inspection)
stateful_enabled if {
    some name, ruleset in input.firewall.name
    some rule_num, rule in ruleset.rule
    rule.state.established.action == "accept"
    rule.state.related.action == "accept"
}

# 3.1.5  Firewall logging enabled on at least one deny rule
firewall_logging_enabled if {
    some name, ruleset in input.firewall.name
    some rule_num, rule in ruleset.rule
    rule.action == "drop"
    rule.log
}

# 3.1.6  Source routing (IP options) disabled
source_routing_disabled if {
    not input.system["ip"]["source-route"]
}

source_routing_disabled if {
    input.system["ip"]["source-route"] == "false"
}

section_3_violations contains msg if {
    not firewall_defined
    msg := "3.1.1 No firewall rulesets defined"
}

section_3_violations contains msg if {
    firewall_defined
    not wan_firewall_applied
    msg := "3.1.2 WAN interface has no inbound/local firewall ruleset applied"
}

section_3_violations contains msg if {
    firewall_defined
    not default_deny_exists
    msg := "3.1.3 No ruleset has default-action drop — default-permit is insecure"
}

section_3_violations contains msg if {
    firewall_defined
    not stateful_enabled
    msg := "3.1.4 No stateful connection tracking rules (ESTABLISHED/RELATED accept)"
}

section_3_violations contains msg if {
    firewall_defined
    not firewall_logging_enabled
    msg := "3.1.5 No logging on deny rules — blocked traffic not auditable"
}

section_3_violations contains msg if {
    not source_routing_disabled
    msg := "3.1.6 IP source routing not explicitly disabled"
}

# ── Section 4: User Account Security ─────────────────────────────────────────

# 4.1.1  Default 'vyos' user has a non-default password (hashed, not plain)
default_user_secured if {
    user := input.system.login.user.vyos
    user.authentication["encrypted-password"]
    user.authentication["encrypted-password"] != "$6$defaultvyos"
}

default_user_secured if {
    not input.system.login.user.vyos   # renamed away from default
}

# 4.1.2  All users have encrypted passwords (not plaintext)
all_users_encrypted if {
    every _, user in input.system.login.user {
        user.authentication["encrypted-password"]
        not user.authentication["plaintext-password"]
    }
}

# 4.1.3  No operator-level users with admin capabilities beyond their role
operator_accounts_scoped if {
    every _, user in input.system.login.user {
        user.level == "admin"   # all accounts explicitly admin or operator
    }
}

section_4_violations contains msg if {
    not default_user_secured
    msg := "4.1.1 Default 'vyos' user present with potentially default credentials"
}

section_4_violations contains msg if {
    not all_users_encrypted
    msg := "4.1.2 One or more user accounts use plaintext passwords"
}

# ── Section 5: System Hardening ───────────────────────────────────────────────

# 5.1.1  Hostname not default
hostname_configured if {
    input.system["host-name"]
    input.system["host-name"] != "vyos"
    count(input.system["host-name"]) > 3
}

# 5.1.2  Timezone explicitly configured
timezone_configured if {
    input.system["time-zone"]
    input.system["time-zone"] != ""
}

# 5.1.3  Console timeout configured (security console)
console_timeout if {
    timeout_str := input.system.console.device["ttyS0"]["timeout-login"]
    to_number(timeout_str) <= 300
}

# 5.1.4  System domain name configured
domain_configured if {
    input.system["domain-name"]
    count(input.system["domain-name"]) > 0
}

section_5_violations contains msg if {
    not hostname_configured
    msg := "5.1.1 Default hostname 'vyos' not changed — device not identifiable"
}

section_5_violations contains msg if {
    not timezone_configured
    msg := "5.1.2 Timezone not configured — timestamps unreliable for forensics"
}

section_5_violations contains msg if {
    not console_timeout
    msg := "5.1.3 Console login timeout not configured or exceeds 300 seconds"
}

# ── Aggregate violations ──────────────────────────────────────────────────────

violations := array.concat(
    array.concat(
        array.concat(
            [v | some v in section_1_violations],
            [v | some v in section_2_violations]
        ),
        array.concat(
            [v | some v in section_3_violations],
            [v | some v in section_4_violations]
        )
    ),
    [v | some v in section_5_violations]
)

compliant if {
    count(violations) == 0
}

# ── Compliance report ─────────────────────────────────────────────────────────

total_controls := 20

_overall_compliance := "PASS" if { compliant }
_overall_compliance := "FAIL" if { not compliant }

compliance_assessment := {
    "compliant": count(violations) == 0,
    "summary": {
        "total_controls":        total_controls,
        "passing_controls":      total_controls - count(violations),
        "failing_controls":      count(violations),
        "compliance_percentage": ((total_controls - count(violations)) * 100) / total_controls,
        "overall_compliance":    _overall_compliance,
    },
    "violations": violations,
    "section_compliance": {
        "1_ssh_access":        count(section_1_violations) == 0,
        "2_mgmt_services":     count(section_2_violations) == 0,
        "3_firewall":          count(section_3_violations) == 0,
        "4_user_accounts":     count(section_4_violations) == 0,
        "5_system_hardening":  count(section_5_violations) == 0,
    },
    "device_info": {
        "hostname": object.get(input.system, "host-name", "unknown"),
        "version":  object.get(input, "version", "unknown"),
        "platform": "vyos",
        "timezone": object.get(input.system, "time-zone", "unknown"),
    },
}
