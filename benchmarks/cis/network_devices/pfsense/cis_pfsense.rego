package cis_pfsense

# CIS pfSense / OPNsense Firewall Hardening Benchmark v1.0.0
# Applies to pfSense Community Edition 2.6/2.7 and OPNsense 23/24
#
# Input structure (parsed from /cf/conf/config.xml via SSH):
#   input.system              — hostname, webgui, ssh, ntpd, dnsmasq/unbound
#   input.filter.rule[]       — firewall rules (interface, action, type)
#   input.interfaces          — WAN, LAN, OPT interface configs
#   input.snmpd               — SNMP daemon config
#   input.syslogd             — syslog config
#   input.installedpackages   — installed packages (pfSense)
#   input.version             — pfSense/OPNsense version string
#   input.platform            — "pfsense" or "opnsense"
#
# OPA endpoint: POST http://192.168.4.62:8181/v1/data/cis_pfsense/compliance_assessment

import rego.v1

default compliant := false

# ── Section 1: Admin Interface Security ──────────────────────────────────────

# 1.1.1  WebGUI enforces HTTPS only
https_enforced if {
    input.system.webgui.protocol == "https"
}

# 1.1.2  HTTP redirect to HTTPS enabled
http_redirect if {
    input.system.webgui.protocol == "https"
    not input.system.webgui["nohttpreferercheck"]
}

# 1.1.3  WebGUI on non-default port (optional but recommended)
nondefault_gui_port if {
    input.system.webgui.port
    input.system.webgui.port != "443"
    input.system.webgui.port != "80"
}

nondefault_gui_port if {
    # Acceptable if on 443 HTTPS with other controls in place
    input.system.webgui.protocol == "https"
}

# 1.1.4  SSH enabled with key authentication (not password only)
ssh_configured if {
    input.system.ssh.enable == "enabled"
}

ssh_key_auth if {
    ssh_configured
    input.system.ssh.authmode
    contains(input.system.ssh.authmode, "key")
}

ssh_key_auth if {
    ssh_configured
    # No explicit authmode means key+pass allowed; check for key files
    some user in input.system.user
    user.authorizedkeys
    count(user.authorizedkeys) > 0
}

# 1.1.5  Console password protection enabled
console_protected if {
    input.system["disableconsolemenu"] == "1"
}

console_protected if {
    not input.system.disableconsolemenu  # default is protected
}

# 1.1.6  Login protection (lockout) enabled
login_protection if {
    not input.system["disableloginprotection"]
}

# 1.1.7  Session timeout configured (≤ 240 minutes)
session_timeout_ok if {
    timeout_str := input.system.webgui["sessiontimeout"]
    timeout := to_number(timeout_str)
    timeout > 0
    timeout <= 240
}

section_1_violations contains msg if {
    not https_enforced
    msg := "1.1.1 WebGUI not using HTTPS — admin credentials transmitted in plaintext"
}

section_1_violations contains msg if {
    not ssh_configured
    not input.system.webgui   # must have SOME management access
    msg := "1.1.4 No management interface (SSH or WebGUI) configured"
}

section_1_violations contains msg if {
    ssh_configured
    not ssh_key_auth
    msg := "1.1.4 SSH enabled with password-only auth — enable key authentication"
}

section_1_violations contains msg if {
    not login_protection
    msg := "1.1.6 Login protection (brute-force lockout) disabled"
}

section_1_violations contains msg if {
    not session_timeout_ok
    msg := "1.1.7 WebGUI session timeout not configured or exceeds 240 minutes"
}

# ── Section 2: Firewall Rules ─────────────────────────────────────────────────

# 2.1.1  Block RFC1918 on WAN interface
block_rfc1918_wan if {
    some rule in input.filter.rule
    rule.interface == "wan"
    rule.type == "block"
    contains(lower(rule.descr), "rfc1918")
}

block_rfc1918_wan if {
    # pfSense has built-in "Block private networks" option
    wan := input.interfaces.wan
    wan["blockpriv"] == "1"
}

# 2.1.2  Block bogon networks on WAN
block_bogons_wan if {
    wan := input.interfaces.wan
    wan["blockbogons"] == "1"
}

# 2.1.3  Default deny inbound on WAN (no allow-all rule)
no_wan_allow_all if {
    not any_rule_allows_all_wan
}

any_rule_allows_all_wan if {
    some rule in input.filter.rule
    rule.interface == "wan"
    rule.type == "pass"
    not rule.source
    not rule.destination
}

# 2.1.4  Firewall logging enabled on at least block rules
firewall_logging if {
    some rule in input.filter.rule
    rule.type == "block"
    rule.log == "1"
}

# 2.1.5  Scrub (packet normalisation) enabled
scrub_enabled if {
    not input.system["disablescrub"]
}

# 2.1.6  State table size explicitly configured (prevents resource exhaustion)
state_table_configured if {
    input.system.maximumstates
    to_number(input.system.maximumstates) > 0
}

section_2_violations contains msg if {
    not block_rfc1918_wan
    msg := "2.1.1 RFC1918 private addresses not blocked on WAN interface"
}

section_2_violations contains msg if {
    not block_bogons_wan
    msg := "2.1.2 Bogon networks not blocked on WAN interface"
}

section_2_violations contains msg if {
    not no_wan_allow_all
    msg := "2.1.3 Allow-all rule exists on WAN — firewall is effectively disabled"
}

section_2_violations contains msg if {
    not firewall_logging
    msg := "2.1.4 No logging on block rules — denied traffic not auditable"
}

section_2_violations contains msg if {
    not scrub_enabled
    msg := "2.1.5 Packet scrubbing (normalisation) disabled — fragmentation attacks possible"
}

# ── Section 3: Management Services ───────────────────────────────────────────

# 3.1.1  SNMP disabled or SNMPv3 only
snmp_secure if {
    not input.snmpd.enable
}

snmp_secure if {
    input.snmpd.enable == "0"
}

snmp_secure if {
    input.snmpd.enable == "1"
    input.snmpd.rocommunity == ""   # no v1/v2c read community
}

# 3.1.2  NTP configured with at least one external server
ntp_configured if {
    count(input.system.timeservers) >= 1
    some server in input.system.timeservers
    not contains(server, "localhost")
}

# 3.1.3  Remote syslog configured
syslog_remote if {
    input.syslogd.remoteserver
    count(input.syslogd.remoteserver) > 0
}

syslog_remote if {
    input.syslogd.enable == "1"
    input.syslogd.remoteserver
}

# 3.1.4  DNS resolver (unbound) configured, not forwarder in simple mode
dns_resolver if {
    input.unbound.enable == "on"
}

dns_resolver if {
    input.unbound.enable == "1"
}

# 3.1.5  UPnP/NAT-PMP disabled
upnp_disabled if {
    not input.installedpackages["miniupnpd"]
}

upnp_disabled if {
    input.miniupnpd.enable == "0"
}

upnp_disabled if {
    not input.miniupnpd
}

section_3_violations contains msg if {
    not snmp_secure
    msg := "3.1.1 SNMP v1/v2c enabled with community string — use SNMPv3 or disable"
}

section_3_violations contains msg if {
    not ntp_configured
    msg := "3.1.2 NTP not configured — accurate timestamps required for log correlation"
}

section_3_violations contains msg if {
    not syslog_remote
    msg := "3.1.3 Remote syslog not configured — logs lost if device is compromised"
}

section_3_violations contains msg if {
    not upnp_disabled
    msg := "3.1.5 UPnP/miniupnpd enabled — allows internal hosts to open firewall ports"
}

# ── Section 4: System Hardening ───────────────────────────────────────────────

# 4.1.1  Hostname not default
hostname_configured if {
    input.system.hostname
    input.system.hostname != "pfSense"
    input.system.hostname != "OPNsense"
    count(input.system.hostname) > 3
}

# 4.1.2  Domain name configured
domain_configured if {
    input.system.domain
    input.system.domain != "localdomain"
    count(input.system.domain) > 3
}

# 4.1.3  Crash reporter disabled (avoids leaking info to vendor)
crash_reporter_disabled if {
    input.system["crashreporterapi"] == "0"
}

crash_reporter_disabled if {
    not input.system["crashreporterapi"]  # not configured = disabled by default in some versions
}

# 4.1.4  Timezone explicitly set
timezone_set if {
    input.system.timezone
    input.system.timezone != ""
    input.system.timezone != "Etc/UTC"  # UTC is fine but should be explicit
}

timezone_set if {
    input.system.timezone == "Etc/UTC"  # explicitly set to UTC is acceptable
    input.system.timezone != ""
}

section_4_violations contains msg if {
    not hostname_configured
    msg := "4.1.1 Default hostname 'pfSense' or 'OPNsense' not changed"
}

section_4_violations contains msg if {
    not domain_configured
    msg := "4.1.2 Default domain 'localdomain' not changed — use a proper domain name"
}

# ── Section 5: Package & Update Management ────────────────────────────────────

# 5.1.1  No packages with known vulnerabilities (placeholder — flag if vuln_list present)
no_vulnerable_packages if {
    not input.vulnerable_packages
}

no_vulnerable_packages if {
    count(input.vulnerable_packages) == 0
}

# 5.1.2  Captive portal disabled if not in use
captive_portal_disabled if {
    not input.captiveportal
}

captive_portal_disabled if {
    every _, config in input.captiveportal {
        config.enable == "0"
    }
}

section_5_violations contains msg if {
    not no_vulnerable_packages
    msg := "5.1.1 Packages with known vulnerabilities detected — update immediately"
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

total_controls := 22

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
        "1_admin_access":     count(section_1_violations) == 0,
        "2_firewall_rules":   count(section_2_violations) == 0,
        "3_mgmt_services":    count(section_3_violations) == 0,
        "4_system_hardening": count(section_4_violations) == 0,
        "5_packages":         count(section_5_violations) == 0,
    },
    "device_info": {
        "hostname": object.get(input.system, "hostname", "unknown"),
        "domain":   object.get(input.system, "domain",   "unknown"),
        "version":  object.get(input,        "version",  "unknown"),
        "platform": object.get(input,        "platform", "pfsense"),
    },
}
