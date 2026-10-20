# METADATA
# title: "CIS pfSense Firewall Benchmark v1.1.1"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, pfsense]
#   coverage:
#     checks: 72
#     cited: 35
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_pfsense

# CIS pfSense Firewall Benchmark v1.1.1: all 33 recommendations (30 Level 1, 3 Level 2).
# pfSense only. OPNsense is a separate product and will get its own package.
#
# Every recommendation in v1.1.1 is "Manual" in the CIS workbook (the audit is a GUI/CLI review).
# Where pfSense's config.xml holds the setting the audit looks at, this policy evaluates that
# setting directly and fails closed when the section was not collected. The rest need a person
# to review them, and they pass only on an explicit attestation boolean
# (input.attest.<name> == true).
#
# Input contract (config.xml parsed to JSON; a single repeated element may arrive as an object):
#   input.system            : hostname, dnsserver, timezone, timeservers, ipv6allow,
#                             disableconsolemenu, sshguard_threshold, sshguard_blocktime,
#                             authserver[], webgui.{protocol, session_timeout, nodnsrebindcheck}
#   input.filter.rule[]     : firewall rules (type, disabled, source, destination, protocol, icmptype, log)
#   input.snmpd             : trapenable, trapserver
#   input.unbound           : dnssec
#   input.syslog / input.syslogd : enable, remoteserver[2|3]  (real pfSense uses "syslog"; the
#                             current collector maps it as "syslogd", so either is accepted)
#   input.hasync            : synchronizetoip
#   input.openvpn           : {"openvpn-server": [ {mode, authmode, data_ciphers, digest, disabled} ]}
#   input.sshd_config       : text of /etc/ssh/sshd_config      (1.1)
#   input.motd              : text of /etc/motd                 (1.3)
#   input.attest.*          : attestation booleans for the review-only recommendations
#
# Checkbox flags in config.xml are present-or-absent; a present flag may arrive as "" or a value.
#
# OPA endpoint used by the collector: POST /v1/data/cis_pfsense/compliance_assessment

import rego.v1

default compliant := false

compliant if count(violations) == 0

# ── Recommendation table (ids, titles and profiles from the v1.1.1 workbook) ──────────────

controls := {
	"1.1": {"section": "1", "level": 1, "title": "Ensure SSH warning banner is configured"},
	"1.2": {"section": "1", "level": 1, "title": "Ensure AutoConfigBackup is enable"},
	"1.3": {"section": "1", "level": 1, "title": "Ensure 'Message Of The Day (MOTD)' is set"},
	"1.4": {"section": "1", "level": 1, "title": "Ensure Hostname is set"},
	"1.5": {"section": "1", "level": 1, "title": "Ensure DNS server is configured"},
	"1.6": {"section": "1", "level": 1, "title": "Ensure IPv6 is disabled if not used"},
	"1.7": {"section": "1", "level": 1, "title": "Ensure 'DNS Rebind Check' is unchecked"},
	"1.8": {"section": "1", "level": 1, "title": "Ensure Web Management is Set to use HTTPS"},
	"1.9": {"section": "1", "level": 1, "title": "Ensure a synchronized High Availability peer is configured"},
	"2.1": {"section": "2", "level": 1, "title": "Ensure Sessions Timeout is set to less than or equal to 10 Minutes"},
	"2.2": {"section": "2", "level": 1, "title": "Ensure LDAP or RADIUS server configured"},
	"2.3": {"section": "2", "level": 1, "title": "Ensure Console Menu is Password Protected"},
	"2.4": {"section": "2", "level": 1, "title": "Ensure all default accounts are either disabled or utilize strong passwords"},
	"3.1": {"section": "3", "level": 1, "title": "Ensure 'Local Account status' is set to 'Disabled'"},
	"3.2": {"section": "3", "level": 1, "title": "Ensure Login Protection Threshold is set to 30 or less"},
	"3.3": {"section": "3", "level": 2, "title": "Ensure Allow access again after time is set to 300 or more second"},
	"3.4": {"section": "3", "level": 1, "title": "Ensure default password of admin is changed"},
	"4.1.1": {"section": "4", "level": 1, "title": "Ensure no Allow Rule with Any in Destination Field present in the Firewall Rules"},
	"4.1.2": {"section": "4", "level": 1, "title": "Ensure no Allow Rule with Any in Source field present in the Firewall Rules"},
	"4.1.3": {"section": "4", "level": 1, "title": "Ensure no Allow Rule with Any in Services field present in the Firewall Rules"},
	"4.1.4": {"section": "4", "level": 1, "title": "Ensure there are no Unused Policies"},
	"4.1.5": {"section": "4", "level": 1, "title": "Ensure Logging is Enable for All Firewall Rules"},
	"4.1.6": {"section": "4", "level": 1, "title": "Ensure ICMP Request is securely configured"},
	"5.1.1": {"section": "5", "level": 1, "title": "Ensure SNMP traps receivers is set"},
	"5.1.2": {"section": "5", "level": 1, "title": "Ensure SNMP traps is enabled"},
	"5.1.3": {"section": "5", "level": 2, "title": "Ensure that the add-on package NET-SNMP is installed and configured securely"},
	"5.2.1": {"section": "5", "level": 1, "title": "Ensure time zone is properly configured"},
	"5.3.1": {"section": "5", "level": 1, "title": "Ensure 'DNSSEC' is Enable on DNS Service"},
	"5.4.1": {"section": "5", "level": 1, "title": "Ensure RADIUS or LDAP are being used for VPN Authentication"},
	"5.4.2": {"section": "5", "level": 1, "title": "Apply a Trusted Signed Certificate for VPN Portal"},
	"5.4.3": {"section": "5", "level": 2, "title": "Ensure that OpenVPN is configured to use TLS encryption for secure communications."},
	"5.5.1": {"section": "5", "level": 1, "title": "Ensure that OpenVPN use strong ciphers or hashing algorithms"},
	"6.1": {"section": "6", "level": 1, "title": "Ensure syslog is configured"},
}

# Review-only recommendations: control id -> attestation key under input.attest.
attestations := {
	"1.2": "autoconfigbackup_enabled",
	"2.4": "default_accounts_secured",
	"3.1": "local_accounts_disabled",
	"3.4": "admin_default_password_changed",
	"4.1.4": "unused_rules_reviewed",
	"5.1.3": "net_snmp_secured",
	"5.4.2": "vpn_portal_certificate_trusted",
}

# ── Helpers ───────────────────────────────────────────────────────────────────────────

# config.xml -> JSON gives a single repeated element as an object, several as an array.
as_list(x) := x if {
	is_array(x)
} else := [x] if {
	is_object(x)
} else := []

# A value that may be one string or a list of strings.
as_strings(x) := [s | some s in x; is_string(s)] if {
	is_array(x)
} else := [x] if {
	is_string(x)
} else := []

# A config.xml checkbox flag is set when the key is present (an unchecked box is removed from
# config.xml) and not an explicit "off" value. An empty element may arrive as "" or null; both mean set.
flag(obj, key) if {
	is_object(obj)
	key in object.keys(obj)
	not obj[key] in {"0", false, "no", "off", "disabled"}
}

nonblank(x) if {
	is_string(x)
	trim_space(x) != ""
}

nonempty_object(x) if {
	is_object(x)
	count(x) > 0
}

is_digits(x) if {
	is_string(x)
	regex.match(`^[0-9]+$`, trim_space(x))
}

is_digits(x) if is_number(x)

attested(key) if input.attest[key] == true

system_collected if nonempty_object(input.system)

webgui_collected if nonempty_object(input.system.webgui)

snmpd_collected if nonempty_object(input.snmpd)

unbound_collected if nonempty_object(input.unbound)

hasync_collected if nonempty_object(input.hasync)

# The collector defaults filter to {"rule": []} when config.xml is not read, so an empty
# rule list is not evidence: it reports as missing, never as a pass.
filter_collected if count(all_rules) > 0

openvpn_collected if {
	is_object(input.openvpn)
	"openvpn-server" in object.keys(input.openvpn)
}

sshd_config_collected if is_string(input.sshd_config)

motd_collected if is_string(input.motd)

# Real pfSense keeps remote logging under "syslog"; the current collector maps "syslogd".
# (helper rule, not `not f(input.syslog)`: that is undefined when the key is absent)
syslog_key_collected if nonempty_object(input.syslog)

syslog_section := input.syslog if syslog_key_collected

syslog_section := input.syslogd if {
	not syslog_key_collected
	nonempty_object(input.syslogd)
}

syslog_collected if syslog_section

# ── Section 1: General Setting Policy ─────────────────────────────────────────────────

# 1.1: the first non-comment Banner directive in sshd_config names a file (not "none").
banner_lines := [t |
	some l in split(input.sshd_config, "\n")
	t := trim_space(l)
	not startswith(t, "#")
	regex.match(`(?i)^Banner\s+\S+`, t)
]

default ok_1_1 := false

ok_1_1 if {
	count(banner_lines) > 0
	m := regex.find_all_string_submatch_n(`(?i)^Banner\s+(\S+)`, banner_lines[0], 1)
	lower(m[0][1]) != "none"
}

# 1.3: /etc/motd carries site text, not the stock FreeBSD welcome.
default ok_1_3 := false

ok_1_3 if {
	nonblank(input.motd)
	not contains(lower(input.motd), "welcome to freebsd")
}

# 1.4: hostname set and changed from the factory default.
default ok_1_4 := false

ok_1_4 if {
	nonblank(input.system.hostname)
	lower(trim_space(input.system.hostname)) != "pfsense"
}

# 1.5: at least one DNS server configured.
default ok_1_5 := false

ok_1_5 if count([s | some s in as_strings(input.system.dnsserver); trim_space(s) != ""]) > 0

# 1.6: "Allow IPv6" is off, or the organization attests IPv6 is in use.
default ok_1_6 := false

ok_1_6 if {
	system_collected
	not flag(input.system, "ipv6allow")
}

ok_1_6 if {
	system_collected
	attested("ipv6_required")
}

# 1.7: "Disable DNS Rebinding Checks" left unchecked, i.e. rebind protection stays on.
default ok_1_7 := false

ok_1_7 if {
	webgui_collected
	not flag(input.system.webgui, "nodnsrebindcheck")
}

# 1.8: webConfigurator protocol is HTTPS.
default ok_1_8 := false

ok_1_8 if lower(input.system.webgui.protocol) == "https"

# 1.9: config sync to an HA peer is configured.
default ok_1_9 := false

ok_1_9 if nonblank(input.hasync.synchronizetoip)

s1_evidence contains "1.1: evidence missing — input.sshd_config not collected" if not sshd_config_collected

s1_evidence contains "1.3: evidence missing — input.motd not collected" if not motd_collected

s1_evidence contains sprintf("%s: evidence missing — input.system not collected", [id]) if {
	not system_collected
	some id in ["1.4", "1.5", "1.6"]
}

s1_evidence contains sprintf("%s: evidence missing — input.system.webgui not collected", [id]) if {
	not webgui_collected
	some id in ["1.7", "1.8"]
}

s1_evidence contains "1.9: evidence missing — input.hasync not collected" if not hasync_collected

section_1_violations contains v if some v in s1_evidence

section_1_violations contains "1.1: SSH login banner not configured (no Banner directive, or Banner none)" if {
	sshd_config_collected
	not ok_1_1
}

section_1_violations contains "1.3: message of the day is empty or still the stock FreeBSD text" if {
	motd_collected
	not ok_1_3
}

section_1_violations contains "1.4: hostname is unset or still the factory default 'pfSense'" if {
	system_collected
	not ok_1_4
}

section_1_violations contains "1.5: no DNS server configured under System > General Setup" if {
	system_collected
	not ok_1_5
}

section_1_violations contains "1.6: IPv6 is allowed and IPv6 use is not attested (input.attest.ipv6_required)" if {
	system_collected
	not ok_1_6
}

section_1_violations contains "1.7: DNS rebinding checks are disabled on the webConfigurator" if {
	webgui_collected
	not ok_1_7
}

section_1_violations contains "1.8: webConfigurator does not use HTTPS" if {
	webgui_collected
	not ok_1_8
}

section_1_violations contains "1.9: no High Availability sync peer (synchronizetoip) configured" if {
	hasync_collected
	not ok_1_9
}

# ── Section 2: Users Management ───────────────────────────────────────────────────────

# 2.1: session timeout 1..10 minutes. Blank means the pfSense default (240), 0 means never.
default ok_2_1 := false

ok_2_1 if {
	t := input.system.webgui.session_timeout
	is_digits(t)
	n := to_number(trim_space(sprintf("%v", [t])))
	n > 0
	n <= 10
}

# 2.2: an LDAP or RADIUS authentication server exists.
ldap_radius_servers := {s.name |
	some s in as_list(input.system.authserver)
	is_object(s)
	lower(object.get(s, "type", "")) in {"ldap", "radius"}
	is_string(s.name)
}

default ok_2_2 := false

ok_2_2 if {
	some s in as_list(input.system.authserver)
	is_object(s)
	lower(object.get(s, "type", "")) in {"ldap", "radius"}
}

# 2.3: "Password protect the console menu" is checked.
default ok_2_3 := false

ok_2_3 if flag(input.system, "disableconsolemenu")

s2_evidence contains "2.1: evidence missing — input.system.webgui not collected" if not webgui_collected

s2_evidence contains sprintf("%s: evidence missing — input.system not collected", [id]) if {
	not system_collected
	some id in ["2.2", "2.3"]
}

section_2_violations contains v if some v in s2_evidence

section_2_violations contains "2.1: webConfigurator session timeout is blank (240 min default), 0 (never) or over 10 minutes" if {
	webgui_collected
	not ok_2_1
}

section_2_violations contains "2.2: no LDAP or RADIUS authentication server configured" if {
	system_collected
	not ok_2_2
}

section_2_violations contains "2.3: console menu is not password protected" if {
	system_collected
	not ok_2_3
}

# ── Section 3: Password Policy ────────────────────────────────────────────────────────

# 3.2: login protection threshold 1..30. Blank means the pfSense default of 30.
default ok_3_2 := false

ok_3_2 if {
	system_collected
	not nonblank(object.get(input.system, "sshguard_threshold", ""))
	not is_number(object.get(input.system, "sshguard_threshold", ""))
}

ok_3_2 if {
	t := input.system.sshguard_threshold
	is_digits(t)
	n := to_number(trim_space(sprintf("%v", [t])))
	n > 0
	n <= 30
}

# 3.3: login protection block time at least 300 s. Blank means the pfSense default of 120.
default ok_3_3 := false

ok_3_3 if {
	t := input.system.sshguard_blocktime
	is_digits(t)
	to_number(trim_space(sprintf("%v", [t]))) >= 300
}

section_3_violations contains sprintf("%s: evidence missing — input.system not collected", [id]) if {
	not system_collected
	some id in ["3.2", "3.3"]
}

section_3_violations contains "3.2: login protection threshold is above 30 or not a positive number" if {
	system_collected
	not ok_3_2
}

section_3_violations contains "3.3: login protection block time is unset (120 s default) or under 300 seconds" if {
	system_collected
	not ok_3_3
}

# ── Section 4: Firewall Policy ────────────────────────────────────────────────────────

all_rules := [r | some r in as_list(input.filter.rule); is_object(r)]

active_rules := [r | some r in all_rules; not flag(r, "disabled")]

# pfSense writes type on every rule; treat a missing type as an allow (fail closed).
allow_rules := [r | some r in active_rules; lower(object.get(r, "type", "pass")) == "pass"]

# A side with no element, or with an <any/> child, is unrestricted.
side_any(r, side) if not r[side]

side_any(r, side) if {
	is_object(r[side])
	"any" in object.keys(r[side])
}

dest_port_set(r) if nonblank(r.destination.port)

rule_label(r) := sprintf("%v/%v", [object.get(r, "interface", "?"), object.get(r, "descr", object.get(r, "tracker", "?"))])

# Service "any": no protocol, or TCP/UDP with no destination port.
service_any(r) if lower(object.get(r, "protocol", "")) in {"", "any"}

service_any(r) if {
	lower(object.get(r, "protocol", "")) in {"tcp", "udp", "tcp/udp"}
	not dest_port_set(r)
}

icmp_any(r) if {
	lower(object.get(r, "protocol", "")) in {"icmp", "ipv6-icmp", "icmp6"}
	types := [t | some t in split(sprintf("%v", [object.get(r, "icmptype", "")]), ","); trim_space(t) != ""]
	count(types) == 0
}

icmp_any(r) if {
	lower(object.get(r, "protocol", "")) in {"icmp", "ipv6-icmp", "icmp6"}
	some t in split(sprintf("%v", [object.get(r, "icmptype", "")]), ",")
	lower(trim_space(t)) == "any"
}

section_4_violations contains sprintf("%s: evidence missing — input.filter.rule not collected", [id]) if {
	not filter_collected
	some id in ["4.1.1", "4.1.2", "4.1.3", "4.1.5", "4.1.6"]
}

section_4_violations contains sprintf("4.1.1: allow rule %s has Any as destination", [rule_label(r)]) if {
	some r in allow_rules
	side_any(r, "destination")
}

section_4_violations contains sprintf("4.1.2: allow rule %s has Any as source", [rule_label(r)]) if {
	some r in allow_rules
	side_any(r, "source")
}

section_4_violations contains sprintf("4.1.3: allow rule %s permits any service (no protocol, or TCP/UDP with no destination port)", [rule_label(r)]) if {
	some r in allow_rules
	service_any(r)
}

section_4_violations contains sprintf("4.1.5: rule %s does not log matched packets", [rule_label(r)]) if {
	some r in active_rules
	not flag(r, "log")
}

section_4_violations contains sprintf("4.1.6: ICMP allow rule %s does not restrict ICMP types", [rule_label(r)]) if {
	some r in allow_rules
	icmp_any(r)
}

# ── Section 5: Service Configuration ──────────────────────────────────────────────────

default ok_5_1_1 := false

ok_5_1_1 if {
	flag(input.snmpd, "trapenable")
	nonblank(input.snmpd.trapserver)
}

default ok_5_1_2 := false

ok_5_1_2 if flag(input.snmpd, "trapenable")

# 5.2.1: the title asks for the time zone, the audit for NTP; both are checked.
default ok_5_2_1 := false

ok_5_2_1 if {
	nonblank(input.system.timezone)
	count([s | some s in as_strings(input.system.timeservers); trim_space(s) != ""]) > 0
}

default ok_5_3_1 := false

ok_5_3_1 if flag(input.unbound, "dnssec")

vpn_servers := [s | some s in as_list(input.openvpn["openvpn-server"]); is_object(s); not flag(s, "disabled")]

vpn_label(s) := sprintf("%v", [object.get(s, "description", object.get(s, "vpnid", "?"))])

# 5.4.1: a server that authenticates users must name an LDAP/RADIUS server in authmode.
user_auth_modes := {"server_user", "server_tls_user"}

vpn_uses_directory(s) if {
	some a in split(sprintf("%v", [object.get(s, "authmode", "")]), ",")
	trim_space(a) in ldap_radius_servers
}

# 5.4.3: shared-key modes do not use TLS.
tls_modes := {"p2p_tls", "server_tls", "server_user", "server_tls_user"}

# 5.5.1: AEAD data ciphers and SHA-2 auth digests.
strong_ciphers := {"AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"}

strong_digests := {"SHA256", "SHA384", "SHA512"}

vpn_ciphers(s) := [upper(trim_space(c)) | some c in split(sprintf("%v", [object.get(s, "data_ciphers", "")]), ","); trim_space(c) != ""]

vpn_ciphers_strong(s) if {
	cs := vpn_ciphers(s)
	count(cs) > 0
	every c in cs { c in strong_ciphers }
}

vpn_digest_strong(s) if upper(trim_space(sprintf("%v", [object.get(s, "digest", "")]))) in strong_digests

section_5_violations contains sprintf("%s: evidence missing — input.snmpd not collected", [id]) if {
	not snmpd_collected
	some id in ["5.1.1", "5.1.2"]
}

section_5_violations contains "5.2.1: evidence missing — input.system not collected" if not system_collected

section_5_violations contains "5.3.1: evidence missing — input.unbound not collected" if not unbound_collected

section_5_violations contains sprintf("%s: evidence missing — input.openvpn not collected", [id]) if {
	not openvpn_collected
	some id in ["5.4.1", "5.4.3", "5.5.1"]
}

section_5_violations contains "5.1.1: SNMP traps are off or no trap receiver is configured" if {
	snmpd_collected
	not ok_5_1_1
}

section_5_violations contains "5.1.2: SNMP traps are not enabled" if {
	snmpd_collected
	not ok_5_1_2
}

section_5_violations contains "5.2.1: time zone or NTP time servers not configured" if {
	system_collected
	not ok_5_2_1
}

section_5_violations contains "5.3.1: DNSSEC is not enabled on the DNS Resolver" if {
	unbound_collected
	not ok_5_3_1
}

section_5_violations contains sprintf("5.4.1: OpenVPN server %s authenticates users without an LDAP/RADIUS server", [vpn_label(s)]) if {
	openvpn_collected
	some s in vpn_servers
	lower(object.get(s, "mode", "")) in user_auth_modes
	not vpn_uses_directory(s)
}

section_5_violations contains sprintf("5.4.3: OpenVPN server %s does not use a TLS mode", [vpn_label(s)]) if {
	openvpn_collected
	some s in vpn_servers
	not lower(object.get(s, "mode", "")) in tls_modes
}

section_5_violations contains sprintf("5.5.1: OpenVPN server %s allows a non-AEAD data cipher or none is set", [vpn_label(s)]) if {
	openvpn_collected
	some s in vpn_servers
	not vpn_ciphers_strong(s)
}

section_5_violations contains sprintf("5.5.1: OpenVPN server %s uses a weak or unset auth digest", [vpn_label(s)]) if {
	openvpn_collected
	some s in vpn_servers
	not vpn_digest_strong(s)
}

# ── Section 6: Logging ────────────────────────────────────────────────────────────────

default ok_6_1 := false

ok_6_1 if {
	flag(syslog_section, "enable")
	some k in ["remoteserver", "remoteserver2", "remoteserver3"]
	nonblank(syslog_section[k])
}

section_6_violations contains "6.1: evidence missing — input.syslog / input.syslogd not collected" if not syslog_collected

section_6_violations contains "6.1: remote syslog is not enabled or has no remote server" if {
	syslog_collected
	not ok_6_1
}

# ── Review-only recommendations (attestation) ─────────────────────────────────────────

attestation_violations contains sprintf("%s: not attested — manual review required, set input.attest.%s to true", [id, key]) if {
	some id, key in attestations
	not attested(key)
}

# ── Aggregate ─────────────────────────────────────────────────────────────────────────

_all_violations := (((((section_1_violations | section_2_violations) | section_3_violations) | section_4_violations) | section_5_violations) | section_6_violations) | attestation_violations

violations := sort([v | some v in _all_violations])

control_id(v) := regex.find_n(`^[0-9]+(\.[0-9]+)*`, v, 1)[0]

evaluated_controls := {id | some id, _ in controls}

total_controls := count(evaluated_controls)

# Distinct failing controls (a control can emit more than one message).
failing_controls := {control_id(v) | some v in violations}

section_names := {
	"1": "1_general_settings",
	"2": "2_users_management",
	"3": "3_password_policy",
	"4": "4_firewall_policy",
	"5": "5_service_configuration",
	"6": "6_logging",
}

section_compliance := {name: ok |
	some sec, name in section_names
	ok := count({id | some id in failing_controls; controls[id].section == sec}) == 0
}

_overall_compliance := "PASS" if compliant

_overall_compliance := "FAIL" if not compliant

compliance_assessment := {
	"compliant": compliant,
	"benchmark": "CIS pfSense Firewall Benchmark v1.1.1",
	"summary": {
		"total_controls": total_controls,
		"controls_evaluated": total_controls,
		"passing_controls": total_controls - count(failing_controls),
		"failing_controls": count(failing_controls),
		"compliance_percentage": ((total_controls - count(failing_controls)) * 100) / total_controls,
		"overall_compliance": _overall_compliance,
	},
	"violations": violations,
	"section_compliance": section_compliance,
	"device_info": {
		# object.get on {} keeps the report defined when input.system is missing.
		"hostname": object.get(object.get(input, "system", {}), "hostname", "unknown"),
		"domain": object.get(object.get(input, "system", {}), "domain", "unknown"),
		"version": object.get(input, "version", "unknown"),
		"platform": object.get(input, "platform", "pfsense"),
	},
}
