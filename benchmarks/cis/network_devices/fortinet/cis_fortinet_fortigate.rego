# METADATA
# title: "CIS FortiGate 7.4.x Benchmark v1.0.1"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, fortinet]
#   coverage:
#     checks: 73
#     cited: 73
#     expected: 64
#     found: 73
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_fortinet_fortigate

# CIS FortiGate 7.4.x Benchmark v1.0.1
# Rewritten 2026-10-20 from the CIS workbook. The previous module claimed "Fortinet FortiGate Benchmark v1.3.0"; its 8
# control ids do not match the FortiGate 7.4.x numbering (e.g. its 1.1 checked the admin GUI TLS version, which is
# 7.4.x 2.1.10; 7.4.x 1.1 is the DNS server).
# 64 recommendations (48 Automated, 16 Manual), every one in the benchmark; ids, levels
# and assessment status read from the workbook. All levels are evaluated; `recommendations` lists each id's level.
# Automated checks fail closed: facts not collected => "<id>: evidence missing — <field> not collected".
# Manual recommendations with a decidable configuration fact are checked like Automated ones:
#   1.2, 1.3, 2.1.4, 2.3.2, 2.4.2, 4.1.2, 4.2.2, 4.5.1, 4.5.3, 4.5.4, 5.2.1.1, 7.3.2, 7.3.3.
# Manual recommendations that need a human judgement carry an attestation boolean under
#   input.fortigate_config.attest (not attested => violation): 2.1.6, 2.4.3, 3.1.
# 7.3.2 and 7.3.3 carry the same title and audit in the workbook; both are kept as separate ids with the same check.
# 3.2 applies to accept policies (3.3 itself asks for deny policies on all services).
# 1.3, 4.1.1 and 4.3.3 need at least one interface with role "wan"; without one the evidence is missing.
# 2.5.2 and 2.5.3 apply to HA clusters; a standalone unit (system.ha.mode == "standalone") passes them.
#
# Input contract (input.fortigate_config, FortiOS CLI names with "-" written as "_"):
#   system.global.*                 : `get system global` (pre_login_banner, admin_https_ssl_versions, admintimeout, ...)
#   system.{dns,ntp,auto_install,password_policy,ha,csf,fortiguard} : the matching `config system ...` objects
#   system.autoupdate.schedule      : `config system autoupdate schedule`
#   system.interface[]              : {name, role, allowaccess} (allowaccess a space-separated string or a list)
#   system.zone[]                   : {name, intrazone}
#   system.admin[]                  : {name, trusthosts[]} (trusthost1..10 values, "0.0.0.0 0.0.0.0" = any)
#   system.snmp.{sysinfo, community[], user[]} : user {name, notify_hosts[], queries}
#   system.automation_stitch[]      : {name, status, trigger, actions[]}
#   firewall.policy[]               : {policyid, srcintf, dstintf, action, service, logtraffic, ips_sensor, av_profile,
#                                      dnsfilter_profile, application_list, internet_service_name, internet_service_src_name}
#   firewall.local_in_policy[]      : {policyid, action, virtual_patch}
#   ips.sensor[]                    : {name, scan_botnet_connections}
#   antivirus.settings / antivirus.profile[] : profile {name, feature_set, fortisandbox_mode, <protocol>: {outbreak_prevention, content_disarm}}
#   dnsfilter.profile[]             : {name, block_botnet, log_all_domain}
#   webfilter.profile[]             : {name, ftgd_wf.filters[] {category (FortiGuard id), action}}
#   application.list[]              : {name, enforce_default_app_port, entries[] {category[] (FortiGuard ids), action}}
#   vpn.ssl.settings                : {servercert, ssl_min_proto_ver, ssl_max_proto_ver, algorithm}
#   log.eventfilter / log.syslogd.setting / log.fortianalyzer.setting
#   attest.*                        : attestation booleans for the judgement recommendations

import rego.v1

# Main compliance rule - every recommendation must pass; no facts, no compliance
default compliant := false

compliant if {
	input.fortigate_config
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
		security_fabric_violations,
		security_profiles_violations,
	]
	some a in arrays
	some v in a
]


# 2.1 / 2.3 / 2.5 System settings, SNMP, high availability
system_settings_violations := sort([m | some m in _v_system_settings])

# 2.2 / 2.4 Password policy and administrators
administration_violations := sort([m | some m in _v_administration])

# 7 Logs and reports
logging_violations := sort([m | some m in _v_logging])

# 1 Network settings
network_violations := sort([m | some m in _v_network])

# 3 Policy and objects
firewall_violations := sort([m | some m in _v_firewall])

# 6 VPN
vpn_violations := sort([m | some m in _v_vpn])

# no wireless recommendations in the 7.4.x benchmark (kept so the report shape is unchanged)
wireless_violations := []

# 5 Security fabric
security_fabric_violations := sort([m | some m in _v_security_fabric])

# 4 Security profiles
security_profiles_violations := sort([m | some m in _v_security_profiles])

# ── helpers ──────────────────────────────────────────────────────────────────
default _global_collected := false

_global_collected if {
	is_object(input.fortigate_config.system.global)
	count(input.fortigate_config.system.global) > 0
}

# a FortiOS multi-value field: a list, or a space-separated string
_names(v) := {sprintf("%v", [x]) | some x in v} if is_array(v)

_names(v) := {t | some t in regex.split(`\s+`, trim_space(v)); t != ""} if is_string(v)

_words(v) := {lower(t) | some t in _names(v)}

_access(i) := _words(object.get(i, "allowaccess", ""))

_set(obj, key) if {
	v := object.get(obj, key, "")
	is_string(v)
	v != ""
}

_wan_interfaces := [i | some i in input.fortigate_config.system.interface; lower(object.get(i, "role", "")) == "wan"]

_wan_names := {i.name | some i in _wan_interfaces}

_accept_policies := [p | some p in input.fortigate_config.firewall.policy; lower(object.get(p, "action", "deny")) == "accept"]

# accept policies whose destination includes a WAN-role interface (traffic outbound to the Internet)
_wan_accept_policies := [p |
	some p in _accept_policies
	count(_names(object.get(p, "dstintf", [])) & _wan_names) > 0
]

_restricted_trusthosts(a) if {
	hs := {h | some h in object.get(a, "trusthosts", []); not h in {"0.0.0.0 0.0.0.0", "0.0.0.0/0"}}
	count(hs) > 0
}

_local_in_patched(p) if lower(object.get(p, "action", "deny")) != "accept"

_local_in_patched(p) if object.get(p, "virtual_patch", "") == "enable"

default _ha_standalone := false

_ha_standalone if lower(input.fortigate_config.system.ha.mode) == "standalone"

# 3.3: Internet Service Database objects the benchmark names (inbound sources / outbound destinations)
_isdb_inbound := {
	"Tor-Exit.Node", "Tor-Relay.Node", "Censys-Scanner", "Shodan-Scanner", "Botnet-C&C.Server",
	"Phishing-Phishing.Server", "Proxy-Proxy.Server", "Spam-Spamming.Server", "VPN-Anonymous.VPN",
	"Malicious-Malicious.Server",
}

_isdb_outbound := {
	"Tor-Relay.Node", "Botnet-C&C.Server", "Phishing-Phishing.Server", "Proxy-Proxy.Server",
	"Spam-Spamming.Server", "VPN-Anonymous.VPN", "Malicious-Malicious.Server",
}

_deny_policies := [p | some p in input.fortigate_config.firewall.policy; lower(object.get(p, "action", "deny")) == "deny"]

_denied_isdb_src := {n | some p in _deny_policies; some n in _names(object.get(p, "internet_service_src_name", []))}

_denied_isdb_dst := {n | some p in _deny_policies; some n in _names(object.get(p, "internet_service_name", []))}

_botnet_block_sensors := {s.name | some s in input.fortigate_config.ips.sensor; object.get(s, "scan_botnet_connections", "") == "block"}

_av_protocols := {"http", "ftp", "imap", "pop3", "smtp", "mapi", "nntp", "cifs", "ssh"}

_outbreak_blocked(prof) if {
	protos := [v | some k, v in prof; k in _av_protocols]
	count(protos) > 0
	every v in protos { object.get(v, "outbreak_prevention", "") == "block" }
}

_proxy_cdr(prof) if {
	object.get(prof, "feature_set", "") == "proxy"
	some k, v in prof
	k in _av_protocols
	object.get(v, "content_disarm", "") == "enable"
}

# FortiGuard web filter category ids blocked by a profile (26 Malicious Websites, 61 Phishing, 86 Spam URLs)
_webfilter_blocked(prof) := {sprintf("%v", [f.category]) |
	wf := object.get(prof, "ftgd_wf", {})
	some f in object.get(wf, "filters", [])
	object.get(f, "action", "") == "block"
}

# FortiGuard application category ids blocked by a list (2 P2P, 6 Proxy)
_app_blocked_categories(l) := {c |
	some e in object.get(l, "entries", [])
	object.get(e, "action", "") == "block"
	some c in _names(object.get(e, "category", []))
}

_quarantine_stitch(s) if {
	object.get(s, "status", "") == "enable"
	contains(lower(sprintf("%v", [object.get(s, "trigger", "")])), "compromised host")
	some a in _names(object.get(s, "actions", []))
	contains(lower(a), "quarantine")
}


# 1.1 (Automated, Level 1)
default r_1_1 := false

r_1_1 if {
	is_string(input.fortigate_config.system.dns.primary)
	not input.fortigate_config.system.dns.primary in {"", "0.0.0.0"}
}

default e_1_1 := false

e_1_1 if {
	is_object(input.fortigate_config.system.dns)
}

_v_network contains "1.1: evidence missing — fortigate_config.system.dns not collected" if {
	not e_1_1
}

_v_network contains "1.1: DNS server must be explicitly configured" if {
	e_1_1
	not r_1_1
}

# 1.2 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_2 := false

r_1_2 if {
	every z in input.fortigate_config.system.zone { lower(object.get(z, "intrazone", "allow")) == "deny" }
}

default e_1_2 := false

e_1_2 if {
	is_array(input.fortigate_config.system.zone)
}

_v_network contains "1.2: evidence missing — fortigate_config.system.zone not collected" if {
	not e_1_2
}

_v_network contains "1.2: intra-zone traffic must be not always allowed" if {
	e_1_2
	not r_1_2
}

# 1.3 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_3 := false

r_1_3 if {
	every i in _wan_interfaces { count(_access(i) & {"ping", "https", "http", "ssh", "snmp", "radius-acct"}) == 0 }
}

default e_1_3 := false

e_1_3 if {
	is_array(input.fortigate_config.system.interface)
	count(input.fortigate_config.system.interface) > 0
	count(_wan_interfaces) > 0
}

_v_network contains "1.3: evidence missing — fortigate_config.system.interface (a WAN-role interface) not collected" if {
	not e_1_3
}

_v_network contains "1.3: all management related services on WAN port must be turned off" if {
	e_1_3
	not r_1_3
}

# 2.1.1 (Automated, Level 1)
default r_2_1_1 := false

r_2_1_1 if {
	input.fortigate_config.system.global.pre_login_banner == "enable"
}

default e_2_1_1 := false

e_2_1_1 if {
	_global_collected
}

_v_system_settings contains "2.1.1: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_1
}

_v_system_settings contains "2.1.1: 'Pre-Login Banner' must be populated" if {
	e_2_1_1
	not r_2_1_1
}

# 2.1.2 (Automated, Level 1)
default r_2_1_2 := false

r_2_1_2 if {
	input.fortigate_config.system.global.post_login_banner == "enable"
}

default e_2_1_2 := false

e_2_1_2 if {
	_global_collected
}

_v_system_settings contains "2.1.2: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_2
}

_v_system_settings contains "2.1.2: 'Post-Login-Banner' must be populated" if {
	e_2_1_2
	not r_2_1_2
}

# 2.1.3 (Automated, Level 1)
default r_2_1_3 := false

r_2_1_3 if {
	_ = input.fortigate_config.system.global.timezone
	sprintf("%v", [input.fortigate_config.system.global.timezone]) != ""
}

default e_2_1_3 := false

e_2_1_3 if {
	_global_collected
}

_v_system_settings contains "2.1.3: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_3
}

_v_system_settings contains "2.1.3: timezone must match the approved configuration" if {
	e_2_1_3
	not r_2_1_3
}

# 2.1.4 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_1_4 := false

r_2_1_4 if {
	input.fortigate_config.system.ntp.ntpsync == "enable"
}

default e_2_1_4 := false

e_2_1_4 if {
	is_object(input.fortigate_config.system.ntp)
}

_v_system_settings contains "2.1.4: evidence missing — fortigate_config.system.ntp not collected" if {
	not e_2_1_4
}

_v_system_settings contains "2.1.4: correct system time must be explicitly configured through NTP" if {
	e_2_1_4
	not r_2_1_4
}

# 2.1.5 (Automated, Level 1)
default r_2_1_5 := false

r_2_1_5 if {
	is_string(input.fortigate_config.system.global.hostname)
	input.fortigate_config.system.global.hostname != ""
}

default e_2_1_5 := false

e_2_1_5 if {
	_global_collected
}

_v_system_settings contains "2.1.5: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_5
}

_v_system_settings contains "2.1.5: hostname must be set" if {
	e_2_1_5
	not r_2_1_5
}

# 2.1.6 (Manual, Level 2)
default r_2_1_6 := false

r_2_1_6 if {
	input.fortigate_config.attest.latest_firmware_installed == true
}

_v_system_settings contains "2.1.6: the latest firmware must be present (manual review not attested)" if {
	not r_2_1_6
}

# 2.1.7 (Automated, Level 2)
default r_2_1_7 := false

r_2_1_7 if {
	input.fortigate_config.system.auto_install.auto_install_config == "disable"
	input.fortigate_config.system.auto_install.auto_install_image == "disable"
}

default e_2_1_7 := false

e_2_1_7 if {
	is_object(input.fortigate_config.system.auto_install)
}

_v_system_settings contains "2.1.7: evidence missing — fortigate_config.system.auto_install not collected" if {
	not e_2_1_7
}

_v_system_settings contains "2.1.7: USB Firmware and configuration installation must be turned off" if {
	e_2_1_7
	not r_2_1_7
}

# 2.1.8 (Automated, Level 2)
default r_2_1_8 := false

r_2_1_8 if {
	input.fortigate_config.system.global.ssl_static_key_ciphers == "disable"
}

default e_2_1_8 := false

e_2_1_8 if {
	_global_collected
}

_v_system_settings contains "2.1.8: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_8
}

_v_system_settings contains "2.1.8: static keys for TLS must be turned off" if {
	e_2_1_8
	not r_2_1_8
}

# 2.1.9 (Automated, Level 2)
default r_2_1_9 := false

r_2_1_9 if {
	input.fortigate_config.system.global.strong_crypto == "enable"
}

default e_2_1_9 := false

e_2_1_9 if {
	_global_collected
}

_v_system_settings contains "2.1.9: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_9
}

_v_system_settings contains "2.1.9: Global Strong Encryption must be turned on" if {
	e_2_1_9
	not r_2_1_9
}

# 2.1.10 (Automated, Level 1)
default r_2_1_10 := false

r_2_1_10 if {
	_words(input.fortigate_config.system.global.admin_https_ssl_versions) == {"tlsv1-3"}
}

default e_2_1_10 := false

e_2_1_10 if {
	_global_collected
}

_v_system_settings contains "2.1.10: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_10
}

_v_system_settings contains "2.1.10: checked condition — management GUI listens on secure TLS version" if {
	e_2_1_10
	not r_2_1_10
}

# 2.1.11 (Automated, Level 2)
default r_2_1_11 := false

r_2_1_11 if {
	input.fortigate_config.system.global.gui_cdn_usage == "enable"
}

default e_2_1_11 := false

e_2_1_11 if {
	_global_collected
}

_v_system_settings contains "2.1.11: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_11
}

_v_system_settings contains "2.1.11: CDN must be turned on for improved GUI performance" if {
	e_2_1_11
	not r_2_1_11
}

# 2.1.12 (Automated, Level 1)
default r_2_1_12 := false

r_2_1_12 if {
	input.fortigate_config.system.global.log_single_cpu_high == "enable"
}

default e_2_1_12 := false

e_2_1_12 if {
	_global_collected
}

_v_system_settings contains "2.1.12: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_12
}

_v_system_settings contains "2.1.12: single CPU core overloaded event must be logged" if {
	e_2_1_12
	not r_2_1_12
}

# 2.1.13 (Automated, Level 2)
default r_2_1_13 := false

r_2_1_13 if {
	input.fortigate_config.system.global.gui_display_hostname == "disable"
}

default e_2_1_13 := false

e_2_1_13 if {
	_global_collected
}

_v_system_settings contains "2.1.13: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_1_13
}

_v_system_settings contains "2.1.13: Hostname must be Not Displayed On Login GUI" if {
	e_2_1_13
	not r_2_1_13
}

# 2.2.1 (Automated, Level 1)
default r_2_2_1 := false

r_2_2_1 if {
	input.fortigate_config.system.password_policy.status == "enable"
	to_number(input.fortigate_config.system.password_policy.minimum_length) >= 14
	{"admin-password", "ipsec-preshared-key"} - _words(input.fortigate_config.system.password_policy.apply_to) == set()
}

default e_2_2_1 := false

e_2_2_1 if {
	is_object(input.fortigate_config.system.password_policy)
}

_v_administration contains "2.2.1: evidence missing — fortigate_config.system.password_policy not collected" if {
	not e_2_2_1
}

_v_administration contains "2.2.1: 'Password Policy' must be turned on" if {
	e_2_2_1
	not r_2_2_1
}

# 2.2.2 (Automated, Level 1)
default r_2_2_2 := false

r_2_2_2 if {
	n := to_number(input.fortigate_config.system.global.admin_lockout_threshold)
	n > 0
	n <= 3
	t := to_number(input.fortigate_config.system.global.admin_lockout_duration)
	t > 0
	t <= 900
}

default e_2_2_2 := false

e_2_2_2 if {
	_global_collected
}

_v_administration contains "2.2.2: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_2_2
}

_v_administration contains "2.2.2: administrator password retries and lockout time must be explicitly configured" if {
	e_2_2_2
	not r_2_2_2
}

# 2.3.1 (Automated, Level 1)
default r_2_3_1 := false

r_2_3_1 if {
	input.fortigate_config.system.snmp.sysinfo.status == "enable"
	count(input.fortigate_config.system.snmp.community) == 0
	count(input.fortigate_config.system.snmp.user) > 0
}

default e_2_3_1 := false

e_2_3_1 if {
	is_object(input.fortigate_config.system.snmp.sysinfo)
	is_array(input.fortigate_config.system.snmp.community)
	is_array(input.fortigate_config.system.snmp.user)
}

_v_system_settings contains "2.3.1: evidence missing — fortigate_config.system.snmp.{sysinfo,community,user} not collected" if {
	not e_2_3_1
}

_v_system_settings contains "2.3.1: only SNMPv3 must be turned on" if {
	e_2_3_1
	not r_2_3_1
}

# 2.3.2 (Manual, Level 2) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_3_2 := false

r_2_3_2 if {
	every u in input.fortigate_config.system.snmp.user { hs := _names(object.get(u, "notify_hosts", [])); count(hs) > 0; not "0.0.0.0" in hs }
}

default e_2_3_2 := false

e_2_3_2 if {
	is_array(input.fortigate_config.system.snmp.user)
	count(input.fortigate_config.system.snmp.user) > 0
}

_v_system_settings contains "2.3.2: evidence missing — fortigate_config.system.snmp.user not collected" if {
	not e_2_3_2
}

_v_system_settings contains "2.3.2: only trusted hosts in SNMPv3 may be permitted" if {
	e_2_3_2
	not r_2_3_2
}

# 2.3.3 (Automated, Level 2)
default r_2_3_3 := false

r_2_3_3 if {
	every u in input.fortigate_config.system.snmp.user { object.get(u, "queries", "enable") == "disable" }
}

default e_2_3_3 := false

e_2_3_3 if {
	is_array(input.fortigate_config.system.snmp.user)
	count(input.fortigate_config.system.snmp.user) > 0
}

_v_system_settings contains "2.3.3: evidence missing — fortigate_config.system.snmp.user not collected" if {
	not e_2_3_3
}

_v_system_settings contains "2.3.3: SNMPv3 Query Per User must be turned off" if {
	e_2_3_3
	not r_2_3_3
}

# 2.3.4 (Automated, Level 1)
default r_2_3_4 := false

r_2_3_4 if {
	input.fortigate_config.system.snmp.sysinfo.status == "enable"
	to_number(input.fortigate_config.system.snmp.sysinfo.trap_free_memory_threshold) >= 20
	to_number(input.fortigate_config.system.snmp.sysinfo.trap_freeable_memory_threshold) <= 50
}

default e_2_3_4 := false

e_2_3_4 if {
	is_object(input.fortigate_config.system.snmp.sysinfo)
}

_v_system_settings contains "2.3.4: evidence missing — fortigate_config.system.snmp.sysinfo not collected" if {
	not e_2_3_4
}

_v_system_settings contains "2.3.4: checked condition — Enabling SNMP trap for memory usage" if {
	e_2_3_4
	not r_2_3_4
}

# 2.4.1 (Automated, Level 1)
default r_2_4_1 := false

r_2_4_1 if {
	every a in input.fortigate_config.system.admin { lower(a.name) != "admin" }
}

default e_2_4_1 := false

e_2_4_1 if {
	is_array(input.fortigate_config.system.admin)
	count(input.fortigate_config.system.admin) > 0
}

_v_administration contains "2.4.1: evidence missing — fortigate_config.system.admin not collected" if {
	not e_2_4_1
}

_v_administration contains "2.4.1: default admin user and create one with other name must be removed" if {
	e_2_4_1
	not r_2_4_1
}

# 2.4.2 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_4_2 := false

r_2_4_2 if {
	every a in input.fortigate_config.system.admin { _restricted_trusthosts(a) }
}

default e_2_4_2 := false

e_2_4_2 if {
	is_array(input.fortigate_config.system.admin)
	count(input.fortigate_config.system.admin) > 0
}

_v_administration contains "2.4.2: evidence missing — fortigate_config.system.admin not collected" if {
	not e_2_4_2
}

_v_administration contains "2.4.2: checked condition — all the login accounts having specific trusted hosts enabled" if {
	e_2_4_2
	not r_2_4_2
}

# 2.4.3 (Manual, Level 1)
default r_2_4_3 := false

r_2_4_3 if {
	input.fortigate_config.attest.admin_profiles_reviewed == true
}

_v_administration contains "2.4.3: admin accounts with different privileges must have their correct profiles assigned (manual review not attested)" if {
	not r_2_4_3
}

# 2.4.4 (Automated, Level 1)
default r_2_4_4 := false

r_2_4_4 if {
	n := to_number(input.fortigate_config.system.global.admintimeout)
	n > 0
	n <= 5
}

default e_2_4_4 := false

e_2_4_4 if {
	_global_collected
}

_v_administration contains "2.4.4: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_4_4
}

_v_administration contains "2.4.4: Admin idle timeout time must be explicitly configured" if {
	e_2_4_4
	not r_2_4_4
}

# 2.4.5 (Automated, Level 1)
default r_2_4_5 := false

r_2_4_5 if {
	every i in input.fortigate_config.system.interface { count(_access(i) & {"http", "telnet"}) == 0 }
}

default e_2_4_5 := false

e_2_4_5 if {
	is_array(input.fortigate_config.system.interface)
	count(input.fortigate_config.system.interface) > 0
}

_v_administration contains "2.4.5: evidence missing — fortigate_config.system.interface not collected" if {
	not e_2_4_5
}

_v_administration contains "2.4.5: only encrypted access channels must be turned on" if {
	e_2_4_5
	not r_2_4_5
}

# 2.4.6 (Automated, Level 1)
default r_2_4_6 := false

r_2_4_6 if {
	count(input.fortigate_config.firewall.local_in_policy) > 0
}

default e_2_4_6 := false

e_2_4_6 if {
	is_array(input.fortigate_config.firewall.local_in_policy)
}

_v_administration contains "2.4.6: evidence missing — fortigate_config.firewall.local_in_policy not collected" if {
	not e_2_4_6
}

_v_administration contains "2.4.6: Local-in Policies must be applied" if {
	e_2_4_6
	not r_2_4_6
}

# 2.4.7 (Automated, Level 1)
default r_2_4_7 := false

r_2_4_7 if {
	object.get(input.fortigate_config.system.global, "admin_port", 80) != 80
	object.get(input.fortigate_config.system.global, "admin_sport", 443) != 443
	object.get(input.fortigate_config.system.global, "admin_https_redirect", "enable") == "disable"
}

default e_2_4_7 := false

e_2_4_7 if {
	_global_collected
}

_v_administration contains "2.4.7: evidence missing — fortigate_config.system.global not collected" if {
	not e_2_4_7
}

_v_administration contains "2.4.7: default Admin ports must be changed" if {
	e_2_4_7
	not r_2_4_7
}

# 2.4.8 (Automated, Level 1)
default r_2_4_8 := false

r_2_4_8 if {
	every p in input.fortigate_config.firewall.local_in_policy { _local_in_patched(p) }
}

default e_2_4_8 := false

e_2_4_8 if {
	is_array(input.fortigate_config.firewall.local_in_policy)
}

_v_administration contains "2.4.8: evidence missing — fortigate_config.firewall.local_in_policy not collected" if {
	not e_2_4_8
}

_v_administration contains "2.4.8: checked condition — Virtual patching on the local-in management interface" if {
	e_2_4_8
	not r_2_4_8
}

# 2.5.1 (Automated, Level 2)
default r_2_5_1 := false

r_2_5_1 if {
	lower(input.fortigate_config.system.ha.mode) in {"a-p", "a-a"}
	is_string(input.fortigate_config.system.ha.group_name)
	input.fortigate_config.system.ha.group_name != ""
	count(_names(object.get(input.fortigate_config.system.ha, "hbdev", []))) > 0
}

default e_2_5_1 := false

e_2_5_1 if {
	is_object(input.fortigate_config.system.ha)
	is_string(input.fortigate_config.system.ha.mode)
}

_v_system_settings contains "2.5.1: evidence missing — fortigate_config.system.ha not collected" if {
	not e_2_5_1
}

_v_system_settings contains "2.5.1: High Availability configuration must be turned on" if {
	e_2_5_1
	not r_2_5_1
}

# 2.5.2 (Automated, Level 1)
default r_2_5_2 := false

r_2_5_2 if {
	count(_names(object.get(input.fortigate_config.system.ha, "monitor", []))) > 0
}

r_2_5_2 if {
	_ha_standalone
}

default e_2_5_2 := false

e_2_5_2 if {
	is_object(input.fortigate_config.system.ha)
	is_string(input.fortigate_config.system.ha.mode)
}

_v_system_settings contains "2.5.2: evidence missing — fortigate_config.system.ha not collected" if {
	not e_2_5_2
}

_v_system_settings contains "2.5.2: \"Monitor Interfaces\" for High Availability devices must be turned on" if {
	e_2_5_2
	not r_2_5_2
}

# 2.5.3 (Automated, Level 1)
default r_2_5_3 := false

r_2_5_3 if {
	input.fortigate_config.system.ha.ha_mgmt_status == "enable"
	count(object.get(input.fortigate_config.system.ha, "ha_mgmt_interfaces", [])) > 0
}

r_2_5_3 if {
	_ha_standalone
}

default e_2_5_3 := false

e_2_5_3 if {
	is_object(input.fortigate_config.system.ha)
	is_string(input.fortigate_config.system.ha.mode)
}

_v_system_settings contains "2.5.3: evidence missing — fortigate_config.system.ha not collected" if {
	not e_2_5_3
}

_v_system_settings contains "2.5.3: HA Reserved Management Interface must be explicitly configured" if {
	e_2_5_3
	not r_2_5_3
}

# 2.5.4 (Automated, Level 2)
default r_2_5_4 := false

r_2_5_4 if {
	to_number(object.get(input.fortigate_config.system.ha, "group_id", 0)) > 0
}

default e_2_5_4 := false

e_2_5_4 if {
	is_object(input.fortigate_config.system.ha)
	is_string(input.fortigate_config.system.ha.mode)
}

_v_system_settings contains "2.5.4: evidence missing — fortigate_config.system.ha not collected" if {
	not e_2_5_4
}

_v_system_settings contains "2.5.4: High Availability Group-ID must be explicitly configured" if {
	e_2_5_4
	not r_2_5_4
}

# 3.1 (Manual, Level 2)
default r_3_1 := false

r_3_1 if {
	input.fortigate_config.attest.unused_policies_reviewed == true
}

_v_firewall contains "3.1: unused policies must be reviewed regularly (manual review not attested)" if {
	not r_3_1
}

# 3.2 (Automated, Level 1)
default r_3_2 := false

r_3_2 if {
	every p in _accept_policies { not "all" in {lower(s) | some s in _names(object.get(p, "service", []))} }
}

default e_3_2 := false

e_3_2 if {
	is_array(input.fortigate_config.firewall.policy)
	count(input.fortigate_config.firewall.policy) > 0
}

_v_firewall contains "3.2: evidence missing — fortigate_config.firewall.policy not collected" if {
	not e_3_2
}

_v_firewall contains "3.2: checked condition — policies do not use \"ALL\" as Service" if {
	e_3_2
	not r_3_2
}

# 3.3 (Automated, Level 1)
default r_3_3 := false

r_3_3 if {
	count(_isdb_inbound - _denied_isdb_src) == 0
	count(_isdb_outbound - _denied_isdb_dst) == 0
}

default e_3_3 := false

e_3_3 if {
	is_array(input.fortigate_config.firewall.policy)
	count(input.fortigate_config.firewall.policy) > 0
}

_v_firewall contains "3.3: evidence missing — fortigate_config.firewall.policy not collected" if {
	not e_3_3
}

_v_firewall contains "3.3: checked condition — firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB" if {
	e_3_3
	not r_3_3
}

# 3.4 (Automated, Level 1)
default r_3_4 := false

r_3_4 if {
	every p in input.fortigate_config.firewall.policy { lower(object.get(p, "logtraffic", "")) in {"all", "utm"} }
}

default e_3_4 := false

e_3_4 if {
	is_array(input.fortigate_config.firewall.policy)
	count(input.fortigate_config.firewall.policy) > 0
}

_v_firewall contains "3.4: evidence missing — fortigate_config.firewall.policy not collected" if {
	not e_3_4
}

_v_firewall contains "3.4: logging must be turned on for all firewall policies" if {
	e_3_4
	not r_3_4
}

# 4.1.1 (Automated, Level 2)
default r_4_1_1 := false

r_4_1_1 if {
	count(_botnet_block_sensors) > 0
	every p in _wan_accept_policies { object.get(p, "ips_sensor", "") in _botnet_block_sensors }
}

default e_4_1_1 := false

e_4_1_1 if {
	is_array(input.fortigate_config.firewall.policy)
	count(input.fortigate_config.firewall.policy) > 0
	is_array(input.fortigate_config.system.interface)
	count(_wan_interfaces) > 0
	is_array(input.fortigate_config.ips.sensor)
}

_v_security_profiles contains "4.1.1: evidence missing — fortigate_config.{ips.sensor,firewall.policy,system.interface WAN role} not collected" if {
	not e_4_1_1
}

_v_security_profiles contains "4.1.1: Botnet connections must be detected and recorded" if {
	e_4_1_1
	not r_4_1_1
}

# 4.1.2 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_1_2 := false

r_4_1_2 if {
	every p in _accept_policies { _set(p, "ips_sensor") }
}

default e_4_1_2 := false

e_4_1_2 if {
	is_array(input.fortigate_config.firewall.policy)
	count(input.fortigate_config.firewall.policy) > 0
}

_v_security_profiles contains "4.1.2: evidence missing — fortigate_config.firewall.policy not collected" if {
	not e_4_1_2
}

_v_security_profiles contains "4.1.2: IPS Security Profile to Policies must be applied" if {
	e_4_1_2
	not r_4_1_2
}

# 4.2.1 (Automated, Level 2)
default r_4_2_1 := false

r_4_2_1 if {
	input.fortigate_config.system.autoupdate.schedule.frequency == "automatic"
}

default e_4_2_1 := false

e_4_2_1 if {
	is_object(input.fortigate_config.system.autoupdate.schedule)
}

_v_security_profiles contains "4.2.1: evidence missing — fortigate_config.system.autoupdate.schedule not collected" if {
	not e_4_2_1
}

_v_security_profiles contains "4.2.1: Antivirus Definition Push Updates must be explicitly configured" if {
	e_4_2_1
	not r_4_2_1
}

# 4.2.2 (Manual, Level 2) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_2_2 := false

r_4_2_2 if {
	every p in _accept_policies { _set(p, "av_profile") }
}

default e_4_2_2 := false

e_4_2_2 if {
	is_array(input.fortigate_config.firewall.policy)
	count(input.fortigate_config.firewall.policy) > 0
}

_v_security_profiles contains "4.2.2: evidence missing — fortigate_config.firewall.policy not collected" if {
	not e_4_2_2
}

_v_security_profiles contains "4.2.2: Antivirus Security Profile to Policies must be applied" if {
	e_4_2_2
	not r_4_2_2
}

# 4.2.3 (Automated, Level 2)
default r_4_2_3 := false

r_4_2_3 if {
	every prof in input.fortigate_config.antivirus.profile { _outbreak_blocked(prof) }
}

default e_4_2_3 := false

e_4_2_3 if {
	is_array(input.fortigate_config.antivirus.profile)
	count(input.fortigate_config.antivirus.profile) > 0
}

_v_security_profiles contains "4.2.3: evidence missing — fortigate_config.antivirus.profile not collected" if {
	not e_4_2_3
}

_v_security_profiles contains "4.2.3: Outbreak Prevention Database must be turned on" if {
	e_4_2_3
	not r_4_2_3
}

# 4.2.4 (Automated, Level 2)
default r_4_2_4 := false

r_4_2_4 if {
	input.fortigate_config.antivirus.settings.machine_learning_detection == "enable"
}

default e_4_2_4 := false

e_4_2_4 if {
	is_object(input.fortigate_config.antivirus.settings)
}

_v_security_profiles contains "4.2.4: evidence missing — fortigate_config.antivirus.settings not collected" if {
	not e_4_2_4
}

_v_security_profiles contains "4.2.4: AI /heuristic based malware detection must be turned on" if {
	e_4_2_4
	not r_4_2_4
}

# 4.2.5 (Automated, Level 2)
default r_4_2_5 := false

r_4_2_5 if {
	input.fortigate_config.antivirus.settings.grayware == "enable"
}

default e_4_2_5 := false

e_4_2_5 if {
	is_object(input.fortigate_config.antivirus.settings)
}

_v_security_profiles contains "4.2.5: evidence missing — fortigate_config.antivirus.settings not collected" if {
	not e_4_2_5
}

_v_security_profiles contains "4.2.5: grayware detection on antivirus must be turned on" if {
	e_4_2_5
	not r_4_2_5
}

# 4.2.6 (Automated, Level 1)
default r_4_2_6 := false

r_4_2_6 if {
	input.fortigate_config.system.fortiguard.sandbox_inline_scan == "enable"
	every prof in input.fortigate_config.antivirus.profile { object.get(prof, "fortisandbox_mode", "") == "inline" }
}

default e_4_2_6 := false

e_4_2_6 if {
	is_object(input.fortigate_config.system.fortiguard)
	is_array(input.fortigate_config.antivirus.profile)
	count(input.fortigate_config.antivirus.profile) > 0
}

_v_security_profiles contains "4.2.6: evidence missing — fortigate_config.{system.fortiguard,antivirus.profile} not collected" if {
	not e_4_2_6
}

_v_security_profiles contains "4.2.6: inline scanning with FortiGuard AI-Based Sandbox Service must be turned on" if {
	e_4_2_6
	not r_4_2_6
}

# 4.2.7 (Automated, Level 2)
default r_4_2_7 := false

r_4_2_7 if {
	some prof in input.fortigate_config.antivirus.profile
	_proxy_cdr(prof)
}

default e_4_2_7 := false

e_4_2_7 if {
	is_array(input.fortigate_config.antivirus.profile)
	count(input.fortigate_config.antivirus.profile) > 0
}

_v_security_profiles contains "4.2.7: evidence missing — fortigate_config.antivirus.profile not collected" if {
	not e_4_2_7
}

_v_security_profiles contains "4.2.7: CDR for proxy mode on XLSB, OpenOffice, and RTF files must be turned on" if {
	e_4_2_7
	not r_4_2_7
}

# 4.3.1 (Automated, Level 2)
default r_4_3_1 := false

r_4_3_1 if {
	every p in input.fortigate_config.dnsfilter.profile { object.get(p, "block_botnet", "") == "enable" }
}

default e_4_3_1 := false

e_4_3_1 if {
	is_array(input.fortigate_config.dnsfilter.profile)
	count(input.fortigate_config.dnsfilter.profile) > 0
}

_v_security_profiles contains "4.3.1: evidence missing — fortigate_config.dnsfilter.profile not collected" if {
	not e_4_3_1
}

_v_security_profiles contains "4.3.1: Botnet C&C Domain Blocking DNS Filter must be turned on" if {
	e_4_3_1
	not r_4_3_1
}

# 4.3.2 (Automated, Level 1)
default r_4_3_2 := false

r_4_3_2 if {
	every p in input.fortigate_config.dnsfilter.profile { object.get(p, "log_all_domain", "") == "enable" }
}

default e_4_3_2 := false

e_4_3_2 if {
	is_array(input.fortigate_config.dnsfilter.profile)
	count(input.fortigate_config.dnsfilter.profile) > 0
}

_v_security_profiles contains "4.3.2: evidence missing — fortigate_config.dnsfilter.profile not collected" if {
	not e_4_3_2
}

_v_security_profiles contains "4.3.2: checked condition — DNS Filter logs all DNS queries and responses" if {
	e_4_3_2
	not r_4_3_2
}

# 4.3.3 (Automated, Level 1)
default r_4_3_3 := false

r_4_3_3 if {
	every p in _wan_accept_policies { _set(p, "dnsfilter_profile") }
}

default e_4_3_3 := false

e_4_3_3 if {
	is_array(input.fortigate_config.firewall.policy)
	count(input.fortigate_config.firewall.policy) > 0
	is_array(input.fortigate_config.system.interface)
	count(_wan_interfaces) > 0
}

_v_security_profiles contains "4.3.3: evidence missing — fortigate_config.{firewall.policy,system.interface WAN role} not collected" if {
	not e_4_3_3
}

_v_security_profiles contains "4.3.3: DNS Filter Security Profile to Policies must be applied" if {
	e_4_3_3
	not r_4_3_3
}

# 4.4.1 (Automated, Level 1)
default r_4_4_1 := false

r_4_4_1 if {
	some prof in input.fortigate_config.webfilter.profile
	count({"26", "61", "86"} - _webfilter_blocked(prof)) == 0
}

default e_4_4_1 := false

e_4_4_1 if {
	is_array(input.fortigate_config.webfilter.profile)
	count(input.fortigate_config.webfilter.profile) > 0
}

_v_security_profiles contains "4.4.1: evidence missing — fortigate_config.webfilter.profile not collected" if {
	not e_4_4_1
}

_v_security_profiles contains "4.4.1: a Web Filtering Profile must exist" if {
	e_4_4_1
	not r_4_4_1
}

# 4.5.1 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_5_1 := false

r_4_5_1 if {
	some l in input.fortigate_config.application.list
	count({"2", "6"} - _app_blocked_categories(l)) == 0
}

default e_4_5_1 := false

e_4_5_1 if {
	is_array(input.fortigate_config.application.list)
	count(input.fortigate_config.application.list) > 0
}

_v_security_profiles contains "4.5.1: evidence missing — fortigate_config.application.list not collected" if {
	not e_4_5_1
}

_v_security_profiles contains "4.5.1: high risk categories on Application Control must be blocked" if {
	e_4_5_1
	not r_4_5_1
}

# 4.5.2 (Automated, Level 2)
default r_4_5_2 := false

r_4_5_2 if {
	every l in input.fortigate_config.application.list { object.get(l, "enforce_default_app_port", "") == "enable" }
}

default e_4_5_2 := false

e_4_5_2 if {
	is_array(input.fortigate_config.application.list)
	count(input.fortigate_config.application.list) > 0
}

_v_security_profiles contains "4.5.2: evidence missing — fortigate_config.application.list not collected" if {
	not e_4_5_2
}

_v_security_profiles contains "4.5.2: applications running on non-default ports must be blocked" if {
	e_4_5_2
	not r_4_5_2
}

# 4.5.3 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_5_3 := false

r_4_5_3 if {
	every l in input.fortigate_config.application.list { every e in object.get(l, "entries", []) { object.get(e, "action", "") != "pass" } }
}

default e_4_5_3 := false

e_4_5_3 if {
	is_array(input.fortigate_config.application.list)
	count(input.fortigate_config.application.list) > 0
}

_v_security_profiles contains "4.5.3: evidence missing — fortigate_config.application.list not collected" if {
	not e_4_5_3
}

_v_security_profiles contains "4.5.3: all Application Control related traffic must be logged" if {
	e_4_5_3
	not r_4_5_3
}

# 4.5.4 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_4_5_4 := false

r_4_5_4 if {
	every p in _accept_policies { _set(p, "application_list") }
}

default e_4_5_4 := false

e_4_5_4 if {
	is_array(input.fortigate_config.firewall.policy)
	count(input.fortigate_config.firewall.policy) > 0
}

_v_security_profiles contains "4.5.4: evidence missing — fortigate_config.firewall.policy not collected" if {
	not e_4_5_4
}

_v_security_profiles contains "4.5.4: Application Control Security Profile to Policies must be applied" if {
	e_4_5_4
	not r_4_5_4
}

# 5.1.1 (Automated, Level 1)
default r_5_1_1 := false

r_5_1_1 if {
	some s in input.fortigate_config.system.automation_stitch
	_quarantine_stitch(s)
}

default e_5_1_1 := false

e_5_1_1 if {
	is_array(input.fortigate_config.system.automation_stitch)
}

_v_security_fabric contains "5.1.1: evidence missing — fortigate_config.system.automation_stitch not collected" if {
	not e_5_1_1
}

_v_security_fabric contains "5.1.1: Compromised Host Quarantine must be turned on" if {
	e_5_1_1
	not r_5_1_1
}

# 5.2.1.1 (Manual, Level 2) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_2_1_1 := false

r_5_2_1_1 if {
	input.fortigate_config.system.csf.status == "enable"
	is_string(input.fortigate_config.system.csf.group_name)
	input.fortigate_config.system.csf.group_name != ""
}

default e_5_2_1_1 := false

e_5_2_1_1 if {
	is_object(input.fortigate_config.system.csf)
}

_v_security_fabric contains "5.2.1.1: evidence missing — fortigate_config.system.csf not collected" if {
	not e_5_2_1_1
}

_v_security_fabric contains "5.2.1.1: Security Fabric must be explicitly configured" if {
	e_5_2_1_1
	not r_5_2_1_1
}

# 6.1.1 (Automated, Level 2)
default r_6_1_1 := false

r_6_1_1 if {
	is_string(input.fortigate_config.vpn.ssl.settings.servercert)
	not lower(input.fortigate_config.vpn.ssl.settings.servercert) in {"", "fortinet_factory", "self-sign"}
}

default e_6_1_1 := false

e_6_1_1 if {
	is_object(input.fortigate_config.vpn.ssl.settings)
}

_v_vpn contains "6.1.1: evidence missing — fortigate_config.vpn.ssl.settings not collected" if {
	not e_6_1_1
}

_v_vpn contains "6.1.1: a Trusted Signed Certificate for VPN Portal must be applied" if {
	e_6_1_1
	not r_6_1_1
}

# 6.1.2 (Automated, Level 2)
default r_6_1_2 := false

r_6_1_2 if {
	input.fortigate_config.vpn.ssl.settings.ssl_max_proto_ver == "tls1-3"
	input.fortigate_config.vpn.ssl.settings.ssl_min_proto_ver == "tls1-2"
	input.fortigate_config.vpn.ssl.settings.algorithm == "high"
}

default e_6_1_2 := false

e_6_1_2 if {
	is_object(input.fortigate_config.vpn.ssl.settings)
}

_v_vpn contains "6.1.2: evidence missing — fortigate_config.vpn.ssl.settings not collected" if {
	not e_6_1_2
}

_v_vpn contains "6.1.2: Limited TLS Versions for SSL VPN must be turned on" if {
	e_6_1_2
	not r_6_1_2
}

# 7.1.1 (Automated, Level 2)
default r_7_1_1 := false

r_7_1_1 if {
	every _, v in input.fortigate_config.log.eventfilter { v == "enable" }
}

default e_7_1_1 := false

e_7_1_1 if {
	is_object(input.fortigate_config.log.eventfilter)
	count(input.fortigate_config.log.eventfilter) > 0
}

_v_logging contains "7.1.1: evidence missing — fortigate_config.log.eventfilter not collected" if {
	not e_7_1_1
}

_v_logging contains "7.1.1: Event Logging must be turned on" if {
	e_7_1_1
	not r_7_1_1
}

# 7.2.1 (Automated, Level 2)
default r_7_2_1 := false

r_7_2_1 if {
	input.fortigate_config.log.syslogd.setting.status == "enable"
	is_string(input.fortigate_config.log.syslogd.setting.server)
	input.fortigate_config.log.syslogd.setting.server != ""
}

default e_7_2_1 := false

e_7_2_1 if {
	is_object(input.fortigate_config.log.syslogd.setting)
	count(input.fortigate_config.log.syslogd.setting) > 0
}

_v_logging contains "7.2.1: evidence missing — fortigate_config.log.syslogd.setting not collected" if {
	not e_7_2_1
}

_v_logging contains "7.2.1: checked condition — Centralized Logging and Reporting" if {
	e_7_2_1
	not r_7_2_1
}

# 7.3.1 (Automated, Level 1)
default r_7_3_1 := false

r_7_3_1 if {
	input.fortigate_config.log.fortianalyzer.setting.enc_algorithm == "high"
	input.fortigate_config.log.fortianalyzer.setting.reliable == "enable"
}

default e_7_3_1 := false

e_7_3_1 if {
	is_object(input.fortigate_config.log.fortianalyzer.setting)
	count(input.fortigate_config.log.fortianalyzer.setting) > 0
}

_v_logging contains "7.3.1: evidence missing — fortigate_config.log.fortianalyzer.setting not collected" if {
	not e_7_3_1
}

_v_logging contains "7.3.1: Log Transmission to FortiAnalyzer / FortiManager must be encrypted in transit or at rest" if {
	e_7_3_1
	not r_7_3_1
}

# 7.3.2 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_3_2 := false

r_7_3_2 if {
	input.fortigate_config.log.syslogd.setting.enc_algorithm == "high"
	input.fortigate_config.log.syslogd.setting.reliable == "enable"
}

default e_7_3_2 := false

e_7_3_2 if {
	is_object(input.fortigate_config.log.syslogd.setting)
	count(input.fortigate_config.log.syslogd.setting) > 0
}

_v_logging contains "7.3.2: evidence missing — fortigate_config.log.syslogd.setting not collected" if {
	not e_7_3_2
}

_v_logging contains "7.3.2: Log Transmission to Syslog must be encrypted in transit or at rest" if {
	e_7_3_2
	not r_7_3_2
}

# 7.3.3 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_3_3 := false

r_7_3_3 if {
	input.fortigate_config.log.syslogd.setting.enc_algorithm == "high"
	input.fortigate_config.log.syslogd.setting.reliable == "enable"
}

default e_7_3_3 := false

e_7_3_3 if {
	is_object(input.fortigate_config.log.syslogd.setting)
	count(input.fortigate_config.log.syslogd.setting) > 0
}

_v_logging contains "7.3.3: evidence missing — fortigate_config.log.syslogd.setting not collected" if {
	not e_7_3_3
}

_v_logging contains "7.3.3: Log Transmission to Syslog must be encrypted in transit or at rest" if {
	e_7_3_3
	not r_7_3_3
}

# Every recommendation in the benchmark: title, level, assessment status, how it is checked, report section.
recommendations := {
	"1.1": {
		"title": "DNS server must be explicitly configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "network"
	},
	"1.2": {
		"title": "intra-zone traffic must be not always allowed",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "network"
	},
	"1.3": {
		"title": "all management related services on WAN port must be turned off",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "network"
	},
	"2.1.1": {
		"title": "'Pre-Login Banner' must be populated",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.2": {
		"title": "'Post-Login-Banner' must be populated",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.3": {
		"title": "timezone must match the approved configuration",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.4": {
		"title": "correct system time must be explicitly configured through NTP",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.5": {
		"title": "hostname must be set",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.6": {
		"title": "the latest firmware must be present",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2"
		],
		"check": "attestation",
		"section": "system_settings"
	},
	"2.1.7": {
		"title": "USB Firmware and configuration installation must be turned off",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.8": {
		"title": "static keys for TLS must be turned off",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.9": {
		"title": "Global Strong Encryption must be turned on",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.10": {
		"title": "checked condition — management GUI listens on secure TLS version",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.11": {
		"title": "CDN must be turned on for improved GUI performance",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.12": {
		"title": "single CPU core overloaded event must be logged",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.1.13": {
		"title": "Hostname must be Not Displayed On Login GUI",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.2.1": {
		"title": "'Password Policy' must be turned on",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "administration"
	},
	"2.2.2": {
		"title": "administrator password retries and lockout time must be explicitly configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "administration"
	},
	"2.3.1": {
		"title": "only SNMPv3 must be turned on",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.3.2": {
		"title": "only trusted hosts in SNMPv3 may be permitted",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.3.3": {
		"title": "SNMPv3 Query Per User must be turned off",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.3.4": {
		"title": "checked condition — Enabling SNMP trap for memory usage",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.4.1": {
		"title": "default admin user and create one with other name must be removed",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "administration"
	},
	"2.4.2": {
		"title": "checked condition — all the login accounts having specific trusted hosts enabled",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "administration"
	},
	"2.4.3": {
		"title": "admin accounts with different privileges must have their correct profiles assigned",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "attestation",
		"section": "administration"
	},
	"2.4.4": {
		"title": "Admin idle timeout time must be explicitly configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "administration"
	},
	"2.4.5": {
		"title": "only encrypted access channels must be turned on",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "administration"
	},
	"2.4.6": {
		"title": "Local-in Policies must be applied",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "administration"
	},
	"2.4.7": {
		"title": "default Admin ports must be changed",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "administration"
	},
	"2.4.8": {
		"title": "checked condition — Virtual patching on the local-in management interface",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "administration"
	},
	"2.5.1": {
		"title": "High Availability configuration must be turned on",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.5.2": {
		"title": "\"Monitor Interfaces\" for High Availability devices must be turned on",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.5.3": {
		"title": "HA Reserved Management Interface must be explicitly configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"2.5.4": {
		"title": "High Availability Group-ID must be explicitly configured",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "system_settings"
	},
	"3.1": {
		"title": "unused policies must be reviewed regularly",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2"
		],
		"check": "attestation",
		"section": "firewall"
	},
	"3.2": {
		"title": "checked condition — policies do not use \"ALL\" as Service",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "firewall"
	},
	"3.3": {
		"title": "checked condition — firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "firewall"
	},
	"3.4": {
		"title": "logging must be turned on for all firewall policies",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "firewall"
	},
	"4.1.1": {
		"title": "Botnet connections must be detected and recorded",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.1.2": {
		"title": "IPS Security Profile to Policies must be applied",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.2.1": {
		"title": "Antivirus Definition Push Updates must be explicitly configured",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.2.2": {
		"title": "Antivirus Security Profile to Policies must be applied",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.2.3": {
		"title": "Outbreak Prevention Database must be turned on",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.2.4": {
		"title": "AI /heuristic based malware detection must be turned on",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.2.5": {
		"title": "grayware detection on antivirus must be turned on",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.2.6": {
		"title": "inline scanning with FortiGuard AI-Based Sandbox Service must be turned on",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.2.7": {
		"title": "CDR for proxy mode on XLSB, OpenOffice, and RTF files must be turned on",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.3.1": {
		"title": "Botnet C&C Domain Blocking DNS Filter must be turned on",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.3.2": {
		"title": "checked condition — DNS Filter logs all DNS queries and responses",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.3.3": {
		"title": "DNS Filter Security Profile to Policies must be applied",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.4.1": {
		"title": "a Web Filtering Profile must exist",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.5.1": {
		"title": "high risk categories on Application Control must be blocked",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.5.2": {
		"title": "applications running on non-default ports must be blocked",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.5.3": {
		"title": "all Application Control related traffic must be logged",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"4.5.4": {
		"title": "Application Control Security Profile to Policies must be applied",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "security_profiles"
	},
	"5.1.1": {
		"title": "Compromised Host Quarantine must be turned on",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "security_fabric"
	},
	"5.2.1.1": {
		"title": "Security Fabric must be explicitly configured",
		"level": 2,
		"assessment": "Manual",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "security_fabric"
	},
	"6.1.1": {
		"title": "a Trusted Signed Certificate for VPN Portal must be applied",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "vpn"
	},
	"6.1.2": {
		"title": "Limited TLS Versions for SSL VPN must be turned on",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "vpn"
	},
	"7.1.1": {
		"title": "Event Logging must be turned on",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "logging"
	},
	"7.2.1": {
		"title": "checked condition — Centralized Logging and Reporting",
		"level": 2,
		"assessment": "Automated",
		"profiles": [
			"Level 2"
		],
		"check": "configuration",
		"section": "logging"
	},
	"7.3.1": {
		"title": "Log Transmission to FortiAnalyzer / FortiManager must be encrypted in transit or at rest",
		"level": 1,
		"assessment": "Automated",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "logging"
	},
	"7.3.2": {
		"title": "Log Transmission to Syslog must be encrypted in transit or at rest",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "logging"
	},
	"7.3.3": {
		"title": "Log Transmission to Syslog must be encrypted in transit or at rest",
		"level": 1,
		"assessment": "Manual",
		"profiles": [
			"Level 1"
		],
		"check": "configuration",
		"section": "logging"
	}
}


_failed_ids := {id | some v in violations; id := split(v, ":")[0]}

# Compliance summary for reporting (counts are recommendations; a recommendation fails once however many messages it emits)
compliance_summary := {
	"total_controls": 64,
	"passing_controls": 64 - count(_failed_ids),
	"failing_controls": count(_failed_ids),
	"compliance_percentage": ((64 - count(_failed_ids)) * 100) / 64,
	"sections": {
		"system_settings": {
			"total": 21,
			"violations": count(system_settings_violations),
		},
		"administration": {
			"total": 10,
			"violations": count(administration_violations),
		},
		"logging": {
			"total": 5,
			"violations": count(logging_violations),
		},
		"network": {
			"total": 3,
			"violations": count(network_violations),
		},
		"firewall": {
			"total": 4,
			"violations": count(firewall_violations),
		},
		"vpn": {
			"total": 2,
			"violations": count(vpn_violations),
		},
		"wireless": {
			"total": 0,
			"violations": count(wireless_violations),
		},
		"security_fabric": {
			"total": 2,
			"violations": count(security_fabric_violations),
		},
		"security_profiles": {
			"total": 17,
			"violations": count(security_profiles_violations),
		},
	},
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
	"security_fabric_violations": security_fabric_violations,
	"security_profiles_violations": security_profiles_violations,
}

compliance_report := {
	"benchmark": "CIS FortiGate 7.4.x Benchmark v1.0.1",
	"total_controls": count(recommendations),
	"standard_total": 64,
	"standard_total_source": "CIS FortiGate 7.4.x Benchmark v1.0.1, recommendations counted from the CIS workbook",
	"failed_controls": count(_failed_ids),
	"passed_controls": count(recommendations) - count(_failed_ids),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
