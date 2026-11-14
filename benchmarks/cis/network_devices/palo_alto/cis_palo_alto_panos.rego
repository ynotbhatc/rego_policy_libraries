# METADATA
# title: "CIS Palo Alto Firewall 11 Benchmark v1.2.1"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, palo-alto]
#   coverage:
#     checks: 79
#     cited: 79
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cis_palo_alto_panos

# CIS Palo Alto Firewall 11 Benchmark v1.2.1
# Rewritten 2026-11-14 from the CIS workbook by tools/cis_generators/gen_palo_alto.py. The previous module claimed
# "CIS Palo Alto PAN-OS Benchmark v1.2.0" and implemented a handful of rules; it is replaced in place.
# 79 recommendations (62 Automated, 17 Manual; 69 Level 1, 10 Level 2), every one in the
# benchmark; ids, levels and assessment status read from the workbook. Messages use our own wording, not CIS text.
# Profile: input.cis_profile.level 1 or 2 (Level 2 includes Level 1); absent => 2. total_controls counts the
# recommendations in the selected profile.
# Automated checks fail closed: facts not collected => "<id>: evidence missing — <field> not collected".
# Manual recommendations with a decidable configuration fact are checked like Automated ones:
#   1.2.4, 5.8, 6.2, 6.20, 6.24, 6.25, 7.4.
# Attestation booleans under input.panos_config.attest (false or absent => violation): 1.2.1, 1.2.2, 1.2.5, 1.6.3, 1.7.1, 2.1, 2.5, 2.6, 2.7, 5.1, 5.7, 8.2, 8.3.
#   Automated in the workbook but attested here: 2.1 (read from traffic/URL logs, not configuration), 2.6 (an
#   Active Directory setting), 5.1 (the per-file-type defaults differ by PAN-OS release; sizing is a judgement).
# 6.22-6.25 apply only when the named license is active; licenses not collected => evidence missing.
#
# Input contract (input.panos_config): the running configuration (`show config running`, XML converted to JSON)
# with "-" in element names written as "_", every <entry> list written as an array of objects keyed by "name",
# every <member> list as an array of strings, and booleans as "yes"/"no". Paths are flattened as follows:
#   deviceconfig.system            : login_banner, server_verification, service{disable_http, disable_telnet},
#                                    snmp_setting.access_setting.version ("v3"), ntp_servers.{primary,secondary}_ntp_server
#                                    .ntp_server_address, update_schedule.{anti_virus,threats,wildfire}{action, recurrence}
#   deviceconfig.setting           : management{enable_log_high_dp_load, idle_timeout}, ssl_decrypt
#                                    .allow_forward_decrypted_content, wildfire.session_info_select{exclude_*}
#   deviceconfig.high_availability : enabled, interface.ha2.port, state_synchronization.enabled, link_monitoring /
#                                    path_monitoring {enabled, failure_condition, link_group[] / path_group[]},
#                                    active_passive.passive_link_state, election_option.preemptive
#   mgt_config                     : password_complexity{...}, password_profile[]{name, password_change.expiration_period}
#   shared                         : server_profile.{syslog[], snmptrap[]}, log_settings.<type>.match_list[]{filter,
#                                    send_syslog[], send_snmptrap[]}, authentication_profile[]{lockout},
#                                    log_forwarding_profile[]{match_list[]{log_type, send_*[]}}
#   network.profiles               : interface_management[]{http, telnet, ...}, zone_protection[]{flood, scan, discard_*}
#   zone[]                         : {name, zone_protection_profile, enable_user_identification}
#   user_id                        : setting.enable_probing, include_exclude_network[]{name, discovery, network_address}
#   profiles.<kind>[]              : virus, spyware, vulnerability, url_filtering, data_filtering, wildfire_analysis
#   profile_group[]                : {name, <kind>[]}
#   rulebase.security[]            : {name, from[], to[], source[], destination[], application[], service[], action,
#                                    disabled, profile_setting{profiles{<kind>[]}, group[]}}
#   rulebase.default_security_rules[], rulebase.decryption[]{action, type, from[], to[]}
#   licenses[]                     : `request license info` {feature, expired}
#   site                           : operator classification, not device config: untrusted_zones[], internet_zones[],
#                                    url_block_categories[] (an empty or absent list is evidence missing)
#   attest.*                       : attestation booleans for the judgement recommendations

import rego.v1

# Main compliance rule - every recommendation in the selected profile must pass; no facts, no compliance
default compliant := false

compliant if {
	input.panos_config
	count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		device_setup_violations,
		user_identification_violations,
		high_availability_violations,
		dynamic_updates_violations,
		wildfire_violations,
		security_profiles_violations,
		security_policies_violations,
		decryption_violations,
	]
	some a in arrays
	some v in a
]

# 1 Device setup
device_setup_violations := sort([m | some m in _v_device_setup])

# 2 User identification
user_identification_violations := sort([m | some m in _v_user_identification])

# 3 High availability
high_availability_violations := sort([m | some m in _v_high_availability])

# 4 Dynamic updates
dynamic_updates_violations := sort([m | some m in _v_dynamic_updates])

# 5 WildFire
wildfire_violations := sort([m | some m in _v_wildfire])

# 6 Security profiles
security_profiles_violations := sort([m | some m in _v_security_profiles])

# 7 Security policies
security_policies_violations := sort([m | some m in _v_security_policies])

# 8 Decryption
decryption_violations := sort([m | some m in _v_decryption])

# ── helpers ──────────────────────────────────────────────────────────────────
# profile selection: input.cis_profile.level 1 or 2 (Level 2 includes Level 1); absent or other => 2, the stricter
default _level := 2

_level := 1 if input.cis_profile.level == 1

_applies(id) if recommendations[id].level <= _level

# PAN-OS booleans are "yes" / "no"; absent is the PAN-OS default ("no")
_yes(o, k) if lower(sprintf("%v", [object.get(o, k, "no")])) == "yes"

_nonempty(v) if {
	is_string(v)
	trim_space(v) != ""
}

# an entry list (always an array in the contract); anything else reads as empty
_l(o, k) := v if {
	v := object.get(o, k, [])
	is_array(v)
}

_l(o, k) := [] if not is_array(object.get(o, k, []))

_ls(o, k) := {lower(sprintf("%v", [x])) | some x in _l(o, k)}

# an action written as a string ("reset-both") or as converted XML ({"reset-both": {}})
_act(a) := lower(a) if is_string(a)

_act(a) := lower(k) if {
	is_object(a)
	count(a) == 1
	some k, _ in a
}

# ── security rules (disabled rules are skipped) ──
_rules := [r | some r in input.panos_config.rulebase.security; not _yes(r, "disabled")]

_allow_rules := [r | some r in _rules; lower(object.get(r, "action", "")) == "allow"]

_deny(r) if lower(object.get(r, "action", "")) in {"deny", "drop", "reset-client", "reset-server", "reset-both"}

_untrusted := {lower(z) | some z in input.panos_config.site.untrusted_zones}

# a rule zone of "any" reaches the Internet
_inet := {lower(z) | some z in input.panos_config.site.internet_zones} | {"any"}

_to_inet(r) if {
	some z in _ls(r, "to")
	z in _inet
}

_from_inet(r) if {
	some z in _ls(r, "from")
	z in _inet
}

_inet_either(r) if _to_inet(r)

_inet_either(r) if _from_inet(r)

_inet_out_rules := [r | some r in _allow_rules; _to_inet(r)]

_inet_rules := [r | some r in _allow_rules; _inet_either(r)]

_to_all_untrusted(r) if "any" in _ls(r, "to")

_to_all_untrusted(r) if count(_untrusted - _ls(r, "to")) == 0

_from_untrusted(r) if {
	some z in _ls(r, "from")
	z in (_untrusted | {"any"})
}

_to_trusted(r) if {
	some z in _ls(r, "to")
	not z in _untrusted
}

_untrusted_inbound := [r | some r in _allow_rules; _from_untrusted(r); _to_trusted(r)]

_app_named(r) if {
	count(_ls(r, "application")) > 0
	not "any" in _ls(r, "application")
}

_service_named(r) if {
	count(_ls(r, "service")) > 0
	not "any" in _ls(r, "service")
}

# Palo Alto Networks predefined external dynamic lists (malicious, high-risk, Tor exit, bulletproof)
_edls := {"panw-known-ip-list", "panw-highrisk-ip-list", "panw-torexit-ip-list", "panw-bulletproof-ip-list"}

_edl_deny(field) if {
	some r in _rules
	_deny(r)
	count(_edls - _ls(r, field)) == 0
}

# security profiles a rule applies, directly or through a profile group
_ps(r) := object.get(r, "profile_setting", {})

_group_profiles(r, kind) := {n |
	some g in _l(_ps(r), "group")
	some pg in _l(input.panos_config, "profile_group")
	pg.name == g
	some n in _l(pg, kind)
}

_rule_profiles(r, kind) := {n | some n in _l(object.get(_ps(r), "profiles", {}), kind)} | _group_profiles(r, kind)

_has_profile(r, kind) if count(_rule_profiles(r, kind)) > 0

_inuse(kind) := {n | some r in _allow_rules; some n in _rule_profiles(r, kind)}

_licensed(names) if {
	some l in input.panos_config.licenses
	lower(object.get(l, "feature", "")) in names
	not _yes(l, "expired")
}

_uid_zones := [z | some z in input.panos_config.zone; _yes(z, "enable_user_identification")]

# ── device setup ──
_log_types := ["system", "config", "userid", "hipmatch", "iptag"]

_syslog_profiles := {p.name |
	some p in input.panos_config.shared.server_profile.syslog
	srv := _l(p, "server")
	count(srv) > 0
	every s in srv { _nonempty(object.get(s, "server", "")) }
}

_snmpv3_profiles := {p.name |
	some p in input.panos_config.shared.server_profile.snmptrap
	lower(object.get(p, "version", "")) == "v3"
	srv := _l(p, "server")
	count(srv) > 0
	every s in srv {
		every k in ["manager", "user", "engineid", "authpwd"] { _nonempty(object.get(s, k, "")) }
	}
}

# every log type has an "All Logs" match sending to the destination, and every destination named is a valid profile
_log_dest_ok(field, profs) if {
	count(profs) > 0
	every t in _log_types {
		ms := _l(object.get(input.panos_config.shared.log_settings, t, {}), "match_list")
		some m in ms
		lower(object.get(m, "filter", "")) == "all logs"
		count(_l(m, field)) > 0
		every m2 in ms {
			every s in _l(m2, field) { s in profs }
		}
	}
}

_expiry_ok(pp) if {
	n := to_number(object.get(object.get(pp, "password_change", {}), "expiration_period", 0))
	n > 0
	n <= 90
}

# 0 failed attempts or 0 lockout time means lockout is off
_lockout_ok(a) if {
	lo := object.get(a, "lockout", {})
	to_number(object.get(lo, "failed_attempts", 0)) > 0
	to_number(object.get(lo, "lockout_time", 0)) > 0
}

default _ntp_ok := false

_ntp_ok if {
	s := input.panos_config.deviceconfig.system.ntp_servers
	p := object.get(object.get(s, "primary_ntp_server", {}), "ntp_server_address", "")
	q := object.get(object.get(s, "secondary_ntp_server", {}), "ntp_server_address", "")
	_nonempty(p)
	_nonempty(q)
	lower(p) != lower(q)
}

# ── high availability ──
_monitor_ok(m, groups, members) if {
	_yes(m, "enabled")
	lower(object.get(m, "failure_condition", "")) == "any"
	some g in _l(m, groups)
	_yes(g, "enabled")
	count(_l(g, members)) > 0
}

# ── WildFire ──
_sends(m) if {
	some k in ["send_syslog", "send_snmptrap", "send_email", "send_http"]
	count(_l(m, k)) > 0
}

_wf_inline_ok(p) if {
	_yes(p, "cloud_inline_analysis")
	some x in _l(p, "inline_cloud_rules")
	"any" in _ls(x, "application")
	"pe" in _ls(x, "file_type")
	lower(object.get(x, "direction", "")) == "both"
	_act(object.get(x, "action", "")) == "block"
}

# ── security profiles ──
_av_decoders_ok(p, k) if {
	ds := _l(p, "decoder")
	count(ds) > 0
	every d in ds { _decoder_ok(d, k) }
}

_decoder_ok(d, k) if _act(object.get(d, k, "")) == "reset-both"

_decoder_ok(d, k) if {
	lower(object.get(d, "name", "")) in {"imap", "pop3"}
	_act(object.get(d, k, "")) == "alert"
}

_mlav_ok(p) if {
	ms := _l(p, "mlav_engine_filebased_enabled")
	count(ms) > 0
	every m in ms { lower(object.get(m, "mlav_policy_action", "")) == "enable" }
}

_spyware_block_rule(p) if {
	some x in _l(p, "rules")
	_act(object.get(x, "action", "")) == "reset-both"
	count({"critical", "high", "medium"} - _ls(x, "severity")) == 0
	lower(object.get(x, "category", "any")) == "any"
	lower(object.get(x, "threat_name", "any")) == "any"
}

_sinkhole_ok(p) if {
	bd := object.get(p, "botnet_domains", {})
	some l in _l(bd, "lists")
	lower(object.get(l, "name", "")) == "default-paloalto-dns"
	_act(object.get(l, "action", "")) == "sinkhole"
	sh := object.get(bd, "sinkhole", {})
	_nonempty(object.get(sh, "ipv4_address", ""))
	_nonempty(object.get(sh, "ipv6_address", ""))
}

_dns_security_ok(p) if {
	cats := _l(object.get(p, "botnet_domains", {}), "dns_security_categories")
	count(cats) > 0
	every c in cats { _act(object.get(c, "action", "")) == "sinkhole" }
	some c in cats
	lower(object.get(c, "name", "")) == "pan-dns-sec-cc"
	lower(object.get(c, "packet_capture", "")) == "extended-capture"
}

_inline_cloud_ok(p, k, want) if {
	_yes(p, "cloud_inline_analysis")
	ms := _l(p, k)
	count(ms) > 0
	every m in ms { _act(object.get(m, "inline_policy_action", "")) == want }
}

_block_acts := {"block-ip", "drop", "reset-both", "reset-client", "reset-server", "block"}

# every rule matching the severity (or "any") takes one of the actions, and at least one rule matches
_vuln_sev(p, s, acts) if {
	xs := [x | some x in _l(p, "rules"); count({s, "any"} & _ls(x, "severity")) > 0]
	count(xs) > 0
	every x in xs { _act(object.get(x, "action", "")) in acts }
}

_vuln_ok(p) if {
	every s in ["critical", "high"] { _vuln_sev(p, s, _block_acts) }
	every s in ["medium", "low", "informational"] { _vuln_sev(p, s, _block_acts | {"default"}) }
}

_url_header_logging(p) if {
	not _yes(p, "log_container_page_only")
	_yes(p, "log_http_hdr_user_agent")
	_yes(p, "log_http_hdr_referer")
	_yes(p, "log_http_hdr_xff")
}

# credential detection on; every category the profile lets through blocks or continues credential submission
_cred_ok(p) if {
	ce := object.get(p, "credential_enforcement", {})
	lower(object.get(ce, "mode", "disabled")) != "disabled"
	_nonempty(object.get(ce, "log_severity", ""))
	count(_l(ce, "allow")) == 0
	count(_l(ce, "alert")) == 0
	count((_ls(p, "alert") | _ls(p, "allow")) - (_ls(ce, "block") | _ls(ce, "continue"))) == 0
}

# ── zone protection ──
_zpp(z) := p if {
	some p in input.panos_config.network.profiles.zone_protection
	p.name == object.get(z, "zone_protection_profile", "")
}

_untrusted_zone_objs := [z | some z in input.panos_config.zone; lower(z.name) in _untrusted]

# every zone the site lists as untrusted exists in the collected zone list
default _untrusted_known := false

_untrusted_known if count(_untrusted - {lower(z.name) | some z in input.panos_config.zone}) == 0

_rate_ok(f) if {
	every k in ["alarm_rate", "activate_rate", "maximal_rate"] { to_number(object.get(f, k, 0)) > 0 }
}

_syn_cookies(p) if {
	f := object.get(object.get(p, "flood", {}), "tcp_syn", {})
	_yes(f, "enable")
	lower(object.get(f, "action", "")) == "syn-cookies"
	_rate_ok(f)
}

_floods_ok(p) if {
	fl := object.get(p, "flood", {})
	every t in ["tcp_syn", "udp", "icmp", "icmpv6", "other_ip"] {
		f := object.get(fl, t, {})
		_yes(f, "enable")
		_rate_ok(f)
	}
}

_scan_ok(s, k, acts) if {
	x := object.get(s, k, {})
	_yes(x, "enable")
	lower(object.get(x, "action", "")) in acts
	to_number(object.get(x, "interval", 0)) > 0
	to_number(object.get(x, "threshold", 0)) > 0
}

_recon_ok(p) if {
	s := object.get(p, "scan", {})
	_scan_ok(s, "tcp_port_scan", {"block-ip"})
	lower(object.get(s.tcp_port_scan, "track_by", "")) == "source"
	to_number(object.get(s.tcp_port_scan, "duration", 0)) > 0
	_scan_ok(s, "host_sweep", {"block", "block-ip"})
	_scan_ok(s, "udp_port_scan", {"alert", "block", "block-ip"})
}

_drops_ok(p) if {
	every k in [
		"discard_ip_spoof", "discard_overlapping_tcp_segment_mismatch", "discard_strict_source_routing",
		"discard_loose_source_routing", "discard_malformed_option",
	] {
		_yes(p, k)
	}
}

# ── decryption ──
_forward_proxy_inet(d) if {
	not _yes(d, "disabled")
	_act(object.get(d, "action", "")) == "decrypt"
	_act(object.get(d, "type", "")) == "ssl-forward-proxy"
	_to_inet(d)
}

# 1.1.1.1 (Automated, Level 1)
default r_1_1_1_1 := false

r_1_1_1_1 if {
	_log_dest_ok("send_syslog", _syslog_profiles)
}

default e_1_1_1_1 := false

e_1_1_1_1 if {
	is_array(input.panos_config.shared.server_profile.syslog)
	is_object(input.panos_config.shared.log_settings)
	count(input.panos_config.shared.log_settings) > 0
}

_v_device_setup contains "1.1.1.1: evidence missing — panos_config.shared.{server_profile.syslog,log_settings} not collected" if {
	_applies("1.1.1.1")
	not e_1_1_1_1
}

_v_device_setup contains "1.1.1.1: system, config, User-ID, HIP-match and IP-tag logs must all forward to a valid syslog server profile" if {
	_applies("1.1.1.1")
	e_1_1_1_1
	not r_1_1_1_1
}

# 1.1.1.2 (Automated, Level 2)
default r_1_1_1_2 := false

r_1_1_1_2 if {
	_log_dest_ok("send_snmptrap", _snmpv3_profiles)
}

default e_1_1_1_2 := false

e_1_1_1_2 if {
	is_array(input.panos_config.shared.server_profile.snmptrap)
	is_object(input.panos_config.shared.log_settings)
	count(input.panos_config.shared.log_settings) > 0
}

_v_device_setup contains "1.1.1.2: evidence missing — panos_config.shared.{server_profile.snmptrap,log_settings} not collected" if {
	_applies("1.1.1.2")
	not e_1_1_1_2
}

_v_device_setup contains "1.1.1.2: system, config, User-ID, HIP-match and IP-tag logs must all send traps to an SNMP v3 trap profile" if {
	_applies("1.1.1.2")
	e_1_1_1_2
	not r_1_1_1_2
}

# 1.1.2 (Automated, Level 1)
default r_1_1_2 := false

r_1_1_2 if {
	is_string(input.panos_config.deviceconfig.system.login_banner)
	trim_space(input.panos_config.deviceconfig.system.login_banner) != ""
}

default e_1_1_2 := false

e_1_1_2 if {
	is_object(input.panos_config.deviceconfig.system)
}

_v_device_setup contains "1.1.2: evidence missing — panos_config.deviceconfig.system not collected" if {
	_applies("1.1.2")
	not e_1_1_2
}

_v_device_setup contains "1.1.2: a login banner must be configured" if {
	_applies("1.1.2")
	e_1_1_2
	not r_1_1_2
}

# 1.1.3 (Automated, Level 1)
default r_1_1_3 := false

r_1_1_3 if {
	input.panos_config.deviceconfig.setting.management.enable_log_high_dp_load == "yes"
}

default e_1_1_3 := false

e_1_1_3 if {
	is_object(input.panos_config.deviceconfig.setting.management)
}

_v_device_setup contains "1.1.3: evidence missing — panos_config.deviceconfig.setting.management not collected" if {
	_applies("1.1.3")
	not e_1_1_3
}

_v_device_setup contains "1.1.3: logging under high dataplane load must be turned on" if {
	_applies("1.1.3")
	e_1_1_3
	not r_1_1_3
}

# 1.2.1 (Manual, Level 1)
default r_1_2_1 := false

r_1_2_1 if {
	input.panos_config.attest.management_permitted_ips_reviewed == true
}

_v_device_setup contains "1.2.1: management interface permitted IPs must be limited to the management hosts (manual review not attested)" if {
	_applies("1.2.1")
	not r_1_2_1
}

# 1.2.2 (Manual, Level 1)
default r_1_2_2 := false

r_1_2_2 if {
	input.panos_config.attest.management_profile_permitted_ips_reviewed == true
}

_v_device_setup contains "1.2.2: interface management profiles offering SSH, HTTPS or SNMP must restrict permitted IPs (manual review not attested)" if {
	_applies("1.2.2")
	not r_1_2_2
}

# 1.2.3 (Automated, Level 1)
default r_1_2_3 := false

r_1_2_3 if {
	input.panos_config.deviceconfig.system.service.disable_http == "yes"
	input.panos_config.deviceconfig.system.service.disable_telnet == "yes"
}

default e_1_2_3 := false

e_1_2_3 if {
	is_object(input.panos_config.deviceconfig.system.service)
}

_v_device_setup contains "1.2.3: evidence missing — panos_config.deviceconfig.system.service not collected" if {
	_applies("1.2.3")
	not e_1_2_3
}

_v_device_setup contains "1.2.3: the management interface must not offer HTTP or Telnet" if {
	_applies("1.2.3")
	e_1_2_3
	not r_1_2_3
}

# 1.2.4 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_2_4 := false

r_1_2_4 if {
	every p in input.panos_config.network.profiles.interface_management { not _yes(p, "http"); not _yes(p, "telnet")}
}

default e_1_2_4 := false

e_1_2_4 if {
	is_array(input.panos_config.network.profiles.interface_management)
}

_v_device_setup contains "1.2.4: evidence missing — panos_config.network.profiles.interface_management not collected" if {
	_applies("1.2.4")
	not e_1_2_4
}

_v_device_setup contains "1.2.4: interface management profiles must not offer HTTP or Telnet" if {
	_applies("1.2.4")
	e_1_2_4
	not r_1_2_4
}

# 1.2.5 (Manual, Level 2)
default r_1_2_5 := false

r_1_2_5 if {
	input.panos_config.attest.admin_web_certificate_valid == true
}

_v_device_setup contains "1.2.5: the web admin interface certificate must be valid and trusted (manual review not attested)" if {
	_applies("1.2.5")
	not r_1_2_5
}

# 1.3.1 (Automated, Level 1)
default r_1_3_1 := false

r_1_3_1 if {
	input.panos_config.mgt_config.password_complexity.enabled == "yes"
	input.panos_config.mgt_config.password_complexity.block_username_inclusion == "yes"
}

default e_1_3_1 := false

e_1_3_1 if {
	is_object(input.panos_config.mgt_config.password_complexity)
}

_v_device_setup contains "1.3.1: evidence missing — panos_config.mgt_config.password_complexity not collected" if {
	_applies("1.3.1")
	not e_1_3_1
}

_v_device_setup contains "1.3.1: admin password complexity must be enforced with username inclusion blocked" if {
	_applies("1.3.1")
	e_1_3_1
	not r_1_3_1
}

# 1.3.2 (Automated, Level 1)
default r_1_3_2 := false

r_1_3_2 if {
	to_number(input.panos_config.mgt_config.password_complexity.minimum_length) >= 12
}

default e_1_3_2 := false

e_1_3_2 if {
	is_object(input.panos_config.mgt_config.password_complexity)
}

_v_device_setup contains "1.3.2: evidence missing — panos_config.mgt_config.password_complexity not collected" if {
	_applies("1.3.2")
	not e_1_3_2
}

_v_device_setup contains "1.3.2: admin passwords must be at least 12 characters long" if {
	_applies("1.3.2")
	e_1_3_2
	not r_1_3_2
}

# 1.3.3 (Automated, Level 1)
default r_1_3_3 := false

r_1_3_3 if {
	to_number(input.panos_config.mgt_config.password_complexity.minimum_uppercase_letters) >= 1
}

default e_1_3_3 := false

e_1_3_3 if {
	is_object(input.panos_config.mgt_config.password_complexity)
}

_v_device_setup contains "1.3.3: evidence missing — panos_config.mgt_config.password_complexity not collected" if {
	_applies("1.3.3")
	not e_1_3_3
}

_v_device_setup contains "1.3.3: admin passwords must contain at least 1 upper-case letter" if {
	_applies("1.3.3")
	e_1_3_3
	not r_1_3_3
}

# 1.3.4 (Automated, Level 1)
default r_1_3_4 := false

r_1_3_4 if {
	to_number(input.panos_config.mgt_config.password_complexity.minimum_lowercase_letters) >= 1
}

default e_1_3_4 := false

e_1_3_4 if {
	is_object(input.panos_config.mgt_config.password_complexity)
}

_v_device_setup contains "1.3.4: evidence missing — panos_config.mgt_config.password_complexity not collected" if {
	_applies("1.3.4")
	not e_1_3_4
}

_v_device_setup contains "1.3.4: admin passwords must contain at least 1 lower-case letter" if {
	_applies("1.3.4")
	e_1_3_4
	not r_1_3_4
}

# 1.3.5 (Automated, Level 1)
default r_1_3_5 := false

r_1_3_5 if {
	to_number(input.panos_config.mgt_config.password_complexity.minimum_numeric_letters) >= 1
}

default e_1_3_5 := false

e_1_3_5 if {
	is_object(input.panos_config.mgt_config.password_complexity)
}

_v_device_setup contains "1.3.5: evidence missing — panos_config.mgt_config.password_complexity not collected" if {
	_applies("1.3.5")
	not e_1_3_5
}

_v_device_setup contains "1.3.5: admin passwords must contain at least 1 digit" if {
	_applies("1.3.5")
	e_1_3_5
	not r_1_3_5
}

# 1.3.6 (Automated, Level 1)
default r_1_3_6 := false

r_1_3_6 if {
	to_number(input.panos_config.mgt_config.password_complexity.minimum_special_characters) >= 1
}

default e_1_3_6 := false

e_1_3_6 if {
	is_object(input.panos_config.mgt_config.password_complexity)
}

_v_device_setup contains "1.3.6: evidence missing — panos_config.mgt_config.password_complexity not collected" if {
	_applies("1.3.6")
	not e_1_3_6
}

_v_device_setup contains "1.3.6: admin passwords must contain at least 1 special character" if {
	_applies("1.3.6")
	e_1_3_6
	not r_1_3_6
}

# 1.3.7 (Automated, Level 1)
default r_1_3_7 := false

r_1_3_7 if {
	n := to_number(input.panos_config.mgt_config.password_complexity.password_change.expiration_period)
	n > 0
	n <= 90
}

default e_1_3_7 := false

e_1_3_7 if {
	is_object(input.panos_config.mgt_config.password_complexity)
}

_v_device_setup contains "1.3.7: evidence missing — panos_config.mgt_config.password_complexity not collected" if {
	_applies("1.3.7")
	not e_1_3_7
}

_v_device_setup contains "1.3.7: admin passwords must expire within 1 to 90 days" if {
	_applies("1.3.7")
	e_1_3_7
	not r_1_3_7
}

# 1.3.8 (Automated, Level 1)
default r_1_3_8 := false

r_1_3_8 if {
	to_number(input.panos_config.mgt_config.password_complexity.new_password_differs_by_characters) >= 3
}

default e_1_3_8 := false

e_1_3_8 if {
	is_object(input.panos_config.mgt_config.password_complexity)
}

_v_device_setup contains "1.3.8: evidence missing — panos_config.mgt_config.password_complexity not collected" if {
	_applies("1.3.8")
	not e_1_3_8
}

_v_device_setup contains "1.3.8: a new admin password must differ from the old one by at least 3 characters" if {
	_applies("1.3.8")
	e_1_3_8
	not r_1_3_8
}

# 1.3.9 (Automated, Level 1)
default r_1_3_9 := false

r_1_3_9 if {
	to_number(input.panos_config.mgt_config.password_complexity.password_history_count) >= 24
}

default e_1_3_9 := false

e_1_3_9 if {
	is_object(input.panos_config.mgt_config.password_complexity)
}

_v_device_setup contains "1.3.9: evidence missing — panos_config.mgt_config.password_complexity not collected" if {
	_applies("1.3.9")
	not e_1_3_9
}

_v_device_setup contains "1.3.9: admin passwords must not repeat any of the last 24" if {
	_applies("1.3.9")
	e_1_3_9
	not r_1_3_9
}

# 1.3.10 (Automated, Level 1)
default r_1_3_10 := false

r_1_3_10 if {
	every pp in input.panos_config.mgt_config.password_profile { _expiry_ok(pp) }
}

default e_1_3_10 := false

e_1_3_10 if {
	is_array(input.panos_config.mgt_config.password_profile)
}

_v_device_setup contains "1.3.10: evidence missing — panos_config.mgt_config.password_profile not collected" if {
	_applies("1.3.10")
	not e_1_3_10
}

_v_device_setup contains "1.3.10: password profiles must not be weaker than the global rules (expiry 1 to 90 days)" if {
	_applies("1.3.10")
	e_1_3_10
	not r_1_3_10
}

# 1.4.1 (Automated, Level 1)
default r_1_4_1 := false

r_1_4_1 if {
	n := to_number(input.panos_config.deviceconfig.setting.management.idle_timeout)
	n > 0
	n <= 10
}

default e_1_4_1 := false

e_1_4_1 if {
	is_object(input.panos_config.deviceconfig.setting.management)
}

_v_device_setup contains "1.4.1: evidence missing — panos_config.deviceconfig.setting.management not collected" if {
	_applies("1.4.1")
	not e_1_4_1
}

_v_device_setup contains "1.4.1: management idle timeout must be 1 to 10 minutes" if {
	_applies("1.4.1")
	e_1_4_1
	not r_1_4_1
}

# 1.4.2 (Automated, Level 1)
default r_1_4_2 := false

r_1_4_2 if {
	every a in input.panos_config.shared.authentication_profile { _lockout_ok(a) }
}

default e_1_4_2 := false

e_1_4_2 if {
	is_array(input.panos_config.shared.authentication_profile)
	count(input.panos_config.shared.authentication_profile) > 0
}

_v_device_setup contains "1.4.2: evidence missing — panos_config.shared.authentication_profile not collected" if {
	_applies("1.4.2")
	not e_1_4_2
}

_v_device_setup contains "1.4.2: authentication profiles must lock out after failed attempts for a non-zero time" if {
	_applies("1.4.2")
	e_1_4_2
	not r_1_4_2
}

# 1.5.1 (Automated, Level 1)
default r_1_5_1 := false

r_1_5_1 if {
	lower(input.panos_config.deviceconfig.system.snmp_setting.access_setting.version) == "v3"
}

default e_1_5_1 := false

e_1_5_1 if {
	is_object(input.panos_config.deviceconfig.system.snmp_setting)
}

_v_device_setup contains "1.5.1: evidence missing — panos_config.deviceconfig.system.snmp_setting not collected" if {
	_applies("1.5.1")
	not e_1_5_1
}

_v_device_setup contains "1.5.1: SNMP polling must use version 3" if {
	_applies("1.5.1")
	e_1_5_1
	not r_1_5_1
}

# 1.6.1 (Automated, Level 1)
default r_1_6_1 := false

r_1_6_1 if {
	input.panos_config.deviceconfig.system.server_verification == "yes"
}

default e_1_6_1 := false

e_1_6_1 if {
	is_object(input.panos_config.deviceconfig.system)
}

_v_device_setup contains "1.6.1: evidence missing — panos_config.deviceconfig.system not collected" if {
	_applies("1.6.1")
	not e_1_6_1
}

_v_device_setup contains "1.6.1: the update server identity must be verified" if {
	_applies("1.6.1")
	e_1_6_1
	not r_1_6_1
}

# 1.6.2 (Automated, Level 1)
default r_1_6_2 := false

r_1_6_2 if {
	_ntp_ok
}

default e_1_6_2 := false

e_1_6_2 if {
	is_object(input.panos_config.deviceconfig.system.ntp_servers)
}

_v_device_setup contains "1.6.2: evidence missing — panos_config.deviceconfig.system.ntp_servers not collected" if {
	_applies("1.6.2")
	not e_1_6_2
}

_v_device_setup contains "1.6.2: two distinct NTP servers must be configured" if {
	_applies("1.6.2")
	e_1_6_2
	not r_1_6_2
}

# 1.6.3 (Manual, Level 2)
default r_1_6_3 := false

r_1_6_3 if {
	input.panos_config.attest.vpn_certificate_valid == true
}

_v_device_setup contains "1.6.3: the remote access VPN certificate and its TLS minimum must be valid (manual review not attested)" if {
	_applies("1.6.3")
	not r_1_6_3
}

# 1.7.1 (Manual, Level 2)
default r_1_7_1 := false

r_1_7_1 if {
	input.panos_config.attest.ikev2_post_quantum_ppk_enabled == true
}

_v_device_setup contains "1.7.1: IKEv2 VPN gateways must use a post-quantum pre-shared key (manual review not attested)" if {
	_applies("1.7.1")
	not r_1_7_1
}

# 2.1 (Automated, Level 2)
default r_2_1 := false

r_2_1 if {
	input.panos_config.attest.user_mapping_verified_in_logs == true
}

_v_user_identification contains "2.1: traffic from trusted zones must carry a mapped user name (manual review not attested)" if {
	_applies("2.1")
	not r_2_1
}

# 2.2 (Automated, Level 2)
default r_2_2 := false

r_2_2 if {
	not _yes(input.panos_config.user_id.setting, "enable_probing")
}

default e_2_2 := false

e_2_2 if {
	is_object(input.panos_config.user_id.setting)
}

_v_user_identification contains "2.2: evidence missing — panos_config.user_id.setting not collected" if {
	_applies("2.2")
	not e_2_2
}

_v_user_identification contains "2.2: User-ID client (WMI) probing must be off" if {
	_applies("2.2")
	e_2_2
	not r_2_2
}

# 2.3 (Automated, Level 1)
default r_2_3 := false

r_2_3 if {
	count({lower(z.name) | some z in _uid_zones} & _untrusted) == 0
}

default e_2_3 := false

e_2_3 if {
	is_array(input.panos_config.zone)
	count(input.panos_config.zone) > 0
	is_array(input.panos_config.site.untrusted_zones)
	count(input.panos_config.site.untrusted_zones) > 0
}

_v_user_identification contains "2.3: evidence missing — panos_config.{zone,site.untrusted_zones} not collected" if {
	_applies("2.3")
	not e_2_3
}

_v_user_identification contains "2.3: User-ID must be on only for trusted internal zones" if {
	_applies("2.3")
	e_2_3
	not r_2_3
}

# 2.4 (Automated, Level 1)
default r_2_4 := false

r_2_4 if {
	count(_uid_zones) == 0
}

r_2_4 if {
	some e in input.panos_config.user_id.include_exclude_network
	lower(object.get(e, "discovery", "")) == "include"
	_nonempty(object.get(e, "network_address", ""))
}

default e_2_4 := false

e_2_4 if {
	is_array(input.panos_config.zone)
	count(input.panos_config.zone) > 0
	is_array(input.panos_config.user_id.include_exclude_network)
}

_v_user_identification contains "2.4: evidence missing — panos_config.{zone,user_id.include_exclude_network} not collected" if {
	_applies("2.4")
	not e_2_4
}

_v_user_identification contains "2.4: with User-ID on, the user mapping must name its trusted networks as include entries" if {
	_applies("2.4")
	e_2_4
	not r_2_4
}

# 2.5 (Manual, Level 1)
default r_2_5 := false

r_2_5 if {
	input.panos_config.attest.userid_account_minimal_groups == true
}

_v_user_identification contains "2.5: the User-ID agent account must hold only the minimal group memberships (manual review not attested)" if {
	_applies("2.5")
	not r_2_5
}

# 2.6 (Automated, Level 1)
default r_2_6 := false

r_2_6 if {
	input.panos_config.attest.userid_account_no_interactive_logon == true
}

_v_user_identification contains "2.6: the User-ID service account must be denied interactive logon (manual review not attested)" if {
	_applies("2.6")
	not r_2_6
}

# 2.7 (Manual, Level 1)
default r_2_7 := false

r_2_7 if {
	input.panos_config.attest.userid_account_no_remote_access == true
}

_v_user_identification contains "2.7: the User-ID service account must have no remote access rights (manual review not attested)" if {
	_applies("2.7")
	not r_2_7
}

# 2.8 (Automated, Level 1)
default r_2_8 := false

r_2_8 if {
	some r in _rules
	_deny(r)
	"msrpc" in _ls(r, "application")
	_to_all_untrusted(r)
}

default e_2_8 := false

e_2_8 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
	is_array(input.panos_config.site.untrusted_zones)
	count(input.panos_config.site.untrusted_zones) > 0
}

_v_user_identification contains "2.8: evidence missing — panos_config.{rulebase.security,site.untrusted_zones} not collected" if {
	_applies("2.8")
	not e_2_8
}

_v_user_identification contains "2.8: a rule must block msrpc from the User-ID agent toward every untrusted zone" if {
	_applies("2.8")
	e_2_8
	not r_2_8
}

# 3.1 (Automated, Level 1)
default r_3_1 := false

r_3_1 if {
	input.panos_config.deviceconfig.high_availability.enabled == "yes"
	is_string(input.panos_config.deviceconfig.high_availability.interface.ha2.port)
	input.panos_config.deviceconfig.high_availability.interface.ha2.port != ""
	input.panos_config.deviceconfig.high_availability.state_synchronization.enabled == "yes"
}

default e_3_1 := false

e_3_1 if {
	is_object(input.panos_config.deviceconfig.high_availability)
}

_v_high_availability contains "3.1: evidence missing — panos_config.deviceconfig.high_availability not collected" if {
	_applies("3.1")
	not e_3_1
}

_v_high_availability contains "3.1: HA must be on with an HA2 data link and session synchronization" if {
	_applies("3.1")
	e_3_1
	not r_3_1
}

# 3.2 (Automated, Level 1)
default r_3_2 := false

r_3_2 if {
	_monitor_ok(object.get(input.panos_config.deviceconfig.high_availability, "link_monitoring", {}), "link_group", "interface")
}

r_3_2 if {
	_monitor_ok(object.get(input.panos_config.deviceconfig.high_availability, "path_monitoring", {}), "path_group", "destination_ip")
}

default e_3_2 := false

e_3_2 if {
	is_object(input.panos_config.deviceconfig.high_availability)
}

_v_high_availability contains "3.2: evidence missing — panos_config.deviceconfig.high_availability not collected" if {
	_applies("3.2")
	not e_3_2
}

_v_high_availability contains "3.2: HA must fail over on link or path monitoring (failure condition any)" if {
	_applies("3.2")
	e_3_2
	not r_3_2
}

# 3.3 (Automated, Level 1)
default r_3_3 := false

r_3_3 if {
	input.panos_config.deviceconfig.high_availability.active_passive.passive_link_state == "auto"
	not _yes(object.get(input.panos_config.deviceconfig.high_availability, "election_option", {}), "preemptive")
}

default e_3_3 := false

e_3_3 if {
	is_object(input.panos_config.deviceconfig.high_availability)
}

_v_high_availability contains "3.3: evidence missing — panos_config.deviceconfig.high_availability not collected" if {
	_applies("3.3")
	not e_3_3
}

_v_high_availability contains "3.3: HA passive link state must be auto and preemption must be off" if {
	_applies("3.3")
	e_3_3
	not r_3_3
}

# 4.1 (Automated, Level 1)
default r_4_1 := false

r_4_1 if {
	input.panos_config.deviceconfig.system.update_schedule.anti_virus.action == "download-and-install"
	input.panos_config.deviceconfig.system.update_schedule.anti_virus.recurrence == "hourly"
}

default e_4_1 := false

e_4_1 if {
	is_object(input.panos_config.deviceconfig.system.update_schedule)
}

_v_dynamic_updates contains "4.1: evidence missing — panos_config.deviceconfig.system.update_schedule not collected" if {
	_applies("4.1")
	not e_4_1
}

_v_dynamic_updates contains "4.1: antivirus content must download and install hourly" if {
	_applies("4.1")
	e_4_1
	not r_4_1
}

# 4.2 (Automated, Level 1)
default r_4_2 := false

r_4_2 if {
	input.panos_config.deviceconfig.system.update_schedule.threats.action == "download-and-install"
	input.panos_config.deviceconfig.system.update_schedule.threats.recurrence in {"daily", "hourly", "every-30-mins", "every-15-mins", "every-5-mins", "every-min"}
}

default e_4_2 := false

e_4_2 if {
	is_object(input.panos_config.deviceconfig.system.update_schedule)
}

_v_dynamic_updates contains "4.2: evidence missing — panos_config.deviceconfig.system.update_schedule not collected" if {
	_applies("4.2")
	not e_4_2
}

_v_dynamic_updates contains "4.2: application and threat content must download and install at least daily" if {
	_applies("4.2")
	e_4_2
	not r_4_2
}

# 5.1 (Automated, Level 1)
default r_5_1 := false

r_5_1 if {
	input.panos_config.attest.wildfire_file_size_limits_reviewed == true
}

_v_wildfire contains "5.1: WildFire upload size limits must be at or above the defaults (manual review not attested)" if {
	_applies("5.1")
	not r_5_1
}

# 5.2 (Automated, Level 1)
default r_5_2 := false

r_5_2 if {
	every r in _allow_rules { _has_profile(r, "wildfire_analysis") }
}

default e_5_2 := false

e_5_2 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
	is_array(input.panos_config.profiles.wildfire_analysis)
	count(input.panos_config.profiles.wildfire_analysis) > 0
}

_v_wildfire contains "5.2: evidence missing — panos_config.{rulebase.security,profiles.wildfire_analysis} not collected" if {
	_applies("5.2")
	not e_5_2
}

_v_wildfire contains "5.2: every allow rule must carry a WildFire analysis profile" if {
	_applies("5.2")
	e_5_2
	not r_5_2
}

# 5.3 (Automated, Level 1)
default r_5_3 := false

r_5_3 if {
	input.panos_config.deviceconfig.setting.ssl_decrypt.allow_forward_decrypted_content == "yes"
}

default e_5_3 := false

e_5_3 if {
	is_object(input.panos_config.deviceconfig.setting.ssl_decrypt)
}

_v_wildfire contains "5.3: evidence missing — panos_config.deviceconfig.setting.ssl_decrypt not collected" if {
	_applies("5.3")
	not e_5_3
}

_v_wildfire contains "5.3: decrypted content must be forwarded to WildFire" if {
	_applies("5.3")
	e_5_3
	not r_5_3
}

# 5.4 (Automated, Level 1)
default r_5_4 := false

r_5_4 if {
	every _, v in object.get(input.panos_config.deviceconfig.setting.wildfire, "session_info_select", {}) { v != "yes" }
}

default e_5_4 := false

e_5_4 if {
	is_object(input.panos_config.deviceconfig.setting.wildfire)
}

_v_wildfire contains "5.4: evidence missing — panos_config.deviceconfig.setting.wildfire not collected" if {
	_applies("5.4")
	not e_5_4
}

_v_wildfire contains "5.4: WildFire session information must include every field" if {
	_applies("5.4")
	e_5_4
	not r_5_4
}

# 5.5 (Automated, Level 1)
default r_5_5 := false

r_5_5 if {
	some lf in input.panos_config.shared.log_forwarding_profile
	some m in _l(lf, "match_list")
	lower(object.get(m, "log_type", "")) == "wildfire"
	_sends(m)
}

default e_5_5 := false

e_5_5 if {
	is_array(input.panos_config.shared.log_forwarding_profile)
}

_v_wildfire contains "5.5: evidence missing — panos_config.shared.log_forwarding_profile not collected" if {
	_applies("5.5")
	not e_5_5
}

_v_wildfire contains "5.5: WildFire logs must be forwarded to an alerting destination" if {
	_applies("5.5")
	e_5_5
	not r_5_5
}

# 5.6 (Automated, Level 1)
default r_5_6 := false

r_5_6 if {
	input.panos_config.deviceconfig.system.update_schedule.wildfire.recurrence == "real-time"
}

default e_5_6 := false

e_5_6 if {
	is_object(input.panos_config.deviceconfig.system.update_schedule)
}

_v_wildfire contains "5.6: evidence missing — panos_config.deviceconfig.system.update_schedule not collected" if {
	_applies("5.6")
	not e_5_6
}

_v_wildfire contains "5.6: WildFire content must update in real time" if {
	_applies("5.6")
	e_5_6
	not r_5_6
}

# 5.7 (Manual, Level 2)
default r_5_7 := false

r_5_7 if {
	input.panos_config.attest.wildfire_cloud_region_approved == true
}

_v_wildfire contains "5.7: the WildFire public cloud region must be the approved one (manual review not attested)" if {
	_applies("5.7")
	not r_5_7
}

# 5.8 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_5_8 := false

r_5_8 if {
	every p in input.panos_config.profiles.wildfire_analysis { _wf_inline_ok(p) }
}

default e_5_8 := false

e_5_8 if {
	is_array(input.panos_config.profiles.wildfire_analysis)
	count(input.panos_config.profiles.wildfire_analysis) > 0
}

_v_wildfire contains "5.8: evidence missing — panos_config.profiles.wildfire_analysis not collected" if {
	_applies("5.8")
	not e_5_8
}

_v_wildfire contains "5.8: WildFire profiles must block PE files through inline cloud analysis" if {
	_applies("5.8")
	e_5_8
	not r_5_8
}

# 6.1 (Automated, Level 1)
default r_6_1 := false

r_6_1 if {
	every p in input.panos_config.profiles.virus { _av_decoders_ok(p, "action"); _av_decoders_ok(p, "wildfire_action")}
}

default e_6_1 := false

e_6_1 if {
	is_array(input.panos_config.profiles.virus)
	count(input.panos_config.profiles.virus) > 0
}

_v_security_profiles contains "6.1: evidence missing — panos_config.profiles.virus not collected" if {
	_applies("6.1")
	not e_6_1
}

_v_security_profiles contains "6.1: antivirus decoders must reset both ends for signature and WildFire actions (imap and pop3 may alert)" if {
	_applies("6.1")
	e_6_1
	not r_6_1
}

# 6.2 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_2 := false

r_6_2 if {
	every r in _allow_rules { _has_profile(r, "virus") }
}

default e_6_2 := false

e_6_2 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
	is_array(input.panos_config.profiles.virus)
	count(input.panos_config.profiles.virus) > 0
}

_v_security_profiles contains "6.2: evidence missing — panos_config.{rulebase.security,profiles.virus} not collected" if {
	_applies("6.2")
	not e_6_2
}

_v_security_profiles contains "6.2: every allow rule must carry an antivirus profile" if {
	_applies("6.2")
	e_6_2
	not r_6_2
}

# 6.3 (Automated, Level 1)
default r_6_3 := false

r_6_3 if {
	some p in input.panos_config.profiles.spyware
	_spyware_block_rule(p)
}

default e_6_3 := false

e_6_3 if {
	is_array(input.panos_config.profiles.spyware)
	count(input.panos_config.profiles.spyware) > 0
}

_v_security_profiles contains "6.3: evidence missing — panos_config.profiles.spyware not collected" if {
	_applies("6.3")
	not e_6_3
}

_v_security_profiles contains "6.3: an anti-spyware profile must reset critical, high and medium threats of any category" if {
	_applies("6.3")
	e_6_3
	not r_6_3
}

# 6.4 (Automated, Level 1)
default r_6_4 := false

r_6_4 if {
	count(_inuse("spyware")) > 0
	every n in _inuse("spyware") { some p in input.panos_config.profiles.spyware; p.name == n; _sinkhole_ok(p)}
}

default e_6_4 := false

e_6_4 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
	is_array(input.panos_config.profiles.spyware)
	count(input.panos_config.profiles.spyware) > 0
}

_v_security_profiles contains "6.4: evidence missing — panos_config.{rulebase.security,profiles.spyware} not collected" if {
	_applies("6.4")
	not e_6_4
}

_v_security_profiles contains "6.4: anti-spyware profiles in use must sinkhole the Palo Alto DNS list with IPv4 and IPv6 sinkhole addresses" if {
	_applies("6.4")
	e_6_4
	not r_6_4
}

# 6.5 (Automated, Level 1)
default r_6_5 := false

r_6_5 if {
	every r in _inet_out_rules { _has_profile(r, "spyware") }
}

default e_6_5 := false

e_6_5 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
	is_array(input.panos_config.site.internet_zones)
	count(input.panos_config.site.internet_zones) > 0
	is_array(input.panos_config.profiles.spyware)
	count(input.panos_config.profiles.spyware) > 0
}

_v_security_profiles contains "6.5: evidence missing — panos_config.{rulebase.security,site.internet_zones,profiles.spyware} not collected" if {
	_applies("6.5")
	not e_6_5
}

_v_security_profiles contains "6.5: every allow rule toward the Internet must carry an anti-spyware profile" if {
	_applies("6.5")
	e_6_5
	not r_6_5
}

# 6.6 (Automated, Level 1)
default r_6_6 := false

r_6_6 if {
	some p in input.panos_config.profiles.vulnerability
	_vuln_ok(p)
}

default e_6_6 := false

e_6_6 if {
	is_array(input.panos_config.profiles.vulnerability)
	count(input.panos_config.profiles.vulnerability) > 0
}

_v_security_profiles contains "6.6: evidence missing — panos_config.profiles.vulnerability not collected" if {
	_applies("6.6")
	not e_6_6
}

_v_security_profiles contains "6.6: a vulnerability profile must block critical and high threats and keep at least the default action below" if {
	_applies("6.6")
	e_6_6
	not r_6_6
}

# 6.7 (Automated, Level 1)
default r_6_7 := false

r_6_7 if {
	every r in _allow_rules { _has_profile(r, "vulnerability") }
}

default e_6_7 := false

e_6_7 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
}

_v_security_profiles contains "6.7: evidence missing — panos_config.rulebase.security not collected" if {
	_applies("6.7")
	not e_6_7
}

_v_security_profiles contains "6.7: every allow rule must carry a vulnerability protection profile" if {
	_applies("6.7")
	e_6_7
	not r_6_7
}

# 6.8 (Automated, Level 1)
default r_6_8 := false

r_6_8 if {
	_licensed({"pan-db url filtering", "advanced url filtering"})
}

default e_6_8 := false

e_6_8 if {
	is_array(input.panos_config.licenses)
}

_v_security_profiles contains "6.8: evidence missing — panos_config.licenses not collected" if {
	_applies("6.8")
	not e_6_8
}

_v_security_profiles contains "6.8: a PAN-DB URL filtering license must be active" if {
	_applies("6.8")
	e_6_8
	not r_6_8
}

# 6.9 (Automated, Level 1)
default r_6_9 := false

r_6_9 if {
	every p in input.panos_config.profiles.url_filtering { count(_ls(input.panos_config.site, "url_block_categories") - (_ls(p, "block") | _ls(p, "override"))) == 0 }
}

default e_6_9 := false

e_6_9 if {
	is_array(input.panos_config.profiles.url_filtering)
	count(input.panos_config.profiles.url_filtering) > 0
	is_array(input.panos_config.site.url_block_categories)
	count(input.panos_config.site.url_block_categories) > 0
}

_v_security_profiles contains "6.9: evidence missing — panos_config.{profiles.url_filtering,site.url_block_categories} not collected" if {
	_applies("6.9")
	not e_6_9
}

_v_security_profiles contains "6.9: URL filtering profiles must block or override every organisation-designated category" if {
	_applies("6.9")
	e_6_9
	not r_6_9
}

# 6.10 (Automated, Level 1)
default r_6_10 := false

r_6_10 if {
	every p in input.panos_config.profiles.url_filtering { count(_l(p, "allow")) == 0 }
}

default e_6_10 := false

e_6_10 if {
	is_array(input.panos_config.profiles.url_filtering)
	count(input.panos_config.profiles.url_filtering) > 0
}

_v_security_profiles contains "6.10: evidence missing — panos_config.profiles.url_filtering not collected" if {
	_applies("6.10")
	not e_6_10
}

_v_security_profiles contains "6.10: URL filtering profiles must log (alert) every category they let through" if {
	_applies("6.10")
	e_6_10
	not r_6_10
}

# 6.11 (Automated, Level 1)
default r_6_11 := false

r_6_11 if {
	every p in input.panos_config.profiles.url_filtering { _url_header_logging(p) }
}

default e_6_11 := false

e_6_11 if {
	is_array(input.panos_config.profiles.url_filtering)
	count(input.panos_config.profiles.url_filtering) > 0
}

_v_security_profiles contains "6.11: evidence missing — panos_config.profiles.url_filtering not collected" if {
	_applies("6.11")
	not e_6_11
}

_v_security_profiles contains "6.11: URL filtering profiles must log User-Agent, Referer and X-Forwarded-For on every page" if {
	_applies("6.11")
	e_6_11
	not r_6_11
}

# 6.12 (Automated, Level 1)
default r_6_12 := false

r_6_12 if {
	every r in _inet_out_rules { _has_profile(r, "url_filtering") }
}

default e_6_12 := false

e_6_12 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
	is_array(input.panos_config.site.internet_zones)
	count(input.panos_config.site.internet_zones) > 0
}

_v_security_profiles contains "6.12: evidence missing — panos_config.{rulebase.security,site.internet_zones} not collected" if {
	_applies("6.12")
	not e_6_12
}

_v_security_profiles contains "6.12: every allow rule toward the Internet must carry a URL filtering profile" if {
	_applies("6.12")
	e_6_12
	not r_6_12
}

# 6.13 (Automated, Level 1)
default r_6_13 := false

r_6_13 if {
	some p in input.panos_config.profiles.data_filtering
	some x in _l(p, "rules")
	count(_l(x, "data_object")) > 0
	to_number(object.get(x, "alert_threshold", 0)) > 0
}

default e_6_13 := false

e_6_13 if {
	is_array(input.panos_config.profiles.data_filtering)
	count(input.panos_config.profiles.data_filtering) > 0
}

_v_security_profiles contains "6.13: evidence missing — panos_config.profiles.data_filtering not collected" if {
	_applies("6.13")
	not e_6_13
}

_v_security_profiles contains "6.13: a data filtering profile must alert on sensitive data patterns above a threshold" if {
	_applies("6.13")
	e_6_13
	not r_6_13
}

# 6.14 (Automated, Level 1)
default r_6_14 := false

r_6_14 if {
	every r in _inet_rules { _has_profile(r, "data_filtering") }
}

default e_6_14 := false

e_6_14 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
	is_array(input.panos_config.site.internet_zones)
	count(input.panos_config.site.internet_zones) > 0
}

_v_security_profiles contains "6.14: evidence missing — panos_config.{rulebase.security,site.internet_zones} not collected" if {
	_applies("6.14")
	not e_6_14
}

_v_security_profiles contains "6.14: every allow rule to or from the Internet must carry a data filtering profile" if {
	_applies("6.14")
	e_6_14
	not r_6_14
}

# 6.15 (Automated, Level 1)
default r_6_15 := false

r_6_15 if {
	_untrusted_known
	every z in _untrusted_zone_objs { _syn_cookies(_zpp(z)) }
}

default e_6_15 := false

e_6_15 if {
	is_array(input.panos_config.zone)
	count(input.panos_config.zone) > 0
	is_array(input.panos_config.site.untrusted_zones)
	count(input.panos_config.site.untrusted_zones) > 0
	is_array(input.panos_config.network.profiles.zone_protection)
}

_v_security_profiles contains "6.15: evidence missing — panos_config.{zone,site.untrusted_zones,network.profiles.zone_protection} not collected" if {
	_applies("6.15")
	not e_6_15
}

_v_security_profiles contains "6.15: untrusted zones must have a zone protection profile answering SYN floods with SYN cookies" if {
	_applies("6.15")
	e_6_15
	not r_6_15
}

# 6.16 (Automated, Level 2)
default r_6_16 := false

r_6_16 if {
	_untrusted_known
	every z in _untrusted_zone_objs { _floods_ok(_zpp(z)) }
}

default e_6_16 := false

e_6_16 if {
	is_array(input.panos_config.zone)
	count(input.panos_config.zone) > 0
	is_array(input.panos_config.site.untrusted_zones)
	count(input.panos_config.site.untrusted_zones) > 0
	is_array(input.panos_config.network.profiles.zone_protection)
}

_v_security_profiles contains "6.16: evidence missing — panos_config.{zone,site.untrusted_zones,network.profiles.zone_protection} not collected" if {
	_applies("6.16")
	not e_6_16
}

_v_security_profiles contains "6.16: untrusted zones must have zone protection flood limits on for every flood type" if {
	_applies("6.16")
	e_6_16
	not r_6_16
}

# 6.17 (Automated, Level 1)
default r_6_17 := false

r_6_17 if {
	every z in input.panos_config.zone { _recon_ok(_zpp(z)) }
}

default e_6_17 := false

e_6_17 if {
	is_array(input.panos_config.zone)
	count(input.panos_config.zone) > 0
	is_array(input.panos_config.network.profiles.zone_protection)
}

_v_security_profiles contains "6.17: evidence missing — panos_config.{zone,network.profiles.zone_protection} not collected" if {
	_applies("6.17")
	not e_6_17
}

_v_security_profiles contains "6.17: every zone must have zone protection with TCP and UDP port scan and host sweep detection on" if {
	_applies("6.17")
	e_6_17
	not r_6_17
}

# 6.18 (Automated, Level 1)
default r_6_18 := false

r_6_18 if {
	every z in input.panos_config.zone { _drops_ok(_zpp(z)) }
}

default e_6_18 := false

e_6_18 if {
	is_array(input.panos_config.zone)
	count(input.panos_config.zone) > 0
	is_array(input.panos_config.network.profiles.zone_protection)
}

_v_security_profiles contains "6.18: evidence missing — panos_config.{zone,network.profiles.zone_protection} not collected" if {
	_applies("6.18")
	not e_6_18
}

_v_security_profiles contains "6.18: every zone must have zone protection dropping spoofed, mismatched-overlap, source-routed and malformed packets" if {
	_applies("6.18")
	e_6_18
	not r_6_18
}

# 6.19 (Automated, Level 1)
default r_6_19 := false

r_6_19 if {
	every p in input.panos_config.profiles.url_filtering { _cred_ok(p) }
}

default e_6_19 := false

e_6_19 if {
	is_array(input.panos_config.profiles.url_filtering)
	count(input.panos_config.profiles.url_filtering) > 0
}

_v_security_profiles contains "6.19: evidence missing — panos_config.profiles.url_filtering not collected" if {
	_applies("6.19")
	not e_6_19
}

_v_security_profiles contains "6.19: URL filtering profiles must block or continue credential submission and keep credential detection on" if {
	_applies("6.19")
	e_6_19
	not r_6_19
}

# 6.20 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_20 := false

r_6_20 if {
	every p in input.panos_config.profiles.virus { _av_decoders_ok(p, "mlav_action") }
}

default e_6_20 := false

e_6_20 if {
	is_array(input.panos_config.profiles.virus)
	count(input.panos_config.profiles.virus) > 0
}

_v_security_profiles contains "6.20: evidence missing — panos_config.profiles.virus not collected" if {
	_applies("6.20")
	not e_6_20
}

_v_security_profiles contains "6.20: the antivirus WildFire inline ML action must reset both ends (imap and pop3 may alert)" if {
	_applies("6.20")
	e_6_20
	not r_6_20
}

# 6.21 (Automated, Level 1)
default r_6_21 := false

r_6_21 if {
	every p in input.panos_config.profiles.virus { _mlav_ok(p) }
}

default e_6_21 := false

e_6_21 if {
	is_array(input.panos_config.profiles.virus)
	count(input.panos_config.profiles.virus) > 0
}

_v_security_profiles contains "6.21: evidence missing — panos_config.profiles.virus not collected" if {
	_applies("6.21")
	not e_6_21
}

_v_security_profiles contains "6.21: antivirus WildFire inline ML must be on for every file model" if {
	_applies("6.21")
	e_6_21
	not r_6_21
}

# 6.22 (Automated, Level 1)
default r_6_22 := false

r_6_22 if {
	not _licensed({"advanced threat prevention"})
}

r_6_22 if {
	every p in input.panos_config.profiles.vulnerability { _inline_cloud_ok(p, "mica_engine_vulnerability_enabled", "alert") }
}

default e_6_22 := false

e_6_22 if {
	is_array(input.panos_config.licenses)
	is_array(input.panos_config.profiles.vulnerability)
	count(input.panos_config.profiles.vulnerability) > 0
}

_v_security_profiles contains "6.22: evidence missing — panos_config.{licenses,profiles.vulnerability} not collected" if {
	_applies("6.22")
	not e_6_22
}

_v_security_profiles contains "6.22: with Advanced Threat Prevention, vulnerability profiles must run inline cloud analysis (models alert)" if {
	_applies("6.22")
	e_6_22
	not r_6_22
}

# 6.23 (Automated, Level 1)
default r_6_23 := false

r_6_23 if {
	not _licensed({"advanced threat prevention", "advanced url filtering"})
}

r_6_23 if {
	every p in input.panos_config.profiles.url_filtering { _yes(p, "local_inline_cat"); _yes(p, "cloud_inline_cat")}
}

default e_6_23 := false

e_6_23 if {
	is_array(input.panos_config.licenses)
	is_array(input.panos_config.profiles.url_filtering)
	count(input.panos_config.profiles.url_filtering) > 0
}

_v_security_profiles contains "6.23: evidence missing — panos_config.{licenses,profiles.url_filtering} not collected" if {
	_applies("6.23")
	not e_6_23
}

_v_security_profiles contains "6.23: with an advanced license, URL filtering profiles must run local and cloud inline categorization" if {
	_applies("6.23")
	e_6_23
	not r_6_23
}

# 6.24 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_24 := false

r_6_24 if {
	not _licensed({"advanced threat prevention"})
}

r_6_24 if {
	every p in input.panos_config.profiles.spyware { _inline_cloud_ok(p, "mica_engine_spyware_enabled", "reset-both") }
}

default e_6_24 := false

e_6_24 if {
	is_array(input.panos_config.licenses)
	is_array(input.panos_config.profiles.spyware)
	count(input.panos_config.profiles.spyware) > 0
}

_v_security_profiles contains "6.24: evidence missing — panos_config.{licenses,profiles.spyware} not collected" if {
	_applies("6.24")
	not e_6_24
}

_v_security_profiles contains "6.24: with Advanced Threat Prevention, anti-spyware profiles must run inline cloud analysis (models reset both)" if {
	_applies("6.24")
	e_6_24
	not r_6_24
}

# 6.25 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_6_25 := false

r_6_25 if {
	not _licensed({"dns security", "advanced dns security"})
}

r_6_25 if {
	every p in input.panos_config.profiles.spyware { _dns_security_ok(p) }
}

default e_6_25 := false

e_6_25 if {
	is_array(input.panos_config.licenses)
	is_array(input.panos_config.profiles.spyware)
	count(input.panos_config.profiles.spyware) > 0
}

_v_security_profiles contains "6.25: evidence missing — panos_config.{licenses,profiles.spyware} not collected" if {
	_applies("6.25")
	not e_6_25
}

_v_security_profiles contains "6.25: with DNS Security, anti-spyware profiles must sinkhole every DNS Security category (C2 with extended capture)" if {
	_applies("6.25")
	e_6_25
	not r_6_25
}

# 7.1 (Automated, Level 2)
default r_7_1 := false

r_7_1 if {
	every r in _untrusted_inbound { _app_named(r); _service_named(r)}
}

default e_7_1 := false

e_7_1 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
	is_array(input.panos_config.site.untrusted_zones)
	count(input.panos_config.site.untrusted_zones) > 0
}

_v_security_policies contains "7.1: evidence missing — panos_config.{rulebase.security,site.untrusted_zones} not collected" if {
	_applies("7.1")
	not e_7_1
}

_v_security_policies contains "7.1: allow rules from an untrusted to a more trusted zone must name the application and the service" if {
	_applies("7.1")
	e_7_1
	not r_7_1
}

# 7.2 (Automated, Level 1)
default r_7_2 := false

r_7_2 if {
	every r in _allow_rules { _service_named(r) }
}

default e_7_2 := false

e_7_2 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
}

_v_security_policies contains "7.2: evidence missing — panos_config.rulebase.security not collected" if {
	_applies("7.2")
	not e_7_2
}

_v_security_policies contains "7.2: allow rules must not use service any" if {
	_applies("7.2")
	e_7_2
	not r_7_2
}

# 7.3 (Automated, Level 1)
default r_7_3 := false

r_7_3 if {
	_edl_deny("destination")
	_edl_deny("source")
}

default e_7_3 := false

e_7_3 if {
	is_array(input.panos_config.rulebase.security)
	count(input.panos_config.rulebase.security) > 0
}

_v_security_policies contains "7.3: evidence missing — panos_config.rulebase.security not collected" if {
	_applies("7.3")
	not e_7_3
}

_v_security_policies contains "7.3: deny rules must block traffic to and from the Palo Alto malicious, high-risk, Tor-exit and bulletproof IP lists" if {
	_applies("7.3")
	e_7_3
	not r_7_3
}

# 7.4 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_7_4 := false

r_7_4 if {
	every n in {"intrazone-default", "interzone-default"} { some d in input.panos_config.rulebase.default_security_rules; d.name == n; _yes(d, "log_end")}
}

default e_7_4 := false

e_7_4 if {
	is_array(input.panos_config.rulebase.default_security_rules)
}

_v_security_policies contains "7.4: evidence missing — panos_config.rulebase.default_security_rules not collected" if {
	_applies("7.4")
	not e_7_4
}

_v_security_policies contains "7.4: the intrazone and interzone default rules must log at session end" if {
	_applies("7.4")
	e_7_4
	not r_7_4
}

# 8.1 (Automated, Level 1)
default r_8_1 := false

r_8_1 if {
	some d in input.panos_config.rulebase.decryption
	_forward_proxy_inet(d)
}

default e_8_1 := false

e_8_1 if {
	is_array(input.panos_config.rulebase.decryption)
	is_array(input.panos_config.site.internet_zones)
	count(input.panos_config.site.internet_zones) > 0
}

_v_decryption contains "8.1: evidence missing — panos_config.{rulebase.decryption,site.internet_zones} not collected" if {
	_applies("8.1")
	not e_8_1
}

_v_decryption contains "8.1: an SSL forward proxy decryption rule must cover traffic toward the Internet" if {
	_applies("8.1")
	e_8_1
	not r_8_1
}

# 8.2 (Manual, Level 1)
default r_8_2 := false

r_8_2 if {
	input.panos_config.attest.ssl_inbound_inspection_reviewed == true
}

_v_decryption contains "8.2: inbound TLS to published servers must pass through SSL inbound inspection (manual review not attested)" if {
	_applies("8.2")
	not r_8_2
}

# 8.3 (Manual, Level 2)
default r_8_3 := false

r_8_3 if {
	input.panos_config.attest.decryption_certificate_trusted == true
}

_v_decryption contains "8.3: the decryption certificate must be trusted and valid (manual review not attested)" if {
	_applies("8.3")
	not r_8_3
}

# Every recommendation in the benchmark: title, level, assessment status, how it is checked, report section.
recommendations := {
	"1.1.1.1": {
		"title": "system, config, User-ID, HIP-match and IP-tag logs must all forward to a valid syslog server profile",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.1.1.2": {
		"title": "system, config, User-ID, HIP-match and IP-tag logs must all send traps to an SNMP v3 trap profile",
		"level": 2,
		"assessment": "Automated",
		"profiles": ["Level 2"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.1.2": {
		"title": "a login banner must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.1.3": {
		"title": "logging under high dataplane load must be turned on",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.2.1": {
		"title": "management interface permitted IPs must be limited to the management hosts",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "device_setup",
	},
	"1.2.2": {
		"title": "interface management profiles offering SSH, HTTPS or SNMP must restrict permitted IPs",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "device_setup",
	},
	"1.2.3": {
		"title": "the management interface must not offer HTTP or Telnet",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.2.4": {
		"title": "interface management profiles must not offer HTTP or Telnet",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.2.5": {
		"title": "the web admin interface certificate must be valid and trusted",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "device_setup",
	},
	"1.3.1": {
		"title": "admin password complexity must be enforced with username inclusion blocked",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.3.2": {
		"title": "admin passwords must be at least 12 characters long",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.3.3": {
		"title": "admin passwords must contain at least 1 upper-case letter",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.3.4": {
		"title": "admin passwords must contain at least 1 lower-case letter",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.3.5": {
		"title": "admin passwords must contain at least 1 digit",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.3.6": {
		"title": "admin passwords must contain at least 1 special character",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.3.7": {
		"title": "admin passwords must expire within 1 to 90 days",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.3.8": {
		"title": "a new admin password must differ from the old one by at least 3 characters",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.3.9": {
		"title": "admin passwords must not repeat any of the last 24",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.3.10": {
		"title": "password profiles must not be weaker than the global rules (expiry 1 to 90 days)",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.4.1": {
		"title": "management idle timeout must be 1 to 10 minutes",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.4.2": {
		"title": "authentication profiles must lock out after failed attempts for a non-zero time",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.5.1": {
		"title": "SNMP polling must use version 3",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.6.1": {
		"title": "the update server identity must be verified",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.6.2": {
		"title": "two distinct NTP servers must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "device_setup",
	},
	"1.6.3": {
		"title": "the remote access VPN certificate and its TLS minimum must be valid",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "device_setup",
	},
	"1.7.1": {
		"title": "IKEv2 VPN gateways must use a post-quantum pre-shared key",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "device_setup",
	},
	"2.1": {
		"title": "traffic from trusted zones must carry a mapped user name",
		"level": 2,
		"assessment": "Automated",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "user_identification",
	},
	"2.2": {
		"title": "User-ID client (WMI) probing must be off",
		"level": 2,
		"assessment": "Automated",
		"profiles": ["Level 2"],
		"check": "configuration",
		"section": "user_identification",
	},
	"2.3": {
		"title": "User-ID must be on only for trusted internal zones",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "user_identification",
	},
	"2.4": {
		"title": "with User-ID on, the user mapping must name its trusted networks as include entries",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "user_identification",
	},
	"2.5": {
		"title": "the User-ID agent account must hold only the minimal group memberships",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "user_identification",
	},
	"2.6": {
		"title": "the User-ID service account must be denied interactive logon",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "user_identification",
	},
	"2.7": {
		"title": "the User-ID service account must have no remote access rights",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "user_identification",
	},
	"2.8": {
		"title": "a rule must block msrpc from the User-ID agent toward every untrusted zone",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "user_identification",
	},
	"3.1": {
		"title": "HA must be on with an HA2 data link and session synchronization",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "high_availability",
	},
	"3.2": {
		"title": "HA must fail over on link or path monitoring (failure condition any)",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "high_availability",
	},
	"3.3": {
		"title": "HA passive link state must be auto and preemption must be off",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "high_availability",
	},
	"4.1": {
		"title": "antivirus content must download and install hourly",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "dynamic_updates",
	},
	"4.2": {
		"title": "application and threat content must download and install at least daily",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "dynamic_updates",
	},
	"5.1": {
		"title": "WildFire upload size limits must be at or above the defaults",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "wildfire",
	},
	"5.2": {
		"title": "every allow rule must carry a WildFire analysis profile",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "wildfire",
	},
	"5.3": {
		"title": "decrypted content must be forwarded to WildFire",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "wildfire",
	},
	"5.4": {
		"title": "WildFire session information must include every field",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "wildfire",
	},
	"5.5": {
		"title": "WildFire logs must be forwarded to an alerting destination",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "wildfire",
	},
	"5.6": {
		"title": "WildFire content must update in real time",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "wildfire",
	},
	"5.7": {
		"title": "the WildFire public cloud region must be the approved one",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "wildfire",
	},
	"5.8": {
		"title": "WildFire profiles must block PE files through inline cloud analysis",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "wildfire",
	},
	"6.1": {
		"title": "antivirus decoders must reset both ends for signature and WildFire actions (imap and pop3 may alert)",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.2": {
		"title": "every allow rule must carry an antivirus profile",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.3": {
		"title": "an anti-spyware profile must reset critical, high and medium threats of any category",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.4": {
		"title": "anti-spyware profiles in use must sinkhole the Palo Alto DNS list with IPv4 and IPv6 sinkhole addresses",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.5": {
		"title": "every allow rule toward the Internet must carry an anti-spyware profile",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.6": {
		"title": "a vulnerability profile must block critical and high threats and keep at least the default action below",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.7": {
		"title": "every allow rule must carry a vulnerability protection profile",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.8": {
		"title": "a PAN-DB URL filtering license must be active",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.9": {
		"title": "URL filtering profiles must block or override every organisation-designated category",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.10": {
		"title": "URL filtering profiles must log (alert) every category they let through",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.11": {
		"title": "URL filtering profiles must log User-Agent, Referer and X-Forwarded-For on every page",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.12": {
		"title": "every allow rule toward the Internet must carry a URL filtering profile",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.13": {
		"title": "a data filtering profile must alert on sensitive data patterns above a threshold",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.14": {
		"title": "every allow rule to or from the Internet must carry a data filtering profile",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.15": {
		"title": "untrusted zones must have a zone protection profile answering SYN floods with SYN cookies",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.16": {
		"title": "untrusted zones must have zone protection flood limits on for every flood type",
		"level": 2,
		"assessment": "Automated",
		"profiles": ["Level 2"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.17": {
		"title": "every zone must have zone protection with TCP and UDP port scan and host sweep detection on",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.18": {
		"title": "every zone must have zone protection dropping spoofed, mismatched-overlap, source-routed and malformed packets",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.19": {
		"title": "URL filtering profiles must block or continue credential submission and keep credential detection on",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.20": {
		"title": "the antivirus WildFire inline ML action must reset both ends (imap and pop3 may alert)",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.21": {
		"title": "antivirus WildFire inline ML must be on for every file model",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.22": {
		"title": "with Advanced Threat Prevention, vulnerability profiles must run inline cloud analysis (models alert)",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.23": {
		"title": "with an advanced license, URL filtering profiles must run local and cloud inline categorization",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.24": {
		"title": "with Advanced Threat Prevention, anti-spyware profiles must run inline cloud analysis (models reset both)",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"6.25": {
		"title": "with DNS Security, anti-spyware profiles must sinkhole every DNS Security category (C2 with extended capture)",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_profiles",
	},
	"7.1": {
		"title": "allow rules from an untrusted to a more trusted zone must name the application and the service",
		"level": 2,
		"assessment": "Automated",
		"profiles": ["Level 2"],
		"check": "configuration",
		"section": "security_policies",
	},
	"7.2": {
		"title": "allow rules must not use service any",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_policies",
	},
	"7.3": {
		"title": "deny rules must block traffic to and from the Palo Alto malicious, high-risk, Tor-exit and bulletproof IP lists",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_policies",
	},
	"7.4": {
		"title": "the intrazone and interzone default rules must log at session end",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "security_policies",
	},
	"8.1": {
		"title": "an SSL forward proxy decryption rule must cover traffic toward the Internet",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "decryption",
	},
	"8.2": {
		"title": "inbound TLS to published servers must pass through SSL inbound inspection",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "decryption",
	},
	"8.3": {
		"title": "the decryption certificate must be trusted and valid",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "decryption",
	},
}

# recommendations in the selected profile
in_scope := {id | some id, _ in recommendations; _applies(id)}

_failed_ids := {id | some v in violations; id := split(v, ":")[0]; id in in_scope}

# Compliance summary for reporting (counts are recommendations; a recommendation fails once however many messages it emits)
compliance_summary := {
	"total_controls": count(in_scope),
	"passing_controls": count(in_scope) - count(_failed_ids),
	"failing_controls": count(_failed_ids),
	"compliance_percentage": ((count(in_scope) - count(_failed_ids)) * 100) / count(in_scope),
	"sections": {
		"device_setup": {
			"total": count({id | some id, r in recommendations; r.section == "device_setup"; _applies(id)}),
			"violations": count(device_setup_violations),
		},
		"user_identification": {
			"total": count({id | some id, r in recommendations; r.section == "user_identification"; _applies(id)}),
			"violations": count(user_identification_violations),
		},
		"high_availability": {
			"total": count({id | some id, r in recommendations; r.section == "high_availability"; _applies(id)}),
			"violations": count(high_availability_violations),
		},
		"dynamic_updates": {
			"total": count({id | some id, r in recommendations; r.section == "dynamic_updates"; _applies(id)}),
			"violations": count(dynamic_updates_violations),
		},
		"wildfire": {
			"total": count({id | some id, r in recommendations; r.section == "wildfire"; _applies(id)}),
			"violations": count(wildfire_violations),
		},
		"security_profiles": {
			"total": count({id | some id, r in recommendations; r.section == "security_profiles"; _applies(id)}),
			"violations": count(security_profiles_violations),
		},
		"security_policies": {
			"total": count({id | some id, r in recommendations; r.section == "security_policies"; _applies(id)}),
			"violations": count(security_policies_violations),
		},
		"decryption": {
			"total": count({id | some id, r in recommendations; r.section == "decryption"; _applies(id)}),
			"violations": count(decryption_violations),
		},
	},
}

compliance_report := {
	"benchmark": "CIS Palo Alto Firewall 11 Benchmark v1.2.1",
	"level": _level,
	"total_controls": count(in_scope),
	"standard_total": 79,
	"standard_total_source": "CIS Palo Alto Firewall 11 Benchmark v1.2.1, recommendations counted from the CIS workbook",
	"failed_controls": count(_failed_ids),
	"passed_controls": count(in_scope) - count(_failed_ids),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
