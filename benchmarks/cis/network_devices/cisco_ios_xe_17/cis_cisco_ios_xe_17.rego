# METADATA
# title: "CIS Cisco IOS XE 17.x Benchmark v2.2.2"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, cisco]
#   coverage:
#     checks: 87
#     cited: 87
#     expected: 84
#     found: 84
#     scope: module
#     density: full
#     basis: declared-total
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cis_cisco_ios_xe_17

# CIS Cisco IOS XE 17.x Benchmark v2.2.2
# Generated from the CIS workbook by tools/cis_generators/gen_cisco_ios_xe_17.py. This module is new: the older
# hand-written Cisco modules (cis_cisco_ios, cis.network.cisco) are generic IOS and do not claim IOS XE.
# 84 recommendations (51 Automated, 33 Manual; 75 Level 1, 9 Level 2), every one in the
# benchmark; ids, levels and assessment status read from the workbook. Messages use our own wording, not CIS text.
# Profile: input.cis_profile.level, the number 1 or 2 (Level 2 includes Level 1); absent => 2; any other value (the
# string "2", 3, null) is invalid evidence, reported as such, with the report scoped at Level 2 and the Level 2
# recommendations failed. total_controls counts the recommendations in the selected profile.
# Automated checks fail closed: facts not collected => "<id>: evidence missing — <field> not collected".
# Manual recommendations with a decidable configuration fact are checked like Automated ones:
#   1.2.1, 1.5.4, 1.5.5, 2.1.1.2, 2.1.2, 2.1.3, 2.1.7, 2.3.1.4, 2.4.2, 2.4.4, 3.1.1, 3.1.2, 3.1.3.
# Attestation booleans under input.ios_xe_config.attest (false or absent => violation): 1.2.4, 1.5.1, 1.5.6, 1.5.10, 2.1.1.1.3, 3.1.4, 3.2.1, 3.2.2, 3.3.1.1, 3.3.1.2, 3.3.1.3, 3.3.1.4, 3.3.1.5, 3.3.1.6, 3.3.1.7, 3.3.1.8, 3.3.1.9, 3.3.2.1, 3.3.2.2, 3.3.3.1.
#
# Input contract (input.ios_xe_config), the parsed running configuration of `show running-config all`
# (cisco.ios facts ansible_net_config, split by the collector):
#   lines     : array of strings, every top-level (unindented) line verbatim, section headers included
#               ("line vty 0 4", "interface Loopback0"); comment lines ("!") may be present and are ignored
#   sections  : array of {header, lines[]}, one per top-level line that has an indented body; lines[] are the
#               body lines with the indentation removed (nested blocks flattened)
#   banners   : {exec, login, motd} the banner texts without delimiters (banner bodies are not top-level lines)
#   attest.*  : attestation booleans for the judgement recommendations
# The "all" form matters: exec-timeout, ip ssh time-out and "no exec" only show up there when left at default.
# Absent lines/sections/banners are evidence missing, never a pass.

import rego.v1

# Main compliance rule - every recommendation in the selected profile must pass; no facts, no compliance
default compliant := false

compliant if {
	input.ios_xe_config
	count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		management_plane_violations,
		control_plane_violations,
		data_plane_violations,
		profile_violations,
	]
	some a in arrays
	some v in a
]

# cis_profile.level that is not the number 1 or 2 (see _level_invalid)
profile_violations := sort([m | some m in _v_profile])

# 1 Management plane
management_plane_violations := sort([m | some m in _v_management_plane])

# 2 Control plane
control_plane_violations := sort([m | some m in _v_control_plane])

# 3 Data plane
data_plane_violations := sort([m | some m in _v_data_plane])

# ── helpers ──────────────────────────────────────────────────────────────────
# profile selection: input.cis_profile.level is the number 1 or 2 (Level 2 includes Level 1); absent => 2. Anything
# else ("2", 3, null, a cis_profile that is not an object) is invalid evidence: the report is scoped at Level 2, the
# stricter, and every Level 2 recommendation carries the finding, because the profile that decides them was not readable.
default _level := 2

_level := 1 if input.cis_profile.level == 1

_applies(id) if recommendations[id].level <= _level

default _level_invalid := false

_level_invalid if {
	cp := input.cis_profile
	not is_object(cp)
}

_level_invalid if {
	lv := input.cis_profile.level
	not lv in {1, 2}
}

_level_got := json.marshal(input.cis_profile.level) if is_object(input.cis_profile)

_level_got := json.marshal(cp) if {
	cp := input.cis_profile
	not is_object(cp)
}

_level_finding := sprintf("evidence invalid — cis_profile.level must be the number 1 or 2, got %s", [_level_got])

_v_profile contains sprintf("cis_profile.level: %s; the report is scoped at Level 2", [_level_finding]) if _level_invalid

_v_profile contains sprintf("%s: %s, so this Level 2 recommendation could not be scoped", [id, _level_finding]) if {
	_level_invalid
	some id, r in recommendations
	r.level == 2
}

# Top-level running-config lines never start with whitespace and a comment starts with "!", so every pattern is
# anchored at ^ on a command word and cannot hit a commented line, an indented child line or a longer command
# (no aaa new-model does not match ^aaa new-model).
_matches(re) := [l | some l in input.ios_xe_config.lines; is_string(l); regex.match(re, l)]

_has(re) if count(_matches(re)) > 0

# first capture group of every matching top-level line
_cap(re) := [m[0][1] |
	some l in input.ios_xe_config.lines
	is_string(l)
	m := regex.find_all_string_submatch_n(re, l, 1)
	count(m) > 0
]

_nums(re) := [to_number(c) | some c in _cap(re)]

_secs(re) := [s | some s in input.ios_xe_config.sections; is_string(s.header); regex.match(re, s.header)]

_sec_has(s, re) if {
	some l in s.lines
	is_string(l)
	regex.match(re, l)
}

_sec_lines(s, re) := [l | some l in s.lines; is_string(l); regex.match(re, l)]

_nonblank(v) if {
	is_string(v)
	trim_space(v) != ""
}

# ── line sections ──
_vty := _secs(`^line vty(\s|$)`)

_aux := _secs(`^line aux\s+0\s*$`)

_con := _secs(`^line con\s+0\s*$`)

_ssh_only(s) if {
	ls := _sec_lines(s, `^transport input(\s|$)`)
	count(ls) > 0
	every l in ls { regex.match(`^transport input\s+ssh\s*$`, l) }
}

# exec-timeout minutes [seconds]: 1 to 600 seconds in total; "0 0" is never-time-out and fails
_timeout_secs(g) := (to_number(g[1]) * 60) + to_number(g[2]) if g[2] != ""

_timeout_secs(g) := to_number(g[1]) * 60 if g[2] == ""

_exec_ok(s) if {
	some l in s.lines
	is_string(l)
	m := regex.find_all_string_submatch_n(`^exec-timeout\s+(\d+)(?:\s+(\d+))?\s*$`, l, 1)
	count(m) > 0
	t := _timeout_secs(m[0])
	t > 0
	t <= 600
}

# ── HTTP server ──
_http_on if _has(`^ip http (secure-)?server\s*$`)

# ── local users ──
_user_lines := _matches(`^username\s+\S+`)

_bad_priv(l) if {
	m := regex.find_all_string_submatch_n(`\sprivilege\s+(\d+)`, l, 1)
	count(m) > 0
	m[0][1] != "1"
}

_has_secret(l) if regex.match(`\ssecret\s+(5|8|9)\s+\S+`, l)

# ── SNMP ──
_snmp_used if _has(`^snmp-server (community|group|user)\s`)

_comm_lines := _matches(`^snmp-server community\s+\S+`)

# arguments after the community string and an optional "view <name>"
_comm_rest(l) := array.slice(t, 3, count(t)) if t := regex.split(`\s+`, trim_space(l))

_comm_args(l) := [] if count(_comm_rest(l)) == 0

_comm_args(l) := r if {
	r := _comm_rest(l)
	count(r) > 0
	lower(r[0]) != "view"
}

_comm_args(l) := array.slice(r, 2, count(r)) if {
	r := _comm_rest(l)
	count(r) > 0
	lower(r[0]) == "view"
}

_comm_rw(l) if {
	a := _comm_args(l)
	count(a) > 0
	lower(a[0]) == "rw"
}

# an ACL follows the access mode, or is the first argument when the mode is left out
_comm_acl(l) if {
	a := _comm_args(l)
	count(a) >= 2
	lower(a[0]) in {"ro", "rw"}
}

_comm_acl(l) if {
	a := _comm_args(l)
	count(a) >= 1
	not lower(a[0]) in {"ro", "rw", "ipv6"}
}

# ── NTP / interfaces ──
_ntp_srv := _matches(`^ntp server\s+\S+`)

_l3_ifs := [s |
	some s in input.ios_xe_config.sections
	is_string(s.header)
	regex.match(`^interface\s+\S+`, s.header)
	not regex.match(`(?i)^interface\s+loopback`, s.header)
	_sec_has(s, `^ip address\s+\d`)
]

# 1.1.1 (Automated, Level 1)
default r_1_1_1 := false

r_1_1_1 if {
	_has(`^aaa new-model\s*$`)
}

default e_1_1_1 := false

e_1_1_1 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.1.1: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.1.1")
	not e_1_1_1
}

_v_management_plane contains "1.1.1: AAA must be turned on globally (aaa new-model)" if {
	_applies("1.1.1")
	e_1_1_1
	not r_1_1_1
}

# 1.1.2 (Automated, Level 1)
default r_1_1_2 := false

r_1_1_2 if {
	_has(`^aaa authentication login\s+\S+`)
}

default e_1_1_2 := false

e_1_1_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.1.2: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.1.2")
	not e_1_1_2
}

_v_management_plane contains "1.1.2: a login authentication method list must be configured" if {
	_applies("1.1.2")
	e_1_1_2
	not r_1_1_2
}

# 1.1.3 (Automated, Level 1)
default r_1_1_3 := false

r_1_1_3 if {
	_has(`^aaa authentication enable default\s+\S+`)
}

default e_1_1_3 := false

e_1_1_3 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.1.3: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.1.3")
	not e_1_1_3
}

_v_management_plane contains "1.1.3: enable-mode authentication must use an AAA default method list" if {
	_applies("1.1.3")
	e_1_1_3
	not r_1_1_3
}

# 1.1.4 (Automated, Level 1)
default r_1_1_4 := false

r_1_1_4 if {
	every s in _vty { _sec_has(s, `^login authentication\s+\S+`) }
}

default e_1_1_4 := false

e_1_1_4 if {
	is_array(input.ios_xe_config.sections)
	count(_vty) > 0
}

_v_management_plane contains "1.1.4: evidence missing — ios_xe_config.sections not collected" if {
	_applies("1.1.4")
	not e_1_1_4
}

_v_management_plane contains "1.1.4: every vty line block must set login authentication" if {
	_applies("1.1.4")
	e_1_1_4
	not r_1_1_4
}

# 1.1.5 (Automated, Level 1)
default r_1_1_5 := false

r_1_1_5 if {
	not _http_on
}

r_1_1_5 if {
	_has(`^ip http authentication\s+\S+`)
}

default e_1_1_5 := false

e_1_1_5 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.1.5: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.1.5")
	not e_1_1_5
}

_v_management_plane contains "1.1.5: when the HTTP server is on, ip http authentication must be set" if {
	_applies("1.1.5")
	e_1_1_5
	not r_1_1_5
}

# 1.1.6 (Automated, Level 1)
default r_1_1_6 := false

r_1_1_6 if {
	_has(`^aaa accounting commands 15\s+\S+`)
}

default e_1_1_6 := false

e_1_1_6 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.1.6: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.1.6")
	not e_1_1_6
}

_v_management_plane contains "1.1.6: privilege 15 command accounting must be configured" if {
	_applies("1.1.6")
	e_1_1_6
	not r_1_1_6
}

# 1.1.7 (Automated, Level 1)
default r_1_1_7 := false

r_1_1_7 if {
	_has(`^aaa accounting connection\s+\S+`)
}

default e_1_1_7 := false

e_1_1_7 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.1.7: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.1.7")
	not e_1_1_7
}

_v_management_plane contains "1.1.7: connection accounting must be configured" if {
	_applies("1.1.7")
	e_1_1_7
	not r_1_1_7
}

# 1.1.8 (Automated, Level 1)
default r_1_1_8 := false

r_1_1_8 if {
	_has(`^aaa accounting exec\s+\S+`)
}

default e_1_1_8 := false

e_1_1_8 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.1.8: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.1.8")
	not e_1_1_8
}

_v_management_plane contains "1.1.8: EXEC session accounting must be configured" if {
	_applies("1.1.8")
	e_1_1_8
	not r_1_1_8
}

# 1.1.9 (Automated, Level 1)
default r_1_1_9 := false

r_1_1_9 if {
	_has(`^aaa accounting network\s+\S+`)
}

default e_1_1_9 := false

e_1_1_9 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.1.9: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.1.9")
	not e_1_1_9
}

_v_management_plane contains "1.1.9: network accounting must be configured" if {
	_applies("1.1.9")
	e_1_1_9
	not r_1_1_9
}

# 1.1.10 (Automated, Level 1)
default r_1_1_10 := false

r_1_1_10 if {
	_has(`^aaa accounting system\s+\S+`)
}

default e_1_1_10 := false

e_1_1_10 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.1.10: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.1.10")
	not e_1_1_10
}

_v_management_plane contains "1.1.10: system accounting must be configured" if {
	_applies("1.1.10")
	e_1_1_10
	not r_1_1_10
}

# 1.2.1 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_2_1 := false

r_1_2_1 if {
	every l in _user_lines { not _bad_priv(l) }
}

default e_1_2_1 := false

e_1_2_1 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.2.1: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.2.1")
	not e_1_2_1
}

_v_management_plane contains "1.2.1: every local username must be at privilege level 1 (none above)" if {
	_applies("1.2.1")
	e_1_2_1
	not r_1_2_1
}

# 1.2.2 (Automated, Level 1)
default r_1_2_2 := false

r_1_2_2 if {
	every s in _vty { _ssh_only(s) }
}

default e_1_2_2 := false

e_1_2_2 if {
	is_array(input.ios_xe_config.sections)
	count(_vty) > 0
}

_v_management_plane contains "1.2.2: evidence missing — ios_xe_config.sections not collected" if {
	_applies("1.2.2")
	not e_1_2_2
}

_v_management_plane contains "1.2.2: every vty line block must allow only ssh for transport input" if {
	_applies("1.2.2")
	e_1_2_2
	not r_1_2_2
}

# 1.2.3 (Automated, Level 1)
default r_1_2_3 := false

r_1_2_3 if {
	count(_aux) == 0
}

r_1_2_3 if {
	count(_aux) > 0
	every s in _aux { _sec_has(s, `^no exec\s*$`) }
}

default e_1_2_3 := false

e_1_2_3 if {
	is_array(input.ios_xe_config.sections)
	count(_vty) > 0
}

_v_management_plane contains "1.2.3: evidence missing — ios_xe_config.sections not collected" if {
	_applies("1.2.3")
	not e_1_2_3
}

_v_management_plane contains "1.2.3: the aux line must have no exec (a device with no aux line passes)" if {
	_applies("1.2.3")
	e_1_2_3
	not r_1_2_3
}

# 1.2.4 (Manual, Level 1)
default r_1_2_4 := false

r_1_2_4 if {
	input.ios_xe_config.attest.vty_acl_defined == true
}

_v_management_plane contains "1.2.4: an access list for the vty lines must exist and be appropriate (manual review not attested)" if {
	_applies("1.2.4")
	not r_1_2_4
}

# 1.2.5 (Automated, Level 1)
default r_1_2_5 := false

r_1_2_5 if {
	every s in _vty { _sec_has(s, `^access-class\s+\S+\s+in(\s|$)`) }
}

default e_1_2_5 := false

e_1_2_5 if {
	is_array(input.ios_xe_config.sections)
	count(_vty) > 0
}

_v_management_plane contains "1.2.5: evidence missing — ios_xe_config.sections not collected" if {
	_applies("1.2.5")
	not e_1_2_5
}

_v_management_plane contains "1.2.5: every vty line block must set an inbound access-class" if {
	_applies("1.2.5")
	e_1_2_5
	not r_1_2_5
}

# 1.2.6 (Automated, Level 1)
default r_1_2_6 := false

r_1_2_6 if {
	count(_aux) == 0
}

r_1_2_6 if {
	count(_aux) > 0
	every s in _aux { _exec_ok(s) }
}

default e_1_2_6 := false

e_1_2_6 if {
	is_array(input.ios_xe_config.sections)
	count(_vty) > 0
}

_v_management_plane contains "1.2.6: evidence missing — ios_xe_config.sections not collected" if {
	_applies("1.2.6")
	not e_1_2_6
}

_v_management_plane contains "1.2.6: the aux line exec-timeout must be 1 to 10 minutes (a device with no aux line passes)" if {
	_applies("1.2.6")
	e_1_2_6
	not r_1_2_6
}

# 1.2.7 (Automated, Level 1)
default r_1_2_7 := false

r_1_2_7 if {
	every s in _con { _exec_ok(s) }
}

default e_1_2_7 := false

e_1_2_7 if {
	is_array(input.ios_xe_config.sections)
	count(_con) > 0
}

_v_management_plane contains "1.2.7: evidence missing — ios_xe_config.sections not collected" if {
	_applies("1.2.7")
	not e_1_2_7
}

_v_management_plane contains "1.2.7: the console line exec-timeout must be 1 to 10 minutes" if {
	_applies("1.2.7")
	e_1_2_7
	not r_1_2_7
}

# 1.2.8 (Automated, Level 1)
default r_1_2_8 := false

r_1_2_8 if {
	every s in _vty { _exec_ok(s) }
}

default e_1_2_8 := false

e_1_2_8 if {
	is_array(input.ios_xe_config.sections)
	count(_vty) > 0
}

_v_management_plane contains "1.2.8: evidence missing — ios_xe_config.sections not collected" if {
	_applies("1.2.8")
	not e_1_2_8
}

_v_management_plane contains "1.2.8: every vty line block must have an exec-timeout of 1 to 10 minutes" if {
	_applies("1.2.8")
	e_1_2_8
	not r_1_2_8
}

# 1.2.9 (Automated, Level 1)
default r_1_2_9 := false

r_1_2_9 if {
	not _http_on
}

r_1_2_9 if {
	some n in _nums(`^ip http max-connections\s+(\d+)`)
	is_number(n)
	n >= 1
	n <= 2
}

default e_1_2_9 := false

e_1_2_9 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.2.9: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.2.9")
	not e_1_2_9
}

_v_management_plane contains "1.2.9: when the HTTP server is on, ip http max-connections must be 1 or 2" if {
	_applies("1.2.9")
	e_1_2_9
	not r_1_2_9
}

# 1.2.10 (Automated, Level 1)
default r_1_2_10 := false

r_1_2_10 if {
	not _http_on
}

r_1_2_10 if {
	some n in _nums(`^ip http timeout-policy idle\s+(\d+)`)
	is_number(n)
	n >= 1
	n <= 600
}

default e_1_2_10 := false

e_1_2_10 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.2.10: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.2.10")
	not e_1_2_10
}

_v_management_plane contains "1.2.10: when the HTTP server is on, the ip http idle timeout must be 1 to 600 seconds" if {
	_applies("1.2.10")
	e_1_2_10
	not r_1_2_10
}

# 1.3.1 (Automated, Level 1)
default r_1_3_1 := false

r_1_3_1 if {
	_nonblank(input.ios_xe_config.banners.exec)
}

default e_1_3_1 := false

e_1_3_1 if {
	is_object(input.ios_xe_config.banners)
}

_v_management_plane contains "1.3.1: evidence missing — ios_xe_config.banners not collected" if {
	_applies("1.3.1")
	not e_1_3_1
}

_v_management_plane contains "1.3.1: a exec banner with text must be configured" if {
	_applies("1.3.1")
	e_1_3_1
	not r_1_3_1
}

# 1.3.2 (Automated, Level 1)
default r_1_3_2 := false

r_1_3_2 if {
	_nonblank(input.ios_xe_config.banners.login)
}

default e_1_3_2 := false

e_1_3_2 if {
	is_object(input.ios_xe_config.banners)
}

_v_management_plane contains "1.3.2: evidence missing — ios_xe_config.banners not collected" if {
	_applies("1.3.2")
	not e_1_3_2
}

_v_management_plane contains "1.3.2: a login banner with text must be configured" if {
	_applies("1.3.2")
	e_1_3_2
	not r_1_3_2
}

# 1.3.3 (Automated, Level 1)
default r_1_3_3 := false

r_1_3_3 if {
	_nonblank(input.ios_xe_config.banners.motd)
}

default e_1_3_3 := false

e_1_3_3 if {
	is_object(input.ios_xe_config.banners)
}

_v_management_plane contains "1.3.3: evidence missing — ios_xe_config.banners not collected" if {
	_applies("1.3.3")
	not e_1_3_3
}

_v_management_plane contains "1.3.3: a motd banner with text must be configured" if {
	_applies("1.3.3")
	e_1_3_3
	not r_1_3_3
}

# 1.3.4 (Automated, Level 1)
default r_1_3_4 := false

r_1_3_4 if {
	_has(`^ip admission auth-proxy-banner http\s+\S`)
}

default e_1_3_4 := false

e_1_3_4 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.3.4: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.3.4")
	not e_1_3_4
}

_v_management_plane contains "1.3.4: a webauth (auth-proxy) banner must be configured" if {
	_applies("1.3.4")
	e_1_3_4
	not r_1_3_4
}

# 1.4.1 (Automated, Level 1)
default r_1_4_1 := false

r_1_4_1 if {
	_has(`^enable secret\s+(5|8|9)\s+\S+`)
}

default e_1_4_1 := false

e_1_4_1 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.4.1: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.4.1")
	not e_1_4_1
}

_v_management_plane contains "1.4.1: an enable secret of hash type 5, 8 or 9 must be set" if {
	_applies("1.4.1")
	e_1_4_1
	not r_1_4_1
}

# 1.4.2 (Automated, Level 1)
default r_1_4_2 := false

r_1_4_2 if {
	_has(`^service password-encryption\s*$`)
}

default e_1_4_2 := false

e_1_4_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.4.2: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.4.2")
	not e_1_4_2
}

_v_management_plane contains "1.4.2: service password-encryption must be on" if {
	_applies("1.4.2")
	e_1_4_2
	not r_1_4_2
}

# 1.4.3 (Automated, Level 1)
default r_1_4_3 := false

r_1_4_3 if {
	every l in _user_lines { _has_secret(l) }
}

default e_1_4_3 := false

e_1_4_3 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.4.3: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.4.3")
	not e_1_4_3
}

_v_management_plane contains "1.4.3: every local user must have a type 5, 8 or 9 secret" if {
	_applies("1.4.3")
	e_1_4_3
	not r_1_4_3
}

# 1.5.1 (Manual, Level 1)
default r_1_5_1 := false

r_1_5_1 if {
	input.ios_xe_config.attest.snmp_disabled_when_unused == true
}

_v_management_plane contains "1.5.1: SNMP must be off when unused (manual review not attested)" if {
	_applies("1.5.1")
	not r_1_5_1
}

# 1.5.2 (Automated, Level 1)
default r_1_5_2 := false

r_1_5_2 if {
	not _has(`^snmp-server community\s+private(\s|$)`)
}

default e_1_5_2 := false

e_1_5_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.5.2: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.5.2")
	not e_1_5_2
}

_v_management_plane contains "1.5.2: an snmp-server community named private must not exist" if {
	_applies("1.5.2")
	e_1_5_2
	not r_1_5_2
}

# 1.5.3 (Automated, Level 1)
default r_1_5_3 := false

r_1_5_3 if {
	not _has(`^snmp-server community\s+public(\s|$)`)
}

default e_1_5_3 := false

e_1_5_3 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.5.3: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.5.3")
	not e_1_5_3
}

_v_management_plane contains "1.5.3: an snmp-server community named public must not exist" if {
	_applies("1.5.3")
	e_1_5_3
	not r_1_5_3
}

# 1.5.4 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_5_4 := false

r_1_5_4 if {
	every l in _comm_lines { not _comm_rw(l) }
}

default e_1_5_4 := false

e_1_5_4 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.5.4: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.5.4")
	not e_1_5_4
}

_v_management_plane contains "1.5.4: no snmp-server community must grant RW access" if {
	_applies("1.5.4")
	e_1_5_4
	not r_1_5_4
}

# 1.5.5 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_1_5_5 := false

r_1_5_5 if {
	every l in _comm_lines { _comm_acl(l) }
}

default e_1_5_5 := false

e_1_5_5 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.5.5: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.5.5")
	not e_1_5_5
}

_v_management_plane contains "1.5.5: every snmp-server community must carry an ACL" if {
	_applies("1.5.5")
	e_1_5_5
	not r_1_5_5
}

# 1.5.6 (Manual, Level 1)
default r_1_5_6 := false

r_1_5_6 if {
	input.ios_xe_config.attest.snmp_acl_defined == true
}

_v_management_plane contains "1.5.6: an access list for SNMP must exist and be appropriate (manual review not attested)" if {
	_applies("1.5.6")
	not r_1_5_6
}

# 1.5.7 (Automated, Level 1)
default r_1_5_7 := false

r_1_5_7 if {
	not _snmp_used
}

r_1_5_7 if {
	_has(`^snmp-server host\s+\S+`)
}

default e_1_5_7 := false

e_1_5_7 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.5.7: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.5.7")
	not e_1_5_7
}

_v_management_plane contains "1.5.7: when SNMP is in use, an snmp-server host must be set" if {
	_applies("1.5.7")
	e_1_5_7
	not r_1_5_7
}

# 1.5.8 (Automated, Level 1)
default r_1_5_8 := false

r_1_5_8 if {
	not _snmp_used
}

r_1_5_8 if {
	_has(`^snmp-server enable traps snmp(\s|$)`)
}

default e_1_5_8 := false

e_1_5_8 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.5.8: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.5.8")
	not e_1_5_8
}

_v_management_plane contains "1.5.8: when SNMP is in use, snmp-server enable traps snmp must be set" if {
	_applies("1.5.8")
	e_1_5_8
	not r_1_5_8
}

# 1.5.9 (Automated, Level 1)
default r_1_5_9 := false

r_1_5_9 if {
	every l in _matches(`^snmp-server group\s+\S+\s+v3\s+\S+`) { regex.match(`^snmp-server group\s+\S+\s+v3\s+priv(\s|$)`, l) }
}

default e_1_5_9 := false

e_1_5_9 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_management_plane contains "1.5.9: evidence missing — ios_xe_config.lines not collected" if {
	_applies("1.5.9")
	not e_1_5_9
}

_v_management_plane contains "1.5.9: every SNMPv3 group must use the priv security level" if {
	_applies("1.5.9")
	e_1_5_9
	not r_1_5_9
}

# 1.5.10 (Manual, Level 1)
default r_1_5_10 := false

r_1_5_10 if {
	input.ios_xe_config.attest.snmpv3_user_aes128_minimum == true
}

_v_management_plane contains "1.5.10: SNMPv3 users must use at least AES-128 privacy (manual review not attested)" if {
	_applies("1.5.10")
	not r_1_5_10
}

# 2.1.1.1.1 (Automated, Level 1)
default r_2_1_1_1_1 := false

r_2_1_1_1_1 if {
	some h in _cap(`^hostname\s+(\S+)\s*$`)
	not lower(h) in {"router", "switch"}
}

default e_2_1_1_1_1 := false

e_2_1_1_1_1 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.1.1.1: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.1.1.1")
	not e_2_1_1_1_1
}

_v_control_plane contains "2.1.1.1.1: a hostname other than the factory default must be set" if {
	_applies("2.1.1.1.1")
	e_2_1_1_1_1
	not r_2_1_1_1_1
}

# 2.1.1.1.2 (Automated, Level 1)
default r_2_1_1_1_2 := false

r_2_1_1_1_2 if {
	some d in _cap(`^ip domain[ -]name\s+(\S+)`)
	d != "vrf"
}

default e_2_1_1_1_2 := false

e_2_1_1_1_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.1.1.2: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.1.1.2")
	not e_2_1_1_1_2
}

_v_control_plane contains "2.1.1.1.2: a global ip domain name must be set" if {
	_applies("2.1.1.1.2")
	e_2_1_1_1_2
	not r_2_1_1_1_2
}

# 2.1.1.1.3 (Manual, Level 1)
default r_2_1_1_1_3 := false

r_2_1_1_1_3 if {
	input.ios_xe_config.attest.rsa_modulus_2048_or_more == true
}

_v_control_plane contains "2.1.1.1.3: the RSA key modulus must be at least 2048 bits (manual review not attested)" if {
	_applies("2.1.1.1.3")
	not r_2_1_1_1_3
}

# 2.1.1.1.4 (Automated, Level 1)
default r_2_1_1_1_4 := false

r_2_1_1_1_4 if {
	some n in _nums(`^ip ssh time-out\s+(\d+)`)
	is_number(n)
	n >= 1
	n <= 60
}

default e_2_1_1_1_4 := false

e_2_1_1_1_4 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.1.1.4: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.1.1.4")
	not e_2_1_1_1_4
}

_v_control_plane contains "2.1.1.1.4: ip ssh time-out must be 1 to 60 seconds" if {
	_applies("2.1.1.1.4")
	e_2_1_1_1_4
	not r_2_1_1_1_4
}

# 2.1.1.1.5 (Automated, Level 1)
default r_2_1_1_1_5 := false

r_2_1_1_1_5 if {
	every n in _nums(`^ip ssh authentication-retries\s+(\d+)`) { n >= 1; n <= 3}
}

default e_2_1_1_1_5 := false

e_2_1_1_1_5 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.1.1.5: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.1.1.5")
	not e_2_1_1_1_5
}

_v_control_plane contains "2.1.1.1.5: ip ssh authentication-retries must be at most 3 (unset is the default 3)" if {
	_applies("2.1.1.1.5")
	e_2_1_1_1_5
	not r_2_1_1_1_5
}

# 2.1.1.2 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_1_1_2 := false

r_2_1_1_2 if {
	_has(`^ip ssh version 2\s*$`)
}

default e_2_1_1_2 := false

e_2_1_1_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.1.2: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.1.2")
	not e_2_1_1_2
}

_v_control_plane contains "2.1.1.2: ip ssh version 2 must be set" if {
	_applies("2.1.1.2")
	e_2_1_1_2
	not r_2_1_1_2
}

# 2.1.2 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_1_2 := false

r_2_1_2 if {
	_has(`^no cdp run\s*$`)
}

default e_2_1_2 := false

e_2_1_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.2: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.2")
	not e_2_1_2
}

_v_control_plane contains "2.1.2: CDP must be turned off globally (no cdp run)" if {
	_applies("2.1.2")
	e_2_1_2
	not r_2_1_2
}

# 2.1.3 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_1_3 := false

r_2_1_3 if {
	_has(`^(no ip bootp server|ip dhcp bootp ignore)\s*$`)
}

default e_2_1_3 := false

e_2_1_3 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.3: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.3")
	not e_2_1_3
}

_v_control_plane contains "2.1.3: the BOOTP server must be off" if {
	_applies("2.1.3")
	e_2_1_3
	not r_2_1_3
}

# 2.1.4 (Automated, Level 1)
default r_2_1_4 := false

r_2_1_4 if {
	_has(`^no service dhcp\s*$`)
}

default e_2_1_4 := false

e_2_1_4 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.4: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.4")
	not e_2_1_4
}

_v_control_plane contains "2.1.4: the DHCP service must be off (no service dhcp)" if {
	_applies("2.1.4")
	e_2_1_4
	not r_2_1_4
}

# 2.1.5 (Automated, Level 1)
default r_2_1_5 := false

r_2_1_5 if {
	_has(`^service tcp-keepalives-in\s*$`)
}

default e_2_1_5 := false

e_2_1_5 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.5: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.5")
	not e_2_1_5
}

_v_control_plane contains "2.1.5: service tcp-keepalives-in must be on" if {
	_applies("2.1.5")
	e_2_1_5
	not r_2_1_5
}

# 2.1.6 (Automated, Level 1)
default r_2_1_6 := false

r_2_1_6 if {
	_has(`^service tcp-keepalives-out\s*$`)
}

default e_2_1_6 := false

e_2_1_6 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.6: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.6")
	not e_2_1_6
}

_v_control_plane contains "2.1.6: service tcp-keepalives-out must be on" if {
	_applies("2.1.6")
	e_2_1_6
	not r_2_1_6
}

# 2.1.7 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_1_7 := false

r_2_1_7 if {
	_has(`^no service pad\s*$`)
}

default e_2_1_7 := false

e_2_1_7 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.1.7: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.1.7")
	not e_2_1_7
}

_v_control_plane contains "2.1.7: the PAD service must be off (no service pad)" if {
	_applies("2.1.7")
	e_2_1_7
	not r_2_1_7
}

# 2.2.1 (Automated, Level 1)
default r_2_2_1 := false

r_2_2_1 if {
	some s in _secs(`^archive\s*$`)
	_sec_has(s, `^logging enable\s*$`)
}

default e_2_2_1 := false

e_2_2_1 if {
	is_array(input.ios_xe_config.sections)
}

_v_control_plane contains "2.2.1: evidence missing — ios_xe_config.sections not collected" if {
	_applies("2.2.1")
	not e_2_2_1
}

_v_control_plane contains "2.2.1: archive configuration-change logging must be enabled" if {
	_applies("2.2.1")
	e_2_2_1
	not r_2_2_1
}

# 2.2.2 (Automated, Level 1)
default r_2_2_2 := false

r_2_2_2 if {
	some n in _nums(`^logging buffered\s+(\d+)`)
	is_number(n)
	n >= 64000
}

default e_2_2_2 := false

e_2_2_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.2.2: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.2.2")
	not e_2_2_2
}

_v_control_plane contains "2.2.2: logging buffered must set a size of at least 64000 bytes" if {
	_applies("2.2.2")
	e_2_2_2
	not r_2_2_2
}

# 2.2.3 (Automated, Level 1)
default r_2_2_3 := false

r_2_2_3 if {
	_has(`^logging console critical\s*$`)
}

default e_2_2_3 := false

e_2_2_3 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.2.3: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.2.3")
	not e_2_2_3
}

_v_control_plane contains "2.2.3: console logging must be limited to level critical" if {
	_applies("2.2.3")
	e_2_2_3
	not r_2_2_3
}

# 2.2.4 (Automated, Level 1)
default r_2_2_4 := false

r_2_2_4 if {
	_has(`^logging\s+(host\s+)?(\d{1,3}(\.\d{1,3}){3}|ipv6\s+\S+)(\s|$)`)
}

default e_2_2_4 := false

e_2_2_4 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.2.4: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.2.4")
	not e_2_2_4
}

_v_control_plane contains "2.2.4: a syslog host must be set by IP address" if {
	_applies("2.2.4")
	e_2_2_4
	not r_2_2_4
}

# 2.2.5 (Automated, Level 1)
default r_2_2_5 := false

r_2_2_5 if {
	_has(`^logging trap\s+(informational|6)\s*$`)
}

default e_2_2_5 := false

e_2_2_5 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.2.5: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.2.5")
	not e_2_2_5
}

_v_control_plane contains "2.2.5: logging trap must be at level informational" if {
	_applies("2.2.5")
	e_2_2_5
	not r_2_2_5
}

# 2.2.6 (Automated, Level 1)
default r_2_2_6 := false

r_2_2_6 if {
	_has(`^service timestamps debug datetime(\s|$)`)
}

default e_2_2_6 := false

e_2_2_6 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.2.6: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.2.6")
	not e_2_2_6
}

_v_control_plane contains "2.2.6: debug timestamps must carry the date and time" if {
	_applies("2.2.6")
	e_2_2_6
	not r_2_2_6
}

# 2.2.7 (Automated, Level 1)
default r_2_2_7 := false

r_2_2_7 if {
	_has(`^logging source-interface\s+\S+`)
}

default e_2_2_7 := false

e_2_2_7 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.2.7: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.2.7")
	not e_2_2_7
}

_v_control_plane contains "2.2.7: a logging source-interface must be set" if {
	_applies("2.2.7")
	e_2_2_7
	not r_2_2_7
}

# 2.2.8 (Automated, Level 1)
default r_2_2_8 := false

r_2_2_8 if {
	_has(`^login on-failure\s+log(\s|$)`)
	_has(`^login on-success\s+log(\s|$)`)
}

default e_2_2_8 := false

e_2_2_8 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.2.8: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.2.8")
	not e_2_2_8
}

_v_control_plane contains "2.2.8: login success and failure logging must both be on" if {
	_applies("2.2.8")
	e_2_2_8
	not r_2_2_8
}

# 2.3.1.1 (Automated, Level 1)
default r_2_3_1_1 := false

r_2_3_1_1 if {
	_has(`^ntp authenticate\s*$`)
}

default e_2_3_1_1 := false

e_2_3_1_1 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.3.1.1: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.3.1.1")
	not e_2_3_1_1
}

_v_control_plane contains "2.3.1.1: ntp authenticate must be on" if {
	_applies("2.3.1.1")
	e_2_3_1_1
	not r_2_3_1_1
}

# 2.3.1.2 (Automated, Level 1)
default r_2_3_1_2 := false

r_2_3_1_2 if {
	_has(`^ntp authentication-key\s+\d+\s+\S+\s+\S+`)
}

default e_2_3_1_2 := false

e_2_3_1_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.3.1.2: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.3.1.2")
	not e_2_3_1_2
}

_v_control_plane contains "2.3.1.2: an ntp authentication-key must be defined" if {
	_applies("2.3.1.2")
	e_2_3_1_2
	not r_2_3_1_2
}

# 2.3.1.3 (Automated, Level 1)
default r_2_3_1_3 := false

r_2_3_1_3 if {
	_has(`^ntp trusted-key\s+\d+`)
}

default e_2_3_1_3 := false

e_2_3_1_3 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.3.1.3: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.3.1.3")
	not e_2_3_1_3
}

_v_control_plane contains "2.3.1.3: an ntp trusted-key must be defined" if {
	_applies("2.3.1.3")
	e_2_3_1_3
	not r_2_3_1_3
}

# 2.3.1.4 (Manual, Level 2) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_3_1_4 := false

r_2_3_1_4 if {
	count(_ntp_srv) > 0
	every l in _ntp_srv { regex.match(`\skey\s+\d+(\s|$)`, l) }
}

default e_2_3_1_4 := false

e_2_3_1_4 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.3.1.4: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.3.1.4")
	not e_2_3_1_4
}

_v_control_plane contains "2.3.1.4: every ntp server must name an authentication key (at least one server)" if {
	_applies("2.3.1.4")
	e_2_3_1_4
	not r_2_3_1_4
}

# 2.3.2 (Automated, Level 1)
default r_2_3_2 := false

r_2_3_2 if {
	_has(`^ntp server\s+(vrf\s+\S+\s+)?(\d{1,3}(\.\d{1,3}){3}|ipv6\s+\S+)(\s|$)`)
}

default e_2_3_2 := false

e_2_3_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.3.2: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.3.2")
	not e_2_3_2
}

_v_control_plane contains "2.3.2: an ntp server must be set by IP address" if {
	_applies("2.3.2")
	e_2_3_2
	not r_2_3_2
}

# 2.4.1 (Automated, Level 1)
default r_2_4_1 := false

r_2_4_1 if {
	count(_matches(`(?i)^interface\s+loopback\s*\d+\s*$`)) == 1
	some s in _secs(`(?i)^interface\s+loopback\s*\d+\s*$`)
	_sec_has(s, `^ip(v6)? address\s+\S+`)
}

default e_2_4_1 := false

e_2_4_1 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
	is_array(input.ios_xe_config.sections)
}

_v_control_plane contains "2.4.1: evidence missing — ios_xe_config.{lines,sections} not collected" if {
	_applies("2.4.1")
	not e_2_4_1
}

_v_control_plane contains "2.4.1: exactly one loopback interface must exist and carry an IP address" if {
	_applies("2.4.1")
	e_2_4_1
	not r_2_4_1
}

# 2.4.2 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_4_2 := false

r_2_4_2 if {
	_has(`^ip (radius|tacacs) source-interface\s+\S+`)
}

r_2_4_2 if {
	some s in input.ios_xe_config.sections
	_sec_has(s, `^ip (radius|tacacs) source-interface\s+\S+`)
}

default e_2_4_2 := false

e_2_4_2 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
	is_array(input.ios_xe_config.sections)
}

_v_control_plane contains "2.4.2: evidence missing — ios_xe_config.{lines,sections} not collected" if {
	_applies("2.4.2")
	not e_2_4_2
}

_v_control_plane contains "2.4.2: AAA (radius or tacacs) must have a source-interface" if {
	_applies("2.4.2")
	e_2_4_2
	not r_2_4_2
}

# 2.4.3 (Automated, Level 1)
default r_2_4_3 := false

r_2_4_3 if {
	_has(`(?i)^ntp source\s+loopback\s*\d+\s*$`)
}

default e_2_4_3 := false

e_2_4_3 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.4.3: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.4.3")
	not e_2_4_3
}

_v_control_plane contains "2.4.3: ntp source must be a loopback interface" if {
	_applies("2.4.3")
	e_2_4_3
	not r_2_4_3
}

# 2.4.4 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_2_4_4 := false

r_2_4_4 if {
	_has(`(?i)^ip tftp source-interface\s+loopback\s*\d+\s*$`)
}

default e_2_4_4 := false

e_2_4_4 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_control_plane contains "2.4.4: evidence missing — ios_xe_config.lines not collected" if {
	_applies("2.4.4")
	not e_2_4_4
}

_v_control_plane contains "2.4.4: the tftp source-interface must be a loopback interface" if {
	_applies("2.4.4")
	e_2_4_4
	not r_2_4_4
}

# 3.1.1 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_1_1 := false

r_3_1_1 if {
	_has(`^no ip source-route\s*$`)
}

default e_3_1_1 := false

e_3_1_1 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_data_plane contains "3.1.1: evidence missing — ios_xe_config.lines not collected" if {
	_applies("3.1.1")
	not e_3_1_1
}

_v_data_plane contains "3.1.1: IP source routing must be off (no ip source-route)" if {
	_applies("3.1.1")
	e_3_1_1
	not r_3_1_1
}

# 3.1.2 (Manual, Level 2) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_1_2 := false

r_3_1_2 if {
	every s in _l3_ifs { _sec_has(s, `^no ip proxy-arp\s*$`) }
}

default e_3_1_2 := false

e_3_1_2 if {
	is_array(input.ios_xe_config.sections)
	count(_l3_ifs) > 0
}

_v_data_plane contains "3.1.2: evidence missing — ios_xe_config.sections not collected" if {
	_applies("3.1.2")
	not e_3_1_2
}

_v_data_plane contains "3.1.2: every routed non-loopback interface must have no ip proxy-arp" if {
	_applies("3.1.2")
	e_3_1_2
	not r_3_1_2
}

# 3.1.3 (Manual, Level 1) -- Manual in the workbook; decidable from configuration, so checked like Automated
default r_3_1_3 := false

r_3_1_3 if {
	not _has(`(?i)^interface\s+tunnel`)
}

default e_3_1_3 := false

e_3_1_3 if {
	is_array(input.ios_xe_config.lines)
	count(input.ios_xe_config.lines) > 0
}

_v_data_plane contains "3.1.3: evidence missing — ios_xe_config.lines not collected" if {
	_applies("3.1.3")
	not e_3_1_3
}

_v_data_plane contains "3.1.3: tunnel interfaces must not be defined" if {
	_applies("3.1.3")
	e_3_1_3
	not r_3_1_3
}

# 3.1.4 (Manual, Level 1)
default r_3_1_4 := false

r_3_1_4 if {
	input.ios_xe_config.attest.urpf_on_untrusted_interfaces == true
}

_v_data_plane contains "3.1.4: uRPF must be set on the appropriate interfaces (manual review not attested)" if {
	_applies("3.1.4")
	not r_3_1_4
}

# 3.2.1 (Manual, Level 2)
default r_3_2_1 := false

r_3_2_1 if {
	input.ios_xe_config.attest.private_source_acl_defined == true
}

_v_data_plane contains "3.2.1: an ACL must forbid private source addresses from external networks (manual review not attested)" if {
	_applies("3.2.1")
	not r_3_2_1
}

# 3.2.2 (Manual, Level 2)
default r_3_2_2 := false

r_3_2_2 if {
	input.ios_xe_config.attest.external_interface_acl_inbound == true
}

_v_data_plane contains "3.2.2: an inbound ACL must be applied on the external interface (manual review not attested)" if {
	_applies("3.2.2")
	not r_3_2_2
}

# 3.3.1.1 (Manual, Level 2)
default r_3_3_1_1 := false

r_3_3_1_1 if {
	input.ios_xe_config.attest.eigrp_key_chain_defined == true
}

_v_data_plane contains "3.3.1.1: an EIGRP key chain must be defined (manual review not attested)" if {
	_applies("3.3.1.1")
	not r_3_3_1_1
}

# 3.3.1.2 (Manual, Level 2)
default r_3_3_1_2 := false

r_3_3_1_2 if {
	input.ios_xe_config.attest.eigrp_key_defined == true
}

_v_data_plane contains "3.3.1.2: the EIGRP key chain must define keys (manual review not attested)" if {
	_applies("3.3.1.2")
	not r_3_3_1_2
}

# 3.3.1.3 (Manual, Level 2)
default r_3_3_1_3 := false

r_3_3_1_3 if {
	input.ios_xe_config.attest.eigrp_key_string_set == true
}

_v_data_plane contains "3.3.1.3: each EIGRP key must have a key-string (manual review not attested)" if {
	_applies("3.3.1.3")
	not r_3_3_1_3
}

# 3.3.1.4 (Manual, Level 2)
default r_3_3_1_4 := false

r_3_3_1_4 if {
	input.ios_xe_config.attest.eigrp_address_family_set == true
}

_v_data_plane contains "3.3.1.4: the EIGRP address family must be configured (manual review not attested)" if {
	_applies("3.3.1.4")
	not r_3_3_1_4
}

# 3.3.1.5 (Manual, Level 2)
default r_3_3_1_5 := false

r_3_3_1_5 if {
	input.ios_xe_config.attest.eigrp_af_interface_default == true
}

_v_data_plane contains "3.3.1.5: the EIGRP af-interface default must be configured (manual review not attested)" if {
	_applies("3.3.1.5")
	not r_3_3_1_5
}

# 3.3.1.6 (Manual, Level 1)
default r_3_3_1_6 := false

r_3_3_1_6 if {
	input.ios_xe_config.attest.eigrp_af_key_chain == true
}

_v_data_plane contains "3.3.1.6: EIGRP af-interfaces must authenticate with a key chain (manual review not attested)" if {
	_applies("3.3.1.6")
	not r_3_3_1_6
}

# 3.3.1.7 (Manual, Level 1)
default r_3_3_1_7 := false

r_3_3_1_7 if {
	input.ios_xe_config.attest.eigrp_af_auth_md5 == true
}

_v_data_plane contains "3.3.1.7: EIGRP af-interfaces must use authentication mode md5 (manual review not attested)" if {
	_applies("3.3.1.7")
	not r_3_3_1_7
}

# 3.3.1.8 (Manual, Level 1)
default r_3_3_1_8 := false

r_3_3_1_8 if {
	input.ios_xe_config.attest.eigrp_interface_key_chain == true
}

_v_data_plane contains "3.3.1.8: EIGRP interfaces must set an authentication key-chain (manual review not attested)" if {
	_applies("3.3.1.8")
	not r_3_3_1_8
}

# 3.3.1.9 (Manual, Level 1)
default r_3_3_1_9 := false

r_3_3_1_9 if {
	input.ios_xe_config.attest.eigrp_interface_auth_mode == true
}

_v_data_plane contains "3.3.1.9: EIGRP interfaces must set an authentication mode (manual review not attested)" if {
	_applies("3.3.1.9")
	not r_3_3_1_9
}

# 3.3.2.1 (Manual, Level 1)
default r_3_3_2_1 := false

r_3_3_2_1 if {
	input.ios_xe_config.attest.ospf_area_message_digest == true
}

_v_data_plane contains "3.3.2.1: OSPF areas must use message-digest authentication (manual review not attested)" if {
	_applies("3.3.2.1")
	not r_3_3_2_1
}

# 3.3.2.2 (Manual, Level 1)
default r_3_3_2_2 := false

r_3_3_2_2 if {
	input.ios_xe_config.attest.ospf_interface_md5_key == true
}

_v_data_plane contains "3.3.2.2: OSPF interfaces must set an md5 message-digest key (manual review not attested)" if {
	_applies("3.3.2.2")
	not r_3_3_2_2
}

# 3.3.3.1 (Manual, Level 1)
default r_3_3_3_1 := false

r_3_3_3_1 if {
	input.ios_xe_config.attest.bgp_neighbor_password == true
}

_v_data_plane contains "3.3.3.1: BGP neighbors must have a password (manual review not attested)" if {
	_applies("3.3.3.1")
	not r_3_3_3_1
}

# Every recommendation in the benchmark: title, level, assessment status, how it is checked, report section.
recommendations := {
	"1.1.1": {
		"title": "AAA must be turned on globally (aaa new-model)",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.1.2": {
		"title": "a login authentication method list must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.1.3": {
		"title": "enable-mode authentication must use an AAA default method list",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.1.4": {
		"title": "every vty line block must set login authentication",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.1.5": {
		"title": "when the HTTP server is on, ip http authentication must be set",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.1.6": {
		"title": "privilege 15 command accounting must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.1.7": {
		"title": "connection accounting must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.1.8": {
		"title": "EXEC session accounting must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.1.9": {
		"title": "network accounting must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.1.10": {
		"title": "system accounting must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.2.1": {
		"title": "every local username must be at privilege level 1 (none above)",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.2.2": {
		"title": "every vty line block must allow only ssh for transport input",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.2.3": {
		"title": "the aux line must have no exec (a device with no aux line passes)",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.2.4": {
		"title": "an access list for the vty lines must exist and be appropriate",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "management_plane",
	},
	"1.2.5": {
		"title": "every vty line block must set an inbound access-class",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.2.6": {
		"title": "the aux line exec-timeout must be 1 to 10 minutes (a device with no aux line passes)",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.2.7": {
		"title": "the console line exec-timeout must be 1 to 10 minutes",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.2.8": {
		"title": "every vty line block must have an exec-timeout of 1 to 10 minutes",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.2.9": {
		"title": "when the HTTP server is on, ip http max-connections must be 1 or 2",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.2.10": {
		"title": "when the HTTP server is on, the ip http idle timeout must be 1 to 600 seconds",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.3.1": {
		"title": "a exec banner with text must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.3.2": {
		"title": "a login banner with text must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.3.3": {
		"title": "a motd banner with text must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.3.4": {
		"title": "a webauth (auth-proxy) banner must be configured",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.4.1": {
		"title": "an enable secret of hash type 5, 8 or 9 must be set",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.4.2": {
		"title": "service password-encryption must be on",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.4.3": {
		"title": "every local user must have a type 5, 8 or 9 secret",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.5.1": {
		"title": "SNMP must be off when unused",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "management_plane",
	},
	"1.5.2": {
		"title": "an snmp-server community named private must not exist",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.5.3": {
		"title": "an snmp-server community named public must not exist",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.5.4": {
		"title": "no snmp-server community must grant RW access",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.5.5": {
		"title": "every snmp-server community must carry an ACL",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.5.6": {
		"title": "an access list for SNMP must exist and be appropriate",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "management_plane",
	},
	"1.5.7": {
		"title": "when SNMP is in use, an snmp-server host must be set",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.5.8": {
		"title": "when SNMP is in use, snmp-server enable traps snmp must be set",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.5.9": {
		"title": "every SNMPv3 group must use the priv security level",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "management_plane",
	},
	"1.5.10": {
		"title": "SNMPv3 users must use at least AES-128 privacy",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "management_plane",
	},
	"2.1.1.1.1": {
		"title": "a hostname other than the factory default must be set",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.1.1.2": {
		"title": "a global ip domain name must be set",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.1.1.3": {
		"title": "the RSA key modulus must be at least 2048 bits",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "control_plane",
	},
	"2.1.1.1.4": {
		"title": "ip ssh time-out must be 1 to 60 seconds",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.1.1.5": {
		"title": "ip ssh authentication-retries must be at most 3 (unset is the default 3)",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.1.2": {
		"title": "ip ssh version 2 must be set",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.2": {
		"title": "CDP must be turned off globally (no cdp run)",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.3": {
		"title": "the BOOTP server must be off",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.4": {
		"title": "the DHCP service must be off (no service dhcp)",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.5": {
		"title": "service tcp-keepalives-in must be on",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.6": {
		"title": "service tcp-keepalives-out must be on",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.1.7": {
		"title": "the PAD service must be off (no service pad)",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.2.1": {
		"title": "archive configuration-change logging must be enabled",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.2.2": {
		"title": "logging buffered must set a size of at least 64000 bytes",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.2.3": {
		"title": "console logging must be limited to level critical",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.2.4": {
		"title": "a syslog host must be set by IP address",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.2.5": {
		"title": "logging trap must be at level informational",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.2.6": {
		"title": "debug timestamps must carry the date and time",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.2.7": {
		"title": "a logging source-interface must be set",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.2.8": {
		"title": "login success and failure logging must both be on",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.3.1.1": {
		"title": "ntp authenticate must be on",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.3.1.2": {
		"title": "an ntp authentication-key must be defined",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.3.1.3": {
		"title": "an ntp trusted-key must be defined",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.3.1.4": {
		"title": "every ntp server must name an authentication key (at least one server)",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.3.2": {
		"title": "an ntp server must be set by IP address",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.4.1": {
		"title": "exactly one loopback interface must exist and carry an IP address",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.4.2": {
		"title": "AAA (radius or tacacs) must have a source-interface",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.4.3": {
		"title": "ntp source must be a loopback interface",
		"level": 1,
		"assessment": "Automated",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"2.4.4": {
		"title": "the tftp source-interface must be a loopback interface",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "control_plane",
	},
	"3.1.1": {
		"title": "IP source routing must be off (no ip source-route)",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "data_plane",
	},
	"3.1.2": {
		"title": "every routed non-loopback interface must have no ip proxy-arp",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "configuration",
		"section": "data_plane",
	},
	"3.1.3": {
		"title": "tunnel interfaces must not be defined",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "configuration",
		"section": "data_plane",
	},
	"3.1.4": {
		"title": "uRPF must be set on the appropriate interfaces",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.2.1": {
		"title": "an ACL must forbid private source addresses from external networks",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.2.2": {
		"title": "an inbound ACL must be applied on the external interface",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.1.1": {
		"title": "an EIGRP key chain must be defined",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.1.2": {
		"title": "the EIGRP key chain must define keys",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.1.3": {
		"title": "each EIGRP key must have a key-string",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.1.4": {
		"title": "the EIGRP address family must be configured",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.1.5": {
		"title": "the EIGRP af-interface default must be configured",
		"level": 2,
		"assessment": "Manual",
		"profiles": ["Level 2"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.1.6": {
		"title": "EIGRP af-interfaces must authenticate with a key chain",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.1.7": {
		"title": "EIGRP af-interfaces must use authentication mode md5",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.1.8": {
		"title": "EIGRP interfaces must set an authentication key-chain",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.1.9": {
		"title": "EIGRP interfaces must set an authentication mode",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.2.1": {
		"title": "OSPF areas must use message-digest authentication",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.2.2": {
		"title": "OSPF interfaces must set an md5 message-digest key",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "data_plane",
	},
	"3.3.3.1": {
		"title": "BGP neighbors must have a password",
		"level": 1,
		"assessment": "Manual",
		"profiles": ["Level 1"],
		"check": "attestation",
		"section": "data_plane",
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
		"management_plane": {
			"total": count({id | some id, r in recommendations; r.section == "management_plane"; _applies(id)}),
			"violations": count(management_plane_violations),
		},
		"control_plane": {
			"total": count({id | some id, r in recommendations; r.section == "control_plane"; _applies(id)}),
			"violations": count(control_plane_violations),
		},
		"data_plane": {
			"total": count({id | some id, r in recommendations; r.section == "data_plane"; _applies(id)}),
			"violations": count(data_plane_violations),
		},
	},
}

compliance_report := {
	"benchmark": "CIS Cisco IOS XE 17.x Benchmark v2.2.2",
	"level": _level,
	"total_controls": count(in_scope),
	"standard_total": 84,
	"standard_total_source": "CIS Cisco IOS XE 17.x Benchmark v2.2.2, recommendations counted from the CIS workbook",
	"failed_controls": count(_failed_ids),
	"passed_controls": count(in_scope) - count(_failed_ids),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}
