# METADATA
# title: "CIS OPNsense Benchmark v1.0.0"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network, opnsense]
#   coverage:
#     checks: 64
#     cited: 31
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis_opnsense

# CIS OPNsense Benchmark v1.0.0: all 29 recommendations. Every one is in the "Profile 1" sheet;
# the "Profile 2" sheet carries section headings only, so every control is level 1.
# Only 1.4 is "Automated" in the workbook; the rest are "Manual" (GUI/CLI review). Where
# OPNsense's config.xml holds the setting the audit looks at, this policy evaluates it directly
# and fails closed when the section was not collected. The rest need a person to review them,
# and they pass only on an explicit attestation boolean (input.attest.<name> == true).
#
# Input contract: OPNsense /conf/config.xml (root <opnsense>) parsed to JSON, sections passed
# through under their own names. A single repeated element may arrive as an object; an empty
# element may arrive as "" or null.
#   input.system         : hostname, dnsserver, timezone, timeservers (space separated),
#                          backupcount, ipv6allow (<= 25.7), disableconsolemenu,
#                          authserver[] {name, type}, webgui {protocol, ssl-hsts,
#                          session_timeout, nodnsrebindcheck}
#   input.ntpd           : prefer (space separated)
#   input.filter.rule[]  : legacy firewall rules (type, interface, floating, disabled, log, descr,
#                          protocol, source{any|network|address}, destination{..., port})
#   input.OPNsense       : the MVC subtree, verbatim. Used here:
#                          Firewall.Filter.rules.rule[]   (rules in the new/MVC rule set)
#                          Interfaces.settings.disableipv6 (26.1 and later)
#                          unboundplus.general.dnssec
#                          Syslog.destinations.destination[] {enabled, hostname}
#   input.sshd_config    : text of /usr/local/etc/ssh/sshd_config   (1.1)
#   input.motd           : text of /var/run/motd                     (1.3)
#   input.attest.*       : attestation booleans for the review-only recommendations
#
# Two boolean encodings: legacy checkboxes (system.*, filter.rule) are present-or-absent, so a
# present key means set (helper flag). MVC BooleanFields (input.OPNsense.*) are "1"/"0", so
# they are compared to "1" explicitly (helper mvc_on); "" there is not "on".
#
# OPA endpoint: POST /v1/data/cis_opnsense/compliance_assessment

import rego.v1

default compliant := false

compliant if count(violations) == 0

# ── Recommendation table (ids, titles and profiles from the v1.0.0 workbook) ──────────────

controls := {
	"1.1": {"section": "1", "level": 1, "title": "Ensure SSH warning banner is configured"},
	"1.2": {"section": "1", "level": 1, "title": "Ensure Backup count is set to 5 or more."},
	"1.3": {"section": "1", "level": 1, "title": "Ensure 'Message Of The Day (MOTD)' is set"},
	"1.4": {"section": "1", "level": 1, "title": "Ensure Hostname is set"},
	"1.5": {"section": "1", "level": 1, "title": "Ensure DNS server is configured"},
	"1.6": {"section": "1", "level": 1, "title": "Ensure IPv6 is disabled if not used"},
	"1.7": {"section": "1", "level": 1, "title": "Ensure 'Disable DNS Rebinding Checks' is unchecked"},
	"1.8": {"section": "1", "level": 1, "title": "Ensure Web Management is Set to use HTTPS"},
	"2.1": {"section": "2", "level": 1, "title": "Ensure Sessions Timeout is set to less than or equal to 10 Minutes"},
	"2.2": {"section": "2", "level": 1, "title": "Ensure LDAP or RADIUS server configured"},
	"2.3": {"section": "2", "level": 1, "title": "Ensure Console Menu is Password Protected"},
	"2.4": {"section": "2", "level": 1, "title": "Ensure all default accounts are either disabled or utilize strong passwords"},
	"3.1": {"section": "3", "level": 1, "title": "Ensure 'Local Account status' is set to 'Disabled'"},
	"3.2": {"section": "3", "level": 1, "title": "Ensure Login Protection methods are enabled."},
	"3.3": {"section": "3", "level": 1, "title": "Ensure default password of admin is changed"},
	"4.1.1": {"section": "4", "level": 1, "title": "Ensure Default Deny is Enforced on All Internal Interfaces"},
	"4.1.2": {"section": "4", "level": 1, "title": "Ensure Least Privilege is Applied to All Permit Rules"},
	"4.1.3": {"section": "4", "level": 1, "title": "Ensure “Any → Any” Rules are Prohibited"},
	"4.1.4": {"section": "4", "level": 1, "title": "Ensure Every Rule Has a Description Using a Standard Format"},
	"4.1.5": {"section": "4", "level": 1, "title": "Ensure Aliases are Used for Hosts, Networks, and Port Groups"},
	"4.1.6": {"section": "4", "level": 1, "title": "Ensure Rules are Implemented on the Ingress Interface"},
	"4.1.7": {"section": "4", "level": 1, "title": "Ensure Standard Rule Ordering is Used Per Interface"},
	"4.1.8": {"section": "4", "level": 1, "title": "Ensure Floating Rules are Restricted to Cross-Zone Policy Use Cases"},
	"5.1.1": {"section": "5", "level": 1, "title": "Ensure time zone is properly configured"},
	"5.2.1": {"section": "5", "level": 1, "title": "Ensure 'DNSSEC' is Enable on DNS Service"},
	"5.3.1": {"section": "5", "level": 1, "title": "Ensure WireGuard is used as the default VPN method"},
	"6.1": {"section": "6", "level": 1, "title": "Ensure Logging is Enabled for Inter-Zone Deny Rules"},
	"6.2": {"section": "6", "level": 1, "title": "Ensure Logging is Enabled for Management Plane Deny Rules"},
	"6.3": {"section": "6", "level": 1, "title": "Ensure Remote Syslog is Configured"},
}

# Review-only recommendations: control id -> attestation key under input.attest.
# 5.3.1: the title (use WireGuard) and the audit (no WireGuard unless required) disagree, so
# this policy does not pick a reading from config; the reviewer attests.
attestations := {
	"2.4": "default_accounts_secured",
	"3.1": "local_accounts_disabled",
	"3.3": "default_root_password_changed",
	"4.1.1": "default_deny_internal_interfaces",
	"4.1.5": "aliases_used",
	"4.1.6": "rules_on_ingress_interface",
	"4.1.7": "standard_rule_ordering",
	"5.3.1": "vpn_method_reviewed",
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

# Legacy checkbox: set when the key is present and not an explicit "off" value.
flag(obj, key) if {
	is_object(obj)
	key in object.keys(obj)
	not obj[key] in {"0", 0, false, "no", "off", "disabled"}
}

# MVC BooleanField: on only when it is "1".
mvc_on(x) if sprintf("%v", [x]) in {"1", "true"}

str(x) := trim_space(sprintf("%v", [x])) if x != null

str(null) := ""

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

csv(x) := [t | some p in split(str(x), ","); t := trim_space(p); t != ""]

words(x) := [t | some p in split(str(x), " "); t := trim_space(p); t != ""]

system_collected if nonempty_object(input.system)

webgui_collected if nonempty_object(input.system.webgui)

ntpd_collected if nonempty_object(input.ntpd)

sshd_config_collected if is_string(input.sshd_config)

motd_collected if is_string(input.motd)

unbound_mvc_collected if nonempty_object(input.OPNsense.unboundplus.general)

syslog_mvc_collected if nonempty_object(input.OPNsense.Syslog)

ifsettings_mvc_collected if nonempty_object(input.OPNsense.Interfaces.settings)

# ── Firewall rules: legacy filter.rule[] and MVC Firewall.Filter.rules.rule[], one shape ──

legacy_side_any(r, side) if not r[side]

legacy_side_any(r, side) if r[side] == null

legacy_side_any(r, side) if {
	is_object(r[side])
	"any" in object.keys(r[side])
}

legacy_self(r) if str(r.destination.network) == "(self)"

legacy_self(r) if regex.match(`^[a-z0-9_]+ip$`, str(r.destination.network))

mvc_self(r) if str(object.get(r, "destination_net", "")) == "(self)"

mvc_self(r) if regex.match(`^[a-z0-9_]+ip$`, str(object.get(r, "destination_net", "")))

# Boolean-valued wrappers, so the rule objects below always carry true/false.
b_flag(o, k) if flag(o, k)

else := false

b_mvc_on(x) if mvc_on(x)

else := false

b_legacy_any(r, side) if legacy_side_any(r, side)

else := false

b_legacy_self(r) if legacy_self(r)

else := false

b_mvc_self(r) if mvc_self(r)

else := false

b_legacy_floating(r, ifs) if legacy_floating(r, ifs)

else := false

b_mvc_floating(r, ifs) if mvc_floating(r, ifs)

else := false

not_true(x) := x == false

legacy_rules := [n |
	some i, r in as_list(input.filter.rule)
	is_object(r)
	ifs := csv(object.get(r, "interface", ""))
	n := {
		"id": sprintf("legacy#%d", [i]),
		# A rule with no type is treated as an allow (fail closed).
		"action": lower(str(object.get(r, "type", "pass"))),
		"enabled": not_true(b_flag(r, "disabled")),
		"log": b_flag(r, "log"),
		"descr": str(object.get(r, "descr", "")),
		"interfaces": ifs,
		"floating": b_legacy_floating(r, ifs),
		"src_any": b_legacy_any(r, "source"),
		"dst_any": b_legacy_any(r, "destination"),
		"dst_self": b_legacy_self(r),
		"dst_port": str(object.get(object.get(r, "destination", {}), "port", "")),
		"protocol": lower(str(object.get(r, "protocol", "any"))),
	}
]

legacy_floating(r, _) if flag(r, "floating")

legacy_floating(_, ifs) if count(ifs) != 1

mvc_rules := [n |
	some i, r in as_list(input.OPNsense.Firewall.Filter.rules.rule)
	is_object(r)
	ifs := csv(object.get(r, "interface", ""))
	n := {
		"id": sprintf("mvc#%d", [i]),
		"action": lower(str(object.get(r, "action", "pass"))),
		# enabled defaults to 1 in the model; only an explicit "0" disables a rule.
		"enabled": str(object.get(r, "enabled", "1")) != "0",
		"log": b_mvc_on(object.get(r, "log", "0")),
		"descr": str(object.get(r, "description", "")),
		"interfaces": ifs,
		"floating": b_mvc_floating(r, ifs),
		"src_any": lower(str(object.get(r, "source_net", "any"))) in {"", "any"},
		"dst_any": lower(str(object.get(r, "destination_net", "any"))) in {"", "any"},
		"dst_self": b_mvc_self(r),
		"dst_port": str(object.get(r, "destination_port", "")),
		"protocol": lower(str(object.get(r, "protocol", "any"))),
	}
]

# OPNsense treats an MVC rule on zero or several interfaces, or an inverted interface, as floating.
mvc_floating(r, _) if mvc_on(object.get(r, "interfacenot", "0"))

mvc_floating(_, ifs) if count(ifs) != 1

all_rules := array.concat(legacy_rules, mvc_rules)

# A real OPNsense always has rules (the factory LAN allow rules at least). An empty rule set
# means the section was not collected (the collector defaults filter to {"rule": []}).
rules_collected if count(all_rules) > 0

active_rules := [r | some r in all_rules; r.enabled]

allow_rules := [r | some r in active_rules; r.action == "pass"]

deny_rules := [r | some r in active_rules; r.action in {"block", "reject"}]

rule_label(r) := sprintf("%s (%s)", [r.id, r.descr]) if r.descr != ""

rule_label(r) := r.id if r.descr == ""

# Service "any": no protocol, or TCP/UDP with no destination port.
service_any(r) if r.protocol in {"", "any"}

service_any(r) if {
	r.protocol in {"tcp", "udp", "tcp/udp"}
	r.dst_port == ""
}

broad_allow(r) if r.src_any

broad_allow(r) if r.dst_any

broad_allow(r) if service_any(r)

webgui_port := str(input.system.webgui.port) if nonblank(str(input.system.webgui.port))

mgmt_ports := {"22", "80", "443"} | {p | p := webgui_port}

mgmt_rule(r) if r.dst_self

mgmt_rule(r) if r.dst_port in mgmt_ports

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

# 1.2: backups kept >= 5. Unset means the OPNsense default of 100.
default ok_1_2 := false

ok_1_2 if {
	system_collected
	not "backupcount" in object.keys(input.system)
}

ok_1_2 if {
	is_digits(input.system.backupcount)
	to_number(str(input.system.backupcount)) >= 5
}

# 1.3: /var/run/motd carries site text, not the stock OPNsense greeting.
default ok_1_3 := false

ok_1_3 if {
	nonblank(input.motd)
	not contains(lower(input.motd), "hello, this is opnsense")
}

# 1.4: hostname set and changed from the factory default.
default ok_1_4 := false

ok_1_4 if {
	nonblank(input.system.hostname)
	lower(trim_space(input.system.hostname)) != "opnsense"
}

# 1.5: at least one DNS server configured.
default ok_1_5 := false

ok_1_5 if count([s | some s in as_strings(input.system.dnsserver); trim_space(s) != ""]) > 0

# 1.6: IPv6 is off, or the organization attests IPv6 is in use.
# 26.1+ keeps it in MVC Interfaces.settings.disableipv6; earlier releases in system.ipv6allow.
# An absent ipv6allow only means "off" on a <= 25.7 config, recognised by an MVC subtree that
# has no Interfaces.settings. Without the MVC subtree the release is unknown: evidence missing.
default ipv6_collected := false

ipv6_collected if ifsettings_mvc_collected

ipv6_collected if legacy_ipv6_config

legacy_ipv6_config if {
	not ifsettings_mvc_collected
	nonempty_object(input.OPNsense)
	system_collected
}

ipv6_off if mvc_on(input.OPNsense.Interfaces.settings.disableipv6)

ipv6_off if {
	legacy_ipv6_config
	not flag(input.system, "ipv6allow")
}

default ok_1_6 := false

ok_1_6 if ipv6_off

ok_1_6 if {
	ipv6_collected
	attested("ipv6_required")
}

# 1.7: "Disable DNS Rebinding Checks" left unchecked.
default ok_1_7 := false

ok_1_7 if {
	webgui_collected
	not flag(input.system.webgui, "nodnsrebindcheck")
}

# 1.8: the audit asks for HSTS; the title for HTTPS. Both are required.
default ok_1_8 := false

ok_1_8 if {
	lower(str(input.system.webgui.protocol)) == "https"
	flag(input.system.webgui, "ssl-hsts")
}

s1_evidence contains "1.1: evidence missing — input.sshd_config not collected" if not sshd_config_collected

s1_evidence contains "1.3: evidence missing — input.motd not collected" if not motd_collected

s1_evidence contains sprintf("%s: evidence missing — input.system not collected", [id]) if {
	not system_collected
	some id in ["1.2", "1.4", "1.5"]
}

s1_evidence contains "1.6: evidence missing — input.OPNsense.Interfaces.settings (or, for <= 25.7, input.system with input.OPNsense) not collected" if not ipv6_collected

s1_evidence contains sprintf("%s: evidence missing — input.system.webgui not collected", [id]) if {
	not webgui_collected
	some id in ["1.7", "1.8"]
}

section_1_violations contains v if some v in s1_evidence

section_1_violations contains "1.1: SSH login banner not configured (no Banner directive, or Banner none)" if {
	sshd_config_collected
	not ok_1_1
}

section_1_violations contains "1.2: configuration backup count is below 5" if {
	system_collected
	not ok_1_2
}

section_1_violations contains "1.3: message of the day is empty or still the stock OPNsense greeting" if {
	motd_collected
	not ok_1_3
}

section_1_violations contains "1.4: hostname is unset or still the factory default 'OPNsense'" if {
	system_collected
	not ok_1_4
}

section_1_violations contains "1.5: no DNS server configured under System > Settings > General" if {
	system_collected
	not ok_1_5
}

section_1_violations contains "1.6: IPv6 is allowed and IPv6 use is not attested (input.attest.ipv6_required)" if {
	ipv6_collected
	not ok_1_6
}

section_1_violations contains "1.7: DNS rebinding checks are disabled on the web GUI" if {
	webgui_collected
	not ok_1_7
}

section_1_violations contains "1.8: web GUI is not HTTPS with HTTP Strict Transport Security enabled" if {
	webgui_collected
	not ok_1_8
}

# ── Section 2: Users Management ───────────────────────────────────────────────────────

auth_types := {lower(str(object.get(s, "type", ""))) |
	some s in as_list(input.system.authserver)
	is_object(s)
}

# 2.1: session timeout 1..10 minutes. Unset means the OPNsense default of 240.
default ok_2_1 := false

ok_2_1 if {
	t := input.system.webgui.session_timeout
	is_digits(t)
	n := to_number(str(t))
	n > 0
	n <= 10
}

# 2.2: an LDAP (optionally with TOTP) or RADIUS authentication server exists.
default ok_2_2 := false

ok_2_2 if count(auth_types & {"ldap", "ldap-totp", "radius"}) > 0

# 2.3: "Password protect the console menu" is checked.
default ok_2_3 := false

ok_2_3 if flag(input.system, "disableconsolemenu")

section_2_violations contains "2.1: evidence missing — input.system.webgui not collected" if not webgui_collected

section_2_violations contains sprintf("%s: evidence missing — input.system not collected", [id]) if {
	not system_collected
	some id in ["2.2", "2.3"]
}

section_2_violations contains "2.1: web GUI session timeout is unset (240 min default), 0 or over 10 minutes" if {
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

# 3.2: a TOTP-capable authentication server (local TOTP or LDAP + TOTP) exists.
default ok_3_2 := false

ok_3_2 if count(auth_types & {"totp", "ldap-totp"}) > 0

section_3_violations contains "3.2: evidence missing — input.system not collected" if not system_collected

section_3_violations contains "3.2: no TOTP authentication server (two-factor login) configured" if {
	system_collected
	not ok_3_2
}

# ── Section 4: Firewall Policy ────────────────────────────────────────────────────────

section_4_violations contains sprintf("%s: evidence missing — input.filter.rule / input.OPNsense.Firewall.Filter.rules not collected", [id]) if {
	not rules_collected
	some id in ["4.1.2", "4.1.3", "4.1.4", "4.1.8"]
}

# 4.1.2: broad allow rules (any source, any destination or any service) need a recorded
# business justification; config finds them, the reviewer attests the justification.
section_4_violations contains sprintf("4.1.2: allow rule %s is broad (any source, destination or service) and its justification is not attested (input.attest.broad_permit_rules_justified)", [rule_label(r)]) if {
	some r in allow_rules
	broad_allow(r)
	not attested("broad_permit_rules_justified")
}

# 4.1.3: literal any -> any on any port. The factory "LAN net to any" rule does not match this
# (its source is the LAN net); 4.1.2 reports it.
section_4_violations contains sprintf("4.1.3: allow rule %s permits any source to any destination on any port", [rule_label(r)]) if {
	some r in allow_rules
	r.src_any
	r.dst_any
	r.dst_port == ""
}

# 4.1.4: config shows an empty description; whether the text follows the site standard is
# a review, attested separately.
section_4_violations contains sprintf("4.1.4: rule %s has no description", [r.id]) if {
	some r in active_rules
	r.descr == ""
}

section_4_violations contains "4.1.4: rule description format not attested (input.attest.rule_descriptions_standardized)" if {
	rules_collected
	not attested("rule_descriptions_standardized")
}

# 4.1.8: no floating rules passes; otherwise their scope and justification need review.
section_4_violations contains sprintf("4.1.8: floating rule %s is in use and its justification is not attested (input.attest.floating_rules_justified)", [rule_label(r)]) if {
	some r in active_rules
	r.floating
	not attested("floating_rules_justified")
}

# ── Section 5: Service Configuration ──────────────────────────────────────────────────

# config.xml stores these space separated; a list of names is accepted too.
spaced(x) := [w | some s in as_strings(x); some w in words(s)]

timeservers := spaced(input.system.timeservers)

# 5.1.1: the title asks for the time zone, the audit for NTP servers with one preferred.
default ok_5_1_1 := false

ok_5_1_1 if {
	nonblank(input.system.timezone)
	count(timeservers) > 0
	some p in spaced(input.ntpd.prefer)
	p in timeservers
}

default ok_5_2_1 := false

ok_5_2_1 if mvc_on(input.OPNsense.unboundplus.general.dnssec)

section_5_violations contains "5.1.1: evidence missing — input.system not collected" if not system_collected

section_5_violations contains "5.1.1: evidence missing — input.ntpd not collected" if not ntpd_collected

section_5_violations contains "5.2.1: evidence missing — input.OPNsense.unboundplus.general not collected" if not unbound_mvc_collected

section_5_violations contains "5.1.1: time zone unset, no NTP servers, or no NTP server marked prefer" if {
	system_collected
	ntpd_collected
	not ok_5_1_1
}

section_5_violations contains "5.2.1: DNSSEC support is not enabled on Unbound DNS" if {
	unbound_mvc_collected
	not ok_5_2_1
}

# ── Section 6: Logging ────────────────────────────────────────────────────────────────

# 6.1 / 6.2: which deny rules are inter-zone or protect the management plane is not fully
# visible in config. 6.1 is checked on every enabled block/reject rule (stricter than the
# benchmark); 6.2 on deny rules aimed at the firewall itself ((self) or <if>ip) or at the
# SSH / web GUI ports.
section_6_violations contains sprintf("%s: evidence missing — input.filter.rule / input.OPNsense.Firewall.Filter.rules not collected", [id]) if {
	not rules_collected
	some id in ["6.1", "6.2"]
}

section_6_violations contains sprintf("6.1: deny rule %s does not log matched packets", [rule_label(r)]) if {
	some r in deny_rules
	not r.log
}

section_6_violations contains sprintf("6.2: management-plane deny rule %s does not log matched packets", [rule_label(r)]) if {
	some r in deny_rules
	mgmt_rule(r)
	not r.log
}

default ok_6_3 := false

ok_6_3 if {
	some d in as_list(input.OPNsense.Syslog.destinations.destination)
	is_object(d)
	mvc_on(object.get(d, "enabled", "0"))
	nonblank(str(object.get(d, "hostname", "")))
}

section_6_violations contains "6.3: evidence missing — input.OPNsense.Syslog not collected" if not syslog_mvc_collected

section_6_violations contains "6.3: no enabled remote syslog destination configured" if {
	syslog_mvc_collected
	not ok_6_3
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

compliance_percentage := ((total_controls - count(failing_controls)) * 100) / total_controls

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
	"benchmark": "CIS OPNsense Benchmark v1.0.0",
	"summary": {
		"total_controls": total_controls,
		"controls_evaluated": total_controls,
		"passing_controls": total_controls - count(failing_controls),
		"failing_controls": count(failing_controls),
		"compliance_percentage": compliance_percentage,
		"overall_compliance": _overall_compliance,
	},
	"violations": violations,
	"section_compliance": section_compliance,
	"device_info": {
		# object.get on {} keeps the report defined when input.system is missing.
		"hostname": object.get(object.get(input, "system", {}), "hostname", "unknown"),
		"domain": object.get(object.get(input, "system", {}), "domain", "unknown"),
		"version": object.get(input, "version", "unknown"),
		"platform": object.get(input, "platform", "opnsense"),
	},
}
