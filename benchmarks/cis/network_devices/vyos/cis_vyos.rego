# METADATA
# title: "CIS VyOS Router Hardening Benchmark v1.0.0"
# custom:
#   class: security
#   framework: cis_network_devices
#   source: cis
#   domains: [network]
#   coverage:
#     checks: 35
#     cited: 26
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.5.0
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
# How `show configuration json` writes a setting, and so what each fact must be:
#   valueless node  (`set service ssh disable-password-authentication`)  {} ; null is read the same way
#   leaf value      (`client-keepalive-interval 60`)                      a string, numbers included ("60")
#   multi-value leaf (`name-server`)                                      a list of strings
#   tag / container node (`ntp server <name>`, `service ssh`)             an object
# A node that is absent is not configured. Anything else in a node's place (the strings "true", "false",
# "no", a number, a boolean where a subtree belongs) is not VyOS configuration: the control fails and the
# finding says "evidence invalid". input.service must be collected for the controls that pass when a
# service is absent (2.1.1 to 2.1.3); without it they report "evidence missing".
#
# OPA endpoint: POST http://localhost:8181/v1/data/cis_vyos/compliance_assessment

import rego.v1

default compliant := false

# ── Helpers ───────────────────────────────────────────────────────────────────

_obj(path) := v if {
	v := object.get(input, path, null)
	is_object(v)
}

# object.get that is defined (as the fallback) when the parent is not an object
_at(path) := object.get(input, path, "__absent__") if {
	is_object(object.get(input, array.slice(path, 0, count(path) - 1), null))
}

_at(path) := "__absent__" if not is_object(object.get(input, array.slice(path, 0, count(path) - 1), null))

# state of a valueless node: "absent", "set" ({} or null, or the boolean true a normalising collector sends),
# "off" (the boolean false) or "invalid" (anything else)
_node_state(v) := "absent" if v == "__absent__"

_node_state(v) := "set" if v in {null, {}, true}

_node_state(false) := "off"

_node_state(v) := "invalid" if {
	v != "__absent__"
	not v in {null, {}, true, false}
}

_node(path) := _node_state(_at(path))

# state of a container node (a service subtree): "absent", "present" (an object, or null for an empty
# subtree), "off" (false) or "invalid"
_tree_state(v) := "absent" if v == "__absent__"

_tree_state(v) := "present" if is_object(v)

_tree_state(null) := "present"

_tree_state(false) := "off"

_tree_state(v) := "invalid" if {
	v != "__absent__"
	v != null
	v != false
	not is_object(v)
}

_tree(path) := _tree_state(_at(path))

_nonblank(v) if {
	is_string(v)
	trim_space(v) != ""
}

# a leaf holding a whole number: the string VyOS writes ("60"), or a JSON number
_int(v) := to_number(trim_space(v)) if {
	is_string(v)
	regex.match(`^\s*[0-9]+\s*$`, v)
}

_int(v) := v if is_number(v)

_path(path) := concat(".", path)

_invalid_node(id, path) := sprintf("%s evidence invalid — %s must be a valueless node ({}), got %s", [id, _path(path), type_name(_at(path))])

_invalid_tree(id, path) := sprintf("%s evidence invalid — %s must be an object, got %s", [id, _path(path), type_name(_at(path))])

default _service_collected := false

_service_collected if is_object(input.service)

_service_missing(id) := sprintf("%s evidence missing — input.service not collected", [id])

# ── Section 1: SSH / Remote Access ───────────────────────────────────────────

# 1.1.1  SSH must be enabled (management access must be SSH, not telnet)
ssh_enabled if _tree(["service", "ssh"]) == "present"

# 1.1.2  Only SSH v2 allowed (VyOS defaults to v2; a finding only if v1 is forced)
ssh_version_2 if _node(["service", "ssh", "v1-enabled"]) in {"absent", "off"}

# 1.1.3  Password-only auth disabled — keys required
ssh_no_password_auth if _node(["service", "ssh", "disable-password-authentication"]) == "set"

# 1.1.4  SSH idle timeout ≤ 300 seconds
ssh_timeout_ok if {
	timeout := _int(_at(["service", "ssh", "client-keepalive-interval"]))
	timeout > 0
	timeout <= 300
}

# 1.1.5  Root login explicitly disabled
ssh_no_root_login if _node(["service", "ssh", "allow-root"]) in {"absent", "off"}

# 1.1.6  Login banner configured
login_banner_configured if _nonblank(input.system.login.banner)

section_1_violations contains msg if {
	not ssh_enabled
	_tree(["service", "ssh"]) != "invalid"
	msg := "1.1.1 SSH service not configured — telnet or no remote access"
}

section_1_violations contains _invalid_tree("1.1.1", ["service", "ssh"]) if _tree(["service", "ssh"]) == "invalid"

section_1_violations contains msg if {
	ssh_enabled
	_node(["service", "ssh", "v1-enabled"]) == "set"
	msg := "1.1.2 SSH v1 explicitly enabled — disable immediately"
}

section_1_violations contains _invalid_node("1.1.2", ["service", "ssh", "v1-enabled"]) if {
	ssh_enabled
	_node(["service", "ssh", "v1-enabled"]) == "invalid"
}

section_1_violations contains msg if {
	ssh_enabled
	_node(["service", "ssh", "disable-password-authentication"]) in {"absent", "off"}
	msg := "1.1.3 SSH password authentication enabled — require key-based auth"
}

section_1_violations contains _invalid_node("1.1.3", ["service", "ssh", "disable-password-authentication"]) if {
	ssh_enabled
	_node(["service", "ssh", "disable-password-authentication"]) == "invalid"
}

section_1_violations contains msg if {
	ssh_enabled
	not ssh_timeout_ok
	msg := "1.1.4 SSH client-keepalive-interval not set or exceeds 300s"
}

section_1_violations contains msg if {
	ssh_enabled
	_node(["service", "ssh", "allow-root"]) == "set"
	msg := "1.1.5 SSH root login not explicitly disabled"
}

section_1_violations contains _invalid_node("1.1.5", ["service", "ssh", "allow-root"]) if {
	ssh_enabled
	_node(["service", "ssh", "allow-root"]) == "invalid"
}

section_1_violations contains msg if {
	not login_banner_configured
	msg := "1.1.6 Login banner not configured (required for legal notice)"
}

# ── Section 2: Management Services ───────────────────────────────────────────

# 2.1.1  Telnet explicitly disabled
telnet_disabled if {
	_service_collected
	_tree(["service", "telnet"]) in {"absent", "off"}
}

# 2.1.2  HTTP management disabled (HTTPS only if GUI in use)
http_disabled if {
	_service_collected
	_tree(["service", "http"]) in {"absent", "off"}
}

# 2.1.3  SNMP disabled or v3 only
snmp_secure if {
	_service_collected
	_tree(["service", "snmp"]) in {"absent", "off"}
}

snmp_secure if {
	count(_obj(["service", "snmp", "v3"])) > 0
	_at(["service", "snmp", "community"]) == "__absent__" # no v1/v2c communities
}

# 2.1.4  NTP configured with at least one server (a tag node: one key per server)
ntp_configured if count(_obj(["system", "ntp", "server"])) >= 1

# 2.1.5  Remote syslog configured
syslog_remote if {
	some server, _ in _obj(["system", "syslog", "host"])
	_nonblank(server)
}

# 2.1.6  DNS name-servers configured (a multi-value leaf: a list of strings)
dns_configured if {
	servers := input.system["name-server"]
	is_array(servers)
	count(servers) >= 1
	every s in servers {
		_name_server(s)
	}
}

# `set system name-server` takes an IPv4 or IPv6 address, or the interface whose DHCP lease supplies one
_name_server(s) if {
	is_string(s)
	regex.match(`^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*|[a-z]+[0-9]+(\.[0-9]+)?)$`, trim_space(s))
}

section_2_violations contains _service_missing(id) if {
	not _service_collected
	some id in ["2.1.1", "2.1.2", "2.1.3"]
}

section_2_violations contains msg if {
	_tree(["service", "telnet"]) == "present"
	msg := "2.1.1 Telnet service enabled — disable immediately"
}

section_2_violations contains _invalid_tree("2.1.1", ["service", "telnet"]) if _tree(["service", "telnet"]) == "invalid"

section_2_violations contains msg if {
	_tree(["service", "http"]) == "present"
	msg := "2.1.2 HTTP management service enabled — use HTTPS only"
}

section_2_violations contains _invalid_tree("2.1.2", ["service", "http"]) if _tree(["service", "http"]) == "invalid"

section_2_violations contains msg if {
	_tree(["service", "snmp"]) == "present"
	not snmp_secure
	msg := "2.1.3 SNMP v1/v2c community configured — use SNMPv3 or disable SNMP"
}

section_2_violations contains _invalid_tree("2.1.3", ["service", "snmp"]) if _tree(["service", "snmp"]) == "invalid"

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

_rulesets := _obj(["firewall", "name"])

# 3.1.1  At least one firewall ruleset exists
firewall_defined if count(_rulesets) >= 1

# 3.1.2  WAN-facing interface has a firewall applied
wan_firewall_applied if {
	some _, config in _obj(["interfaces", "ethernet"])
	is_string(config.description)
	lower(config.description) == "wan"
	config.firewall["in"].name in object.keys(_rulesets) # names a ruleset that exists
}

wan_firewall_applied if {
	some _, config in _obj(["interfaces", "ethernet"])
	is_string(config.description)
	lower(config.description) == "wan"
	config.firewall.local.name in object.keys(_rulesets) # names a ruleset that exists
}

# 3.1.3  At least one ruleset uses default-action drop
default_deny_exists if {
	some _, ruleset in _rulesets
	ruleset["default-action"] == "drop"
}

# 3.1.4  State-based connection tracking enabled (stateful inspection)
stateful_enabled if {
	some _, ruleset in _rulesets
	some _, rule in ruleset.rule
	rule.state.established.action == "accept"
	rule.state.related.action == "accept"
}

# 3.1.5  Firewall logging enabled on at least one deny rule (`log` is a valueless node)
firewall_logging_enabled if {
	some _, ruleset in _rulesets
	some _, rule in ruleset.rule
	rule.action == "drop"
	_node_state(object.get(rule, "log", "__absent__")) == "set"
}

# 3.1.6  Source routing (IP options) disabled
# VyOS has no system.ip["source-route"] key. Source routing is disabled by an
# explicit setting (a valueless node, serialised as null/{}), so the key must be
# PRESENT: an absent setting is not evidence that source routing is disabled.
source_routing_disabled if _node(["system", "ip", "disable-source-route"]) == "set"

source_routing_disabled if _at(["firewall", "ip-src-route"]) == "disable"

source_routing_disabled if _at(["firewall", "global-options", "ip-src-route"]) == "disable"

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
	_node(["system", "ip", "disable-source-route"]) != "invalid"
	msg := "3.1.6 IP source routing not explicitly disabled"
}

section_3_violations contains _invalid_node("3.1.6", ["system", "ip", "disable-source-route"]) if {
	not source_routing_disabled
	_node(["system", "ip", "disable-source-route"]) == "invalid"
}

# ── Section 4: User Account Security ─────────────────────────────────────────

_users := _obj(["system", "login", "user"])

# a crypt(3) hash ($6$...), or a locked account (! or *)
_password_hash(v) if {
	is_string(v)
	regex.match(`^\$[0-9a-z]+\$.+`, v)
}

_password_hash(v) if v in {"!", "*"}

# 4.1.1  Default 'vyos' user has a non-default password (hashed, not plain)
default_user_secured if {
	hash := _users.vyos.authentication["encrypted-password"]
	_password_hash(hash)
	hash != "$6$defaultvyos"
}

# renamed away from the default: the user table was collected, holds a user, and none is named vyos
default_user_secured if {
	count(_users) > 0
	not "vyos" in object.keys(_users)
}

# 4.1.2  All users have encrypted passwords (not plaintext). VyOS leaves `plaintext-password ""` behind
# once it has hashed a password, so an empty string there is not a plaintext password.
_no_plaintext(auth) if not "plaintext-password" in object.keys(auth)

_no_plaintext(auth) if auth["plaintext-password"] == ""

all_users_encrypted if {
	count(_users) > 0
	every _, user in _users {
		_password_hash(user.authentication["encrypted-password"])
		_no_plaintext(user.authentication)
	}
}

# 4.1.3  No operator-level users with admin capabilities beyond their role
operator_accounts_scoped if {
	every _, user in input.system.login.user {
		user.level == "admin" # all accounts explicitly admin or operator
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
	name := input.system["host-name"]
	is_string(name)
	name != "vyos"
	count(name) > 3
}

# 5.1.2  Timezone explicitly configured
timezone_configured if _nonblank(input.system["time-zone"])

# 5.1.3  Console timeout configured (security console)
console_timeout if _int(input.system.console.device.ttyS0["timeout-login"]) <= 300

# 5.1.4  System domain name configured
domain_configured if _nonblank(input.system["domain-name"])

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
			[v | some v in section_2_violations],
		),
		array.concat(
			[v | some v in section_3_violations],
			[v | some v in section_4_violations],
		),
	),
	[v | some v in section_5_violations],
)

compliant if {
	count(violations) == 0
}

# ── Compliance report ─────────────────────────────────────────────────────────

total_controls := 23

_overall_compliance := "PASS" if compliant
_overall_compliance := "FAIL" if not compliant

compliance_assessment := {
	"compliant": count(violations) == 0,
	"summary": {
		"total_controls": total_controls,
		"passing_controls": total_controls - count(violations),
		"failing_controls": count(violations),
		"compliance_percentage": ((total_controls - count(violations)) * 100) / total_controls,
		"overall_compliance": _overall_compliance,
	},
	"violations": violations,
	"section_compliance": {
		"1_ssh_access": count(section_1_violations) == 0,
		"2_mgmt_services": count(section_2_violations) == 0,
		"3_firewall": count(section_3_violations) == 0,
		"4_user_accounts": count(section_4_violations) == 0,
		"5_system_hardening": count(section_5_violations) == 0,
	},
	"device_info": {
		# object.get(input, "system", {}) guards against a missing input.system:
		# object.get(<undefined>, …) is itself undefined and would collapse the whole
		# compliance_assessment object to null (OPA returns {}), masking a failed/empty
		# fact collection as a silent result. Defaulting to {} keeps the report defined
		# so an empty input scores low (loud) instead of returning null.
		"hostname": object.get(object.get(input, "system", {}), "host-name", "unknown"),
		"version": object.get(input, "version", "unknown"),
		"platform": "vyos",
		"timezone": object.get(object.get(input, "system", {}), "time-zone", "unknown"),
	},
}
