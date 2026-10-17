# METADATA
# title: "CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 5.2: Configure SSH Server"
# custom:
#   class: security
#   framework: cis_ubuntu_20_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 33
#     cited: 23
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_ubuntu_20_04.ssh

# CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 5.2: Configure SSH Server

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in config_violations], [v | some v in crypto_violations]),
	[v | some v in permission_violations],
)

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# ---------------------------------------------------------------------------
# sshd_config parsing: only active (non-comment) lines before the first Match
# block count; keywords are case-insensitive; sshd uses the FIRST occurrence.
# ---------------------------------------------------------------------------
all_active_lines := [l |
	some line in split(input.ssh.sshd_config_raw, "\n")
	l := trim_space(line)
	l != ""
	not startswith(l, "#")
] if is_string(input.ssh.sshd_config_raw)

match_indexes := [i | some i, l in all_active_lines; regex.match(`(?i)^match\s`, l)]

global_end := min(array.concat(match_indexes, [count(all_active_lines)]))

global_lines := array.slice(all_active_lines, 0, global_end)

# all values given for a directive (global section), in file order
directive_values(name) := [trim_space(m[1]) |
	some l in global_lines
	m := regex.find_all_string_submatch_n(sprintf(`(?i)^%s(?:\s*=\s*|\s+)(\S.*)$`, [name]), l, 1)[0]
]

# effective (first) value, lower-cased
first_value(name) := lower(directive_values(name)[0])

# effective value, or a sentinel when the directive is absent (so `not … in {…}` sees a value)
effective_value(name) := first_value(name) if count(directive_values(name)) > 0 else := "<unset>"

# comma-separated algorithm list of the effective directive, '+' prefix stripped
alg_tokens(name) := {t |
	some tok in split(directive_values(name)[0], ",")
	t := lower(trim_prefix(trim_space(tok), "+"))
}

# durations such as "60", "90s", "1m" in seconds
seconds(v) := n if {
	m := regex.find_all_string_submatch_n(`^(\d+)([smhdw]?)$`, v, 1)[0]
	mult := {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m[2]]
	n := to_number(m[1]) * mult
}

# Missing evidence must not pass.
config_violations contains msg if {
	not input.ssh.sshd_config_raw
	msg := "CIS 5.2.x: evidence missing — ssh.sshd_config_raw not collected"
}

# CIS 5.2.1: Ensure permissions on /etc/ssh/sshd_config are configured
permission_violations contains msg if {
	not mode_within(input.ssh.sshd_config_mode, "0600")
	msg := sprintf("CIS 5.2.1: /etc/ssh/sshd_config has mode %s, should be 0600 or more restrictive", [input.ssh.sshd_config_mode])
}

permission_violations contains msg if {
	input.ssh.sshd_config_owner != "root"
	msg := sprintf("CIS 5.2.1: /etc/ssh/sshd_config owned by %s, should be root", [input.ssh.sshd_config_owner])
}

permission_violations contains msg if {
	input.ssh.sshd_config_group != "root"
	msg := sprintf("CIS 5.2.1: /etc/ssh/sshd_config group is %s, should be root", [input.ssh.sshd_config_group])
}

permission_violations contains msg if {
	some field in ["sshd_config_mode", "sshd_config_owner", "sshd_config_group"]
	not input.ssh[field]
	msg := sprintf("CIS 5.2.1: evidence missing — ssh.%s not collected", [field])
}

# CIS 5.2.2: Ensure permissions on SSH private host key files
permission_violations contains msg if {
	some key in input.ssh.private_key_files
	not mode_within(key.mode, "0600")
	msg := sprintf("CIS 5.2.2: SSH private host key %s has mode %s, should be 0600 or more restrictive", [key.path, key.mode])
}

permission_violations contains msg if {
	count(object.get(input, ["ssh", "private_key_files"], [])) == 0
	msg := "CIS 5.2.2: evidence missing — ssh.private_key_files not collected"
}

# CIS 5.2.3: Ensure permissions on SSH public host key files
permission_violations contains msg if {
	some key in input.ssh.public_key_files
	not mode_within(key.mode, "0644")
	msg := sprintf("CIS 5.2.3: SSH public host key %s has mode %s, should be 0644 or more restrictive", [key.path, key.mode])
}

permission_violations contains msg if {
	count(object.get(input, ["ssh", "public_key_files"], [])) == 0
	msg := "CIS 5.2.3: evidence missing — ssh.public_key_files not collected"
}

# CIS 5.2.4: Ensure SSH access is limited
config_violations contains msg if {
	is_array(all_active_lines)
	limiting := [n | some n in ["AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups"]; count(directive_values(n)) > 0]
	count(limiting) == 0
	msg := "CIS 5.2.4: SSH access is not limited via AllowUsers/AllowGroups/DenyUsers/DenyGroups"
}

# CIS 5.2.5: Ensure SSH LogLevel is appropriate
config_violations contains msg if {
	is_array(all_active_lines)
	not effective_value("LogLevel") in {"verbose", "info"}
	msg := "CIS 5.2.5: SSH LogLevel is not set to VERBOSE or INFO"
}

# CIS 5.2.7: Ensure SSH root login is disabled
config_violations contains msg if {
	is_array(all_active_lines)
	not effective_value("PermitRootLogin") in {"no", "prohibit-password", "without-password", "forced-commands-only"}
	msg := "CIS 5.2.7: SSH root login is not disabled"
}

# Directives that must not carry a given value (first occurrence wins).
forbidden_settings := [
	{"name": "UsePAM", "bad": "no", "msg": "CIS 5.2.6: SSH UsePAM is disabled"},
	{"name": "HostbasedAuthentication", "bad": "yes", "msg": "CIS 5.2.8: SSH HostbasedAuthentication is enabled"},
	{"name": "PermitEmptyPasswords", "bad": "yes", "msg": "CIS 5.2.9: SSH PermitEmptyPasswords is enabled"},
	{"name": "PermitUserEnvironment", "bad": "yes", "msg": "CIS 5.2.10: SSH PermitUserEnvironment is enabled"},
	{"name": "IgnoreRhosts", "bad": "no", "msg": "CIS 5.2.11: SSH IgnoreRhosts is disabled"},
	{"name": "X11Forwarding", "bad": "yes", "msg": "CIS 5.2.12: SSH X11Forwarding is enabled"},
	{"name": "AllowTcpForwarding", "bad": "yes", "msg": "CIS 5.2.13: SSH AllowTcpForwarding is enabled"},
	{"name": "Banner", "bad": "none", "msg": "CIS 5.2.14: SSH banner is set to none"},
]

config_violations contains setting.msg if {
	some setting in forbidden_settings
	first_value(setting.name) == setting.bad
}

# CIS 5.2.14: Ensure SSH warning banner is configured
config_violations contains msg if {
	is_array(all_active_lines)
	count(directive_values("Banner")) == 0
	msg := "CIS 5.2.14: SSH warning banner (Banner) is not configured"
}

# CIS 5.2.15: Ensure SSH MaxAuthTries is set to 4 or less
config_violations contains msg if {
	v := first_value("MaxAuthTries")
	not regex.match(`^\d+$`, v)
	msg := sprintf("CIS 5.2.15: SSH MaxAuthTries is %s, should be 4 or less", [v])
}

config_violations contains msg if {
	v := first_value("MaxAuthTries")
	regex.match(`^\d+$`, v)
	to_number(v) > 4
	msg := sprintf("CIS 5.2.15: SSH MaxAuthTries is %s, should be 4 or less", [v])
}

config_violations contains msg if {
	is_array(all_active_lines)
	count(directive_values("MaxAuthTries")) == 0
	msg := "CIS 5.2.15: SSH MaxAuthTries is not configured (sshd default is 6), should be 4 or less"
}

# CIS 5.2.16: Ensure SSH MaxStartups is configured
config_violations contains msg if {
	is_array(all_active_lines)
	count(directive_values("MaxStartups")) == 0
	msg := "CIS 5.2.16: SSH MaxStartups is not configured"
}

# CIS 5.2.17: Ensure SSH MaxSessions is set to 10 or less (sshd default is 10)
config_violations contains msg if {
	v := first_value("MaxSessions")
	not regex.match(`^\d+$`, v)
	msg := sprintf("CIS 5.2.17: SSH MaxSessions is %s, should be 10 or less", [v])
}

config_violations contains msg if {
	v := first_value("MaxSessions")
	regex.match(`^\d+$`, v)
	to_number(v) > 10
	msg := sprintf("CIS 5.2.17: SSH MaxSessions is %s, should be 10 or less", [v])
}

# CIS 5.2.18: Ensure SSH LoginGraceTime is set to one minute or less (sshd default is 120s)
config_violations contains msg if {
	v := first_value("LoginGraceTime")
	not seconds(v)
	msg := sprintf("CIS 5.2.18: SSH LoginGraceTime is %s seconds, should be 60 or less", [v])
}

config_violations contains msg if {
	v := first_value("LoginGraceTime")
	seconds(v) > 60
	msg := sprintf("CIS 5.2.18: SSH LoginGraceTime is %s seconds, should be 60 or less", [v])
}

config_violations contains msg if {
	is_array(all_active_lines)
	count(directive_values("LoginGraceTime")) == 0
	msg := "CIS 5.2.18: SSH LoginGraceTime is not configured (sshd default is 120 seconds), should be 60 or less"
}

# CIS 5.2.19: Ensure SSH Idle Timeout Interval is configured
config_violations contains msg if {
	is_array(all_active_lines)
	count(directive_values("ClientAliveInterval")) == 0
	msg := "CIS 5.2.19: SSH ClientAliveInterval is not configured"
}

config_violations contains msg if {
	is_array(all_active_lines)
	count(directive_values("ClientAliveCountMax")) == 0
	msg := "CIS 5.2.19: SSH ClientAliveCountMax is not configured"
}

# CIS 5.2.20: Ensure SSH Ciphers are configured
weak_ciphers := ["arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]

crypto_violations contains msg if {
	some weak_cipher in weak_ciphers
	weak_cipher in alg_tokens("Ciphers")
	msg := sprintf("CIS 5.2.20: SSH configuration contains weak cipher: %s", [weak_cipher])
}

# CIS 5.2.21: Ensure only strong MAC algorithms are used
weak_macs := ["hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com"]

crypto_violations contains msg if {
	some weak_mac in weak_macs
	weak_mac in alg_tokens("MACs")
	msg := sprintf("CIS 5.2.21: SSH configuration contains weak MAC algorithm: %s", [weak_mac])
}

# CIS 5.2.22: Ensure only strong Key Exchange algorithms are used
weak_kex := ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]

crypto_violations contains msg if {
	some weak_kex_algo in weak_kex
	weak_kex_algo in alg_tokens("KexAlgorithms")
	msg := sprintf("CIS 5.2.22: SSH configuration contains weak key exchange algorithm: %s", [weak_kex_algo])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"config_violations": count(config_violations),
	"crypto_violations": count(crypto_violations),
	"permission_violations": count(permission_violations),
	"controls_checked": 22,
	"section": "5.2 Configure SSH Server",
	"benchmark": "CIS Ubuntu 20.04 v3.0.0",
}
