# METADATA
# title: "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Section 5.2: Configure SSH Server"
# custom:
#   class: security
#   framework: cis_debian_11
#   source: cis
#   domains: [linux, debian]
#   coverage:
#     checks: 35
#     cited: 23
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_debian_11.ssh

# DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Section 5.2: Configure SSH Server

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

has_key(obj, k) if {
	_ = obj[k]
}

# --- sshd_config parsing: non-comment lines, global section only (before the first Match),
# --- keywords case-insensitive, first occurrence wins (sshd semantics).

raw_config := object.get(object.get(input, "ssh", {}), "sshd_config_raw", "")

cfg_lines := [t |
	some l in split(raw_config, "\n")
	t := trim_space(l)
	t != ""
	not startswith(t, "#")
]

match_positions := [i |
	some i, l in cfg_lines
	regex.match(`(?i)^match\s`, l)
]

global_end := min(array.concat(match_positions, [count(cfg_lines)]))

global_lines := array.slice(cfg_lines, 0, global_end)

# value of a directive (lower-cased, quotes stripped); undefined when not set
directive(key) := v if {
	vals := [m[1] |
		some l in global_lines
		m := regex.find_all_string_submatch_n(sprintf(`(?i)^%s(?:\s+|\s*=\s*)(\S.*)$`, [key]), l, 1)[0]
	]
	count(vals) > 0
	v := lower(trim(trim_space(vals[0]), "\""))
}

dir_in(key, allowed) if directive(key) in allowed

# sshd time value ("90", "2m", "1m30s") to seconds; undefined if malformed
seconds(v) := total if {
	regex.match(`^([0-9]+[smhdw]?)+$`, v)
	parts := regex.find_all_string_submatch_n(`([0-9]+)([smhdw]?)`, v, -1)
	total := sum([n |
		some p in parts
		n := to_number(p[1]) * unit_secs[p[2]]
	])
}

unit_secs := {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

# list tokens of an algorithm directive that are actually enabled (removals with "-" are skipped)
enabled_tokens(key) := [t |
	some raw_t in split(directive(key), ",")
	t0 := trim_space(raw_t)
	not startswith(t0, "-")
	t := trim_prefix(trim_prefix(t0, "+"), "^")
]

# CIS 5.2.1: Ensure permissions on /etc/ssh/sshd_config are configured
permission_violations contains msg if {
	some k in ["sshd_config_mode", "sshd_config_owner", "sshd_config_group"]
	not has_key(object.get(input, "ssh", {}), k)
	msg := sprintf("CIS 5.2.1: evidence missing — ssh.%s not collected", [k])
}

permission_violations contains msg if {
	not mode_within(input.ssh.sshd_config_mode, "0600")
	msg := sprintf("CIS 5.2.1: /etc/ssh/sshd_config has mode %s, should be 0600", [input.ssh.sshd_config_mode])
}

permission_violations contains msg if {
	input.ssh.sshd_config_owner != "root"
	msg := sprintf("CIS 5.2.1: /etc/ssh/sshd_config owned by %s, should be root", [input.ssh.sshd_config_owner])
}

permission_violations contains msg if {
	input.ssh.sshd_config_group != "root"
	msg := sprintf("CIS 5.2.1: /etc/ssh/sshd_config group is %s, should be root", [input.ssh.sshd_config_group])
}

# CIS 5.2.2: Ensure permissions on SSH private host key files
permission_violations contains msg if {
	not input.ssh.private_key_files
	msg := "CIS 5.2.2: evidence missing — ssh.private_key_files not collected"
}

permission_violations contains msg if {
	some key in input.ssh.private_key_files
	not mode_within(key.mode, "0600")
	msg := sprintf("CIS 5.2.2: SSH private host key %s has mode %s, should be 0600", [key.path, key.mode])
}

# CIS 5.2.3: Ensure permissions on SSH public host key files
permission_violations contains msg if {
	not input.ssh.public_key_files
	msg := "CIS 5.2.3: evidence missing — ssh.public_key_files not collected"
}

permission_violations contains msg if {
	some key in input.ssh.public_key_files
	not mode_within(key.mode, "0644")
	msg := sprintf("CIS 5.2.3: SSH public host key %s has mode %s, should be 0644", [key.path, key.mode])
}

# Missing evidence fails closed
config_violations contains msg if {
	not input.ssh.sshd_config_raw
	msg := "CIS 5.2.x: evidence missing — ssh.sshd_config_raw not collected"
}

# CIS 5.2.4: Ensure SSH access is limited
config_violations contains msg if {
	every k in ["AllowUsers", "AllowGroups", "DenyUsers", "DenyGroups"] {
		not directive(k)
	}
	msg := "CIS 5.2.4: SSH access is not limited via AllowUsers/AllowGroups/DenyUsers/DenyGroups"
}

# CIS 5.2.5: Ensure SSH LogLevel is appropriate
config_violations contains msg if {
	not dir_in("LogLevel", {"verbose", "info"})
	msg := "CIS 5.2.5: SSH LogLevel is not set to VERBOSE or INFO"
}

# CIS 5.2.6: Ensure SSH PAM is enabled
config_violations contains msg if {
	directive("UsePAM") == "no"
	msg := "CIS 5.2.6: SSH UsePAM is disabled"
}

# CIS 5.2.7: Ensure SSH root login is disabled
config_violations contains msg if {
	not dir_in("PermitRootLogin", {"no", "prohibit-password", "without-password", "forced-commands-only"})
	msg := "CIS 5.2.7: SSH root login is not disabled"
}

# CIS 5.2.8: Ensure SSH HostbasedAuthentication is disabled
config_violations contains msg if {
	directive("HostbasedAuthentication") == "yes"
	msg := "CIS 5.2.8: SSH HostbasedAuthentication is enabled"
}

# CIS 5.2.9: Ensure SSH PermitEmptyPasswords is disabled
config_violations contains msg if {
	directive("PermitEmptyPasswords") == "yes"
	msg := "CIS 5.2.9: SSH PermitEmptyPasswords is enabled"
}

# CIS 5.2.10: Ensure SSH PermitUserEnvironment is disabled
config_violations contains msg if {
	directive("PermitUserEnvironment") == "yes"
	msg := "CIS 5.2.10: SSH PermitUserEnvironment is enabled"
}

# CIS 5.2.11: Ensure SSH IgnoreRhosts is enabled
config_violations contains msg if {
	directive("IgnoreRhosts") == "no"
	msg := "CIS 5.2.11: SSH IgnoreRhosts is disabled"
}

# CIS 5.2.12: Ensure SSH X11Forwarding is disabled
config_violations contains msg if {
	directive("X11Forwarding") == "yes"
	msg := "CIS 5.2.12: SSH X11Forwarding is enabled"
}

# CIS 5.2.13: Ensure SSH AllowTcpForwarding is disabled
config_violations contains msg if {
	directive("AllowTcpForwarding") in {"yes", "all"}
	msg := "CIS 5.2.13: SSH AllowTcpForwarding is enabled"
}

# CIS 5.2.14: Ensure SSH warning banner is configured
config_violations contains msg if {
	not directive("Banner")
	msg := "CIS 5.2.14: SSH warning banner (Banner) is not configured"
}

config_violations contains msg if {
	directive("Banner") == "none"
	msg := "CIS 5.2.14: SSH banner is set to none"
}

# CIS 5.2.15: Ensure SSH MaxAuthTries is set to 4 or less (sshd default is 6, so unset fails)
config_violations contains msg if {
	v := directive("MaxAuthTries")
	not regex.match(`^[0-9]+$`, v)
	msg := sprintf("CIS 5.2.15: SSH MaxAuthTries %s is not a number", [v])
}

config_violations contains msg if {
	v := directive("MaxAuthTries")
	regex.match(`^[0-9]+$`, v)
	to_number(v) > 4
	msg := sprintf("CIS 5.2.15: SSH MaxAuthTries is %s, should be 4 or less", [v])
}

config_violations contains msg if {
	not directive("MaxAuthTries")
	msg := "CIS 5.2.15: SSH MaxAuthTries is not set (sshd default is 6, should be 4 or less)"
}

# CIS 5.2.16: Ensure SSH MaxStartups is configured
config_violations contains msg if {
	not directive("MaxStartups")
	msg := "CIS 5.2.16: SSH MaxStartups is not configured"
}

# CIS 5.2.17: Ensure SSH MaxSessions is set to 10 or less (sshd default is 10)
config_violations contains msg if {
	v := directive("MaxSessions")
	not regex.match(`^[0-9]+$`, v)
	msg := sprintf("CIS 5.2.17: SSH MaxSessions %s is not a number", [v])
}

config_violations contains msg if {
	v := directive("MaxSessions")
	regex.match(`^[0-9]+$`, v)
	to_number(v) > 10
	msg := sprintf("CIS 5.2.17: SSH MaxSessions is %s, should be 10 or less", [v])
}

# CIS 5.2.18: Ensure SSH LoginGraceTime is set to one minute or less (sshd default is 120s, so unset fails)
config_violations contains msg if {
	v := directive("LoginGraceTime")
	not seconds(v)
	msg := sprintf("CIS 5.2.18: SSH LoginGraceTime %s is not a valid time value", [v])
}

config_violations contains msg if {
	v := directive("LoginGraceTime")
	seconds(v) > 60
	msg := sprintf("CIS 5.2.18: SSH LoginGraceTime is %s (%d seconds), should be 60 or less", [v, seconds(v)])
}

config_violations contains msg if {
	not directive("LoginGraceTime")
	msg := "CIS 5.2.18: SSH LoginGraceTime is not set (sshd default is 120 seconds, should be 60 or less)"
}

# CIS 5.2.19: Ensure SSH Idle Timeout Interval is configured
config_violations contains msg if {
	not directive("ClientAliveInterval")
	msg := "CIS 5.2.19: SSH ClientAliveInterval is not configured"
}

config_violations contains msg if {
	not directive("ClientAliveCountMax")
	msg := "CIS 5.2.19: SSH ClientAliveCountMax is not configured"
}

# CIS 5.2.20: Ensure SSH Ciphers are configured
weak_ciphers := ["arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]

crypto_violations contains msg if {
	some t in enabled_tokens("Ciphers")
	some weak_cipher in weak_ciphers
	lower(t) == weak_cipher
	msg := sprintf("CIS 5.2.20: SSH configuration contains weak cipher: %s", [weak_cipher])
}

# CIS 5.2.21: Ensure only strong MAC algorithms are used
weak_macs := [
	"hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com",
	"hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-ripemd160-etm@openssh.com",
	"hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com",
]

crypto_violations contains msg if {
	some t in enabled_tokens("MACs")
	some weak_mac in weak_macs
	lower(t) == weak_mac
	msg := sprintf("CIS 5.2.21: SSH configuration contains weak MAC algorithm: %s", [weak_mac])
}

# CIS 5.2.22: Ensure only strong Key Exchange algorithms are used
weak_kex := ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]

crypto_violations contains msg if {
	some t in enabled_tokens("KexAlgorithms")
	some weak_kex_algo in weak_kex
	lower(t) == weak_kex_algo
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
	"benchmark": "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 (applied to Debian 11)",
}
