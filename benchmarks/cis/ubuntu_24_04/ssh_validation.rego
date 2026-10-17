# METADATA
# title: "DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 — applied to Ubuntu 24.04 LTS (see README) - Section 5.2: Configure SSH Server"
# custom:
#   class: security
#   framework: cis_ubuntu_24_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 26
#     cited: 22
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: orchestrator
#     as_of: v2.4.1
package cis_ubuntu_24_04.ssh

# DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 — applied to Ubuntu 24.04 LTS (see README) - Section 5.2: Configure SSH Server

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in config_violations], [v | some v in crypto_violations]),
	[v | some v in permission_violations],
)

# Active (non-comment, non-blank) sshd_config lines. Commented-out stock defaults
# such as "#PermitRootLogin prohibit-password" must never satisfy or trip a check.
sshd_lines := [t |
	some line in split(object.get(object.get(input, "ssh", {}), "sshd_config_raw", ""), "\n")
	t := trim_space(line)
	t != ""
	not startswith(t, "#")
]

# [{"i": position, "k": lower-cased directive, "v": value}] for `Key value` and `Key=value` lines
sshd_directives := [{"i": i, "k": lower(m[0][1]), "v": trim_space(m[0][2])} |
	some i in numbers.range(0, count(sshd_lines) - 1)
	m := regex.find_all_string_submatch_n(`^([A-Za-z0-9]+)(?:\s*=\s*|\s+)(.+)$`, sshd_lines[i], 1)
	count(m) == 1
]

config_collected if count(sshd_directives) > 0

# sshd uses the first occurrence of a directive
sshd_value(key) := v if {
	cands := [d | some d in sshd_directives; d.k == key]
	count(cands) > 0
	first := min([d.i | some d in cands])
	some d in cands
	d.i == first
	v := d.v
}

sshd_value_lc(key) := lower(sshd_value(key))

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(d) | some d in split(p, "")]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

# A numeric sshd value ("4", "60"); "2m"-style times are converted to seconds.
sshd_number(v) := to_number(v) if regex.match(`^\d+$`, v)

sshd_number(v) := to_number(trim_suffix(v, "m")) * 60 if regex.match(`^\d+m$`, v)

config_violations contains "CIS 5.2: evidence missing — ssh.sshd_config_raw not collected" if {
	not config_collected
}

# CIS 5.2.1: Ensure permissions on /etc/ssh/sshd_config are configured
permission_violations contains msg if {
	some key in ["sshd_config_mode", "sshd_config_owner", "sshd_config_group"]
	object.get(object.get(input, "ssh", {}), key, null) == null
	msg := sprintf("CIS 5.2.1: evidence missing — ssh.%s not collected", [key])
}

permission_violations contains msg if {
	input.ssh.sshd_config_mode
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
permission_violations contains "CIS 5.2.2: evidence missing — ssh.private_key_files not collected" if {
	object.get(object.get(input, "ssh", {}), "private_key_files", null) == null
}

permission_violations contains msg if {
	some key in input.ssh.private_key_files
	not mode_within(key.mode, "0600")
	msg := sprintf("CIS 5.2.2: SSH private host key %s has mode %s, should be 0600", [key.path, key.mode])
}

# CIS 5.2.3: Ensure permissions on SSH public host key files
permission_violations contains "CIS 5.2.3: evidence missing — ssh.public_key_files not collected" if {
	object.get(object.get(input, "ssh", {}), "public_key_files", null) == null
}

permission_violations contains msg if {
	some key in input.ssh.public_key_files
	not mode_within(key.mode, "0644")
	msg := sprintf("CIS 5.2.3: SSH public host key %s has mode %s, should be 0644", [key.path, key.mode])
}

# CIS 5.2.4: Ensure SSH access is limited
config_violations contains msg if {
	config_collected
	not sshd_value("allowusers")
	not sshd_value("allowgroups")
	not sshd_value("denyusers")
	not sshd_value("denygroups")
	msg := "CIS 5.2.4: SSH access is not limited via AllowUsers/AllowGroups/DenyUsers/DenyGroups"
}

# CIS 5.2.5: Ensure SSH LogLevel is appropriate
loglevel_ok if sshd_value_lc("loglevel") in {"verbose", "info"}

root_login_ok if sshd_value_lc("permitrootlogin") in {"no", "prohibit-password", "forced-commands-only"}

config_violations contains msg if {
	config_collected
	not loglevel_ok
	msg := "CIS 5.2.5: SSH LogLevel is not set to VERBOSE or INFO"
}

# CIS 5.2.6: Ensure SSH PAM is enabled
config_violations contains msg if {
	sshd_value_lc("usepam") == "no"
	msg := "CIS 5.2.6: SSH UsePAM is disabled"
}

# CIS 5.2.7: Ensure SSH root login is disabled
config_violations contains msg if {
	config_collected
	not root_login_ok
	msg := "CIS 5.2.7: SSH root login is not disabled"
}

# CIS 5.2.8: Ensure SSH HostbasedAuthentication is disabled
config_violations contains msg if {
	sshd_value_lc("hostbasedauthentication") == "yes"
	msg := "CIS 5.2.8: SSH HostbasedAuthentication is enabled"
}

# CIS 5.2.9: Ensure SSH PermitEmptyPasswords is disabled
config_violations contains msg if {
	sshd_value_lc("permitemptypasswords") == "yes"
	msg := "CIS 5.2.9: SSH PermitEmptyPasswords is enabled"
}

# CIS 5.2.10: Ensure SSH PermitUserEnvironment is disabled
config_violations contains msg if {
	sshd_value_lc("permituserenvironment") == "yes"
	msg := "CIS 5.2.10: SSH PermitUserEnvironment is enabled"
}

# CIS 5.2.11: Ensure SSH IgnoreRhosts is enabled
config_violations contains msg if {
	sshd_value_lc("ignorerhosts") == "no"
	msg := "CIS 5.2.11: SSH IgnoreRhosts is disabled"
}

# CIS 5.2.12: Ensure SSH X11Forwarding is disabled
config_violations contains msg if {
	sshd_value_lc("x11forwarding") == "yes"
	msg := "CIS 5.2.12: SSH X11Forwarding is enabled"
}

# CIS 5.2.13: Ensure SSH AllowTcpForwarding is disabled
config_violations contains msg if {
	sshd_value_lc("allowtcpforwarding") == "yes"
	msg := "CIS 5.2.13: SSH AllowTcpForwarding is enabled"
}

# CIS 5.2.14: Ensure SSH warning banner is configured
config_violations contains msg if {
	config_collected
	not sshd_value("banner")
	msg := "CIS 5.2.14: SSH warning banner (Banner) is not configured"
}

config_violations contains msg if {
	sshd_value_lc("banner") == "none"
	msg := "CIS 5.2.14: SSH banner is set to none"
}

# CIS 5.2.15: Ensure SSH MaxAuthTries is set to 4 or less
config_violations contains msg if {
	v := sshd_value("maxauthtries")
	sshd_number(v) > 4
	msg := sprintf("CIS 5.2.15: SSH MaxAuthTries is %s, should be 4 or less", [v])
}

# CIS 5.2.16: Ensure SSH MaxStartups is configured
config_violations contains msg if {
	config_collected
	not sshd_value("maxstartups")
	msg := "CIS 5.2.16: SSH MaxStartups is not configured"
}

# CIS 5.2.17: Ensure SSH MaxSessions is set to 10 or less
config_violations contains msg if {
	v := sshd_value("maxsessions")
	sshd_number(v) > 10
	msg := sprintf("CIS 5.2.17: SSH MaxSessions is %s, should be 10 or less", [v])
}

# CIS 5.2.18: Ensure SSH LoginGraceTime is set to one minute or less
config_violations contains msg if {
	v := sshd_value("logingracetime")
	sshd_number(v) > 60
	msg := sprintf("CIS 5.2.18: SSH LoginGraceTime is %s seconds, should be 60 or less", [v])
}

# CIS 5.2.19: Ensure SSH Idle Timeout Interval is configured
config_violations contains msg if {
	config_collected
	not sshd_value("clientaliveinterval")
	msg := "CIS 5.2.19: SSH ClientAliveInterval is not configured"
}

config_violations contains msg if {
	config_collected
	not sshd_value("clientalivecountmax")
	msg := "CIS 5.2.19: SSH ClientAliveCountMax is not configured"
}

# CIS 5.2.20: Ensure SSH Ciphers are configured
weak_ciphers := ["arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]

crypto_violations contains msg if {
	some line in split(input.ssh.sshd_config_raw, "\n")
	startswith(trim_space(line), "Ciphers")
	some weak_cipher in weak_ciphers
	contains(line, weak_cipher)
	msg := sprintf("CIS 5.2.20: SSH configuration contains weak cipher: %s", [weak_cipher])
}

# CIS 5.2.21: Ensure only strong MAC algorithms are used
weak_macs := ["hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com"]

crypto_violations contains msg if {
	some line in split(input.ssh.sshd_config_raw, "\n")
	startswith(trim_space(line), "MACs")
	some weak_mac in weak_macs
	contains(line, weak_mac)
	msg := sprintf("CIS 5.2.21: SSH configuration contains weak MAC algorithm: %s", [weak_mac])
}

# CIS 5.2.22: Ensure only strong Key Exchange algorithms are used
weak_kex := ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]

crypto_violations contains msg if {
	some line in split(input.ssh.sshd_config_raw, "\n")
	startswith(trim_space(line), "KexAlgorithms")
	some weak_kex_algo in weak_kex
	contains(line, weak_kex_algo)
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
	"benchmark": "DERIVED from CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 (applied to Ubuntu 24.04 LTS)",
}
