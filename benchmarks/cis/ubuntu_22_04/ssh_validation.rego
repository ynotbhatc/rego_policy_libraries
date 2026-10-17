# METADATA
# title: "CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Section 5.2: Configure SSH Server"
# custom:
#   class: security
#   framework: cis_ubuntu_22_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 31
#     cited: 23
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_ubuntu_22_04.ssh

# CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Section 5.2: Configure SSH Server

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in config_violations], [v | some v in crypto_violations]),
	[v | some v in permission_violations],
)

# ---------------------------------------------------------------------------
# sshd_config parsing. The input is `sshd -T` output (lowercase keywords) or the raw
# sshd_config file (any case). Keywords are case-insensitive, the separator is
# whitespace or "=", comment lines are ignored, and sshd uses the FIRST occurrence of a
# keyword. Values are compared as whole tokens, never as substrings of the file.
# ---------------------------------------------------------------------------

ssh_directives := [{"key": lower(m[1]), "val": trim_space(m[2])} |
	some line in split(input.ssh.sshd_config_raw, "\n")
	l := trim_space(line)
	l != ""
	not startswith(l, "#")
	m := regex.find_all_string_submatch_n(`^([A-Za-z0-9]+)(?:\s*=\s*|\s+)(.*)$`, l, 1)[0]
]

# First value of a keyword; undefined if the keyword is not set
ssh_value(key) := vals[0] if {
	vals := [d.val | some d in ssh_directives; d.key == key]
	count(vals) > 0
}

ssh_is(key, wanted) if lower(ssh_value(key)) in wanted

ssh_set(key) if ssh_value(key)

# first value parsed as a number of seconds ("60", "1m", "2m", "1h"); undefined if not parseable
ssh_seconds(key) := n if {
	m := regex.find_all_string_submatch_n(`^([0-9]+)([smhdw]?)$`, lower(ssh_value(key)), 1)[0]
	mult := {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m[2]]
	n := to_number(m[1]) * mult
}

ssh_number(key) := to_number(ssh_value(key))

# Evidence: no sshd configuration collected, nothing can be asserted
config_violations contains msg if {
	not ssh_collected
	msg := "CIS 5.2.x: evidence missing — ssh.sshd_config_raw not collected"
}

ssh_collected if count(ssh_directives) > 0

# Modes are octal; an absent or unparsable mode fails
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

# CIS 5.2.1: Ensure permissions on /etc/ssh/sshd_config are configured
sshd_config_mode_ok if mode_within(input.ssh.sshd_config_mode, "0600")

permission_violations contains msg if {
	not sshd_config_mode_ok
	msg := sprintf("CIS 5.2.1: /etc/ssh/sshd_config has mode %v, should be 0600 (or mode not collected)", [object.get(input, ["ssh", "sshd_config_mode"], "<missing>")])
}

permission_violations contains msg if {
	not input.ssh.sshd_config_owner == "root"
	msg := sprintf("CIS 5.2.1: /etc/ssh/sshd_config owned by %v, should be root (or owner not collected)", [object.get(input, ["ssh", "sshd_config_owner"], "<missing>")])
}

permission_violations contains msg if {
	not input.ssh.sshd_config_group == "root"
	msg := sprintf("CIS 5.2.1: /etc/ssh/sshd_config group is %v, should be root (or group not collected)", [object.get(input, ["ssh", "sshd_config_group"], "<missing>")])
}

key_mode_ok(key, max) if mode_within(key.mode, max)

# CIS 5.2.2: Ensure permissions on SSH private host key files
private_keys_collected if is_array(input.ssh.private_key_files)

permission_violations contains msg if {
	not private_keys_collected
	msg := "CIS 5.2.2: evidence missing — ssh.private_key_files not collected"
}

permission_violations contains msg if {
	some key in input.ssh.private_key_files
	not key_mode_ok(key, "0600")
	msg := sprintf("CIS 5.2.2: SSH private host key %v has mode %v, should be 0600", [key.path, object.get(key, "mode", "<missing>")])
}

# CIS 5.2.3: Ensure permissions on SSH public host key files
public_keys_collected if is_array(input.ssh.public_key_files)

permission_violations contains msg if {
	not public_keys_collected
	msg := "CIS 5.2.3: evidence missing — ssh.public_key_files not collected"
}

permission_violations contains msg if {
	some key in input.ssh.public_key_files
	not key_mode_ok(key, "0644")
	msg := sprintf("CIS 5.2.3: SSH public host key %v has mode %v, should be 0644", [key.path, object.get(key, "mode", "<missing>")])
}

# CIS 5.2.4: Ensure SSH access is limited
access_limited if {
	some key in ["allowusers", "allowgroups", "denyusers", "denygroups"]
	ssh_set(key)
}

config_violations contains msg if {
	not access_limited
	msg := "CIS 5.2.4: SSH access is not limited via AllowUsers/AllowGroups/DenyUsers/DenyGroups"
}

# CIS 5.2.5: Ensure SSH LogLevel is appropriate
config_violations contains msg if {
	not ssh_is("loglevel", {"verbose", "info"})
	msg := "CIS 5.2.5: SSH LogLevel is not set to VERBOSE or INFO"
}

# CIS 5.2.6: Ensure SSH PAM is enabled
config_violations contains msg if {
	ssh_is("usepam", {"no"})
	msg := "CIS 5.2.6: SSH UsePAM is disabled"
}

# CIS 5.2.7: Ensure SSH root login is disabled
config_violations contains msg if {
	not ssh_is("permitrootlogin", {"no", "prohibit-password", "without-password", "forced-commands-only"})
	msg := "CIS 5.2.7: SSH root login is not disabled"
}

# CIS 5.2.8: Ensure SSH HostbasedAuthentication is disabled
config_violations contains msg if {
	ssh_is("hostbasedauthentication", {"yes"})
	msg := "CIS 5.2.8: SSH HostbasedAuthentication is enabled"
}

# CIS 5.2.9: Ensure SSH PermitEmptyPasswords is disabled
config_violations contains msg if {
	ssh_is("permitemptypasswords", {"yes"})
	msg := "CIS 5.2.9: SSH PermitEmptyPasswords is enabled"
}

# CIS 5.2.10: Ensure SSH PermitUserEnvironment is disabled
config_violations contains msg if {
	ssh_is("permituserenvironment", {"yes"})
	msg := "CIS 5.2.10: SSH PermitUserEnvironment is enabled"
}

# CIS 5.2.11: Ensure SSH IgnoreRhosts is enabled
config_violations contains msg if {
	ssh_is("ignorerhosts", {"no"})
	msg := "CIS 5.2.11: SSH IgnoreRhosts is disabled"
}

# CIS 5.2.12: Ensure SSH X11Forwarding is disabled
config_violations contains msg if {
	ssh_is("x11forwarding", {"yes"})
	msg := "CIS 5.2.12: SSH X11Forwarding is enabled"
}

# CIS 5.2.13: Ensure SSH AllowTcpForwarding is disabled
config_violations contains msg if {
	ssh_is("allowtcpforwarding", {"yes"})
	msg := "CIS 5.2.13: SSH AllowTcpForwarding is enabled"
}

# CIS 5.2.14: Ensure SSH warning banner is configured
config_violations contains msg if {
	not ssh_set("banner")
	msg := "CIS 5.2.14: SSH warning banner (Banner) is not configured"
}

config_violations contains msg if {
	ssh_is("banner", {"none"})
	msg := "CIS 5.2.14: SSH banner is set to none"
}

# CIS 5.2.15: Ensure SSH MaxAuthTries is set to 4 or less.
# Not set means the sshd default (6), which exceeds the limit.
max_auth_tries_ok if ssh_number("maxauthtries") <= 4

config_violations contains msg if {
	ssh_set("maxauthtries")
	not max_auth_tries_ok
	msg := sprintf("CIS 5.2.15: SSH MaxAuthTries is %s, should be 4 or less", [ssh_value("maxauthtries")])
}

config_violations contains msg if {
	not ssh_set("maxauthtries")
	msg := "CIS 5.2.15: SSH MaxAuthTries is not configured (sshd default is 6, should be 4 or less)"
}

# CIS 5.2.16: Ensure SSH MaxStartups is configured
config_violations contains msg if {
	not ssh_set("maxstartups")
	msg := "CIS 5.2.16: SSH MaxStartups is not configured"
}

# CIS 5.2.17: Ensure SSH MaxSessions is set to 10 or less (not set = sshd default of 10)
max_sessions_ok if ssh_number("maxsessions") <= 10

config_violations contains msg if {
	ssh_set("maxsessions")
	not max_sessions_ok
	msg := sprintf("CIS 5.2.17: SSH MaxSessions is %s, should be 10 or less", [ssh_value("maxsessions")])
}

# CIS 5.2.18: Ensure SSH LoginGraceTime is set to one minute or less.
# Not set means the sshd default (120 s), which exceeds the limit.
login_grace_ok if ssh_seconds("logingracetime") <= 60

config_violations contains msg if {
	ssh_set("logingracetime")
	not login_grace_ok
	msg := sprintf("CIS 5.2.18: SSH LoginGraceTime is %s seconds, should be 60 or less", [ssh_value("logingracetime")])
}

config_violations contains msg if {
	not ssh_set("logingracetime")
	msg := "CIS 5.2.18: SSH LoginGraceTime is not configured (sshd default is 120 seconds, should be 60 or less)"
}

# CIS 5.2.19: Ensure SSH Idle Timeout Interval is configured
config_violations contains msg if {
	not ssh_set("clientaliveinterval")
	msg := "CIS 5.2.19: SSH ClientAliveInterval is not configured"
}

config_violations contains msg if {
	not ssh_set("clientalivecountmax")
	msg := "CIS 5.2.19: SSH ClientAliveCountMax is not configured"
}

# Algorithm lists: comma-separated, compared as whole tokens. "+x" / "^x" add an algorithm,
# "-x" removes one (so "-3des-cbc" does not enable it).
ssh_algorithms(key) := {t |
	some raw in split(ssh_value(key), ",")
	t := trim_prefix(trim_prefix(lower(trim_space(raw)), "+"), "^")
	not startswith(trim_space(raw), "-")
}

# CIS 5.2.20: Ensure SSH Ciphers are configured
weak_ciphers := ["arcfour", "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]

crypto_violations contains msg if {
	some weak_cipher in weak_ciphers
	weak_cipher in ssh_algorithms("ciphers")
	msg := sprintf("CIS 5.2.20: SSH configuration contains weak cipher: %s", [weak_cipher])
}

# CIS 5.2.21: Ensure only strong MAC algorithms are used
weak_macs := [
	"hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com",
	"hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-ripemd160-etm@openssh.com",
	"hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com",
]

crypto_violations contains msg if {
	some weak_mac in weak_macs
	weak_mac in ssh_algorithms("macs")
	msg := sprintf("CIS 5.2.21: SSH configuration contains weak MAC algorithm: %s", [weak_mac])
}

# CIS 5.2.22: Ensure only strong Key Exchange algorithms are used
weak_kex := ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]

crypto_violations contains msg if {
	some weak_kex_algo in weak_kex
	weak_kex_algo in ssh_algorithms("kexalgorithms")
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
	"benchmark": "CIS Ubuntu 22.04 v3.0.0",
}
