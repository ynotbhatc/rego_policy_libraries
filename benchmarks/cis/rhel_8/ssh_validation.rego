package cis_rhel8.ssh

# CIS RHEL 8 Benchmark v3.0.0 - Section 5.2: SSH Server Configuration
# Validates SSH daemon configuration for security hardening

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in permission_violations], [v | some v in config_violations]),
	[v | some v in crypto_violations],
)

# Parse sshd_config into key-value map
sshd_config := {lower(key): value |
	some line in split(input.ssh.sshd_config_raw, "\n")
	trimmed := trim_space(line)
	not startswith(trimmed, "#")
	trimmed != ""
	parts := regex.split(`\s+`, trimmed)
	count(parts) >= 2
	key := parts[0]
	value := parts[1]
}

# CIS 5.2.1 - SSH config file permissions
permission_violations contains "CIS 5.2.1: /etc/ssh/sshd_config permissions not 0600" if {
	input.ssh.config_permissions.mode != "0600"
}

permission_violations contains "CIS 5.2.1: /etc/ssh/sshd_config not owned by root" if {
	input.ssh.config_permissions.pw_name != "root"
}

permission_violations contains "CIS 5.2.1: /etc/ssh/sshd_config group not root" if {
	input.ssh.config_permissions.gr_name != "root"
}

# CIS 5.2.2 - SSH private key permissions
permission_violations contains sprintf("CIS 5.2.2: SSH private key %s has incorrect permissions (mode: %s)", [key.stat.path, key.stat.mode]) if {
	some key in input.ssh.private_key_permissions
	key.stat.mode != "0600"
}

permission_violations contains sprintf("CIS 5.2.2: SSH private key %s not owned by root (owner: %s)", [key.stat.path, key.stat.pw_name]) if {
	some key in input.ssh.private_key_permissions
	key.stat.pw_name != "root"
}

# CIS 5.2.3 - SSH public key permissions
permission_violations contains sprintf("CIS 5.2.3: SSH public key %s permissions too permissive (mode: %s)", [key.path, key.mode]) if {
	some key in input.ssh.public_key_permissions
	to_number(key.mode) > 644
}

# CIS 5.2.4 - LogLevel
config_violations contains "CIS 5.2.4: SSH LogLevel not set to INFO or VERBOSE" if {
	loglevel := sshd_config["loglevel"]
	not loglevel in ["INFO", "VERBOSE"]
}

config_violations contains "CIS 5.2.4: SSH LogLevel not configured" if {
	not sshd_config["loglevel"]
}

# CIS 5.2.5 - X11 Forwarding
config_violations contains "CIS 5.2.5: SSH X11Forwarding is enabled (should be 'no')" if {
	sshd_config["x11forwarding"] == "yes"
}

# CIS 5.2.6 - MaxAuthTries
config_violations contains sprintf("CIS 5.2.6: SSH MaxAuthTries is %v (should be 4 or less)", [tries]) if {
	tries := to_number(sshd_config["maxauthtries"])
	tries > 4
}

config_violations contains "CIS 5.2.6: SSH MaxAuthTries not configured" if {
	not sshd_config["maxauthtries"]
}

# CIS 5.2.7 - IgnoreRhosts
config_violations contains "CIS 5.2.7: SSH IgnoreRhosts not enabled" if {
	sshd_config["ignorerhosts"] != "yes"
}

config_violations contains "CIS 5.2.7: SSH IgnoreRhosts not configured" if {
	not sshd_config["ignorerhosts"]
}

# CIS 5.2.8 - HostbasedAuthentication
config_violations contains "CIS 5.2.8: SSH HostbasedAuthentication is enabled (should be 'no')" if {
	sshd_config["hostbasedauthentication"] == "yes"
}

# CIS 5.2.9 - PermitRootLogin
config_violations contains sprintf("CIS 5.2.9: SSH PermitRootLogin is '%v' (should be 'no')", [permit]) if {
	permit := sshd_config["permitrootlogin"]
	permit != "no"
}

config_violations contains "CIS 5.2.9: SSH PermitRootLogin not configured" if {
	not sshd_config["permitrootlogin"]
}

# CIS 5.2.10 - PermitEmptyPasswords
config_violations contains "CIS 5.2.10: SSH PermitEmptyPasswords is enabled (should be 'no')" if {
	sshd_config["permitemptypasswords"] == "yes"
}

# CIS 5.2.11 - PermitUserEnvironment
config_violations contains "CIS 5.2.11: SSH PermitUserEnvironment is enabled (should be 'no')" if {
	sshd_config["permituserenvironment"] == "yes"
}

# CIS 5.2.12 - Ciphers
weak_ciphers := {
	"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
	"arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
	"cast128-cbc", "rijndael-cbc@lysator.liu.se",
}

crypto_violations contains sprintf("CIS 5.2.12: Weak SSH cipher '%s' is allowed", [cipher]) if {
	ciphers_str := sshd_config["ciphers"]
	some cipher in split(ciphers_str, ",")
	cipher in weak_ciphers
}

# CIS 5.2.13 - MAC algorithms
weak_macs := {
	"hmac-md5", "hmac-md5-96", "hmac-ripemd160",
	"hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com",
	"hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
	"hmac-ripemd160-etm@openssh.com", "hmac-sha1-etm@openssh.com",
	"hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com",
}

crypto_violations contains sprintf("CIS 5.2.13: Weak SSH MAC '%s' is allowed", [mac]) if {
	macs_str := sshd_config["macs"]
	some mac in split(macs_str, ",")
	mac in weak_macs
}

# CIS 5.2.14 - Key exchange algorithms
weak_kex := {
	"diffie-hellman-group1-sha1",
	"diffie-hellman-group14-sha1",
	"diffie-hellman-group-exchange-sha1",
}

crypto_violations contains sprintf("CIS 5.2.14: Weak SSH KexAlgorithm '%s' is allowed", [kex]) if {
	kex_str := sshd_config["kexalgorithms"]
	some kex in split(kex_str, ",")
	kex in weak_kex
}

# CIS 5.2.15 - Idle timeout
config_violations contains sprintf("CIS 5.2.15: SSH ClientAliveInterval is %v seconds (should be 300 or less)", [interval]) if {
	interval := to_number(sshd_config["clientaliveinterval"])
	interval > 300
}

config_violations contains "CIS 5.2.15: SSH ClientAliveInterval not configured" if {
	not sshd_config["clientaliveinterval"]
}

config_violations contains sprintf("CIS 5.2.15: SSH ClientAliveCountMax is %v (should be 3 or less)", [n]) if {
	n := to_number(sshd_config["clientalivecountmax"])
	n > 3
}

# CIS 5.2.16 - LoginGraceTime
config_violations contains sprintf("CIS 5.2.16: SSH LoginGraceTime is %v seconds (should be 60 or less)", [grace]) if {
	grace := to_number(sshd_config["logingracetime"])
	grace > 60
}

# CIS 5.2.17 - Banner
config_violations contains "CIS 5.2.17: SSH Banner not configured" if {
	not sshd_config["banner"]
}

config_violations contains "CIS 5.2.17: SSH Banner set to 'none'" if {
	sshd_config["banner"] == "none"
}

# CIS 5.2.18 - UsePAM
config_violations contains "CIS 5.2.18: SSH UsePAM not enabled" if {
	sshd_config["usepam"] != "yes"
}

config_violations contains "CIS 5.2.18: SSH UsePAM not configured" if {
	not sshd_config["usepam"]
}

# CIS 5.2.19 - AllowTcpForwarding
config_violations contains "CIS 5.2.19: SSH AllowTcpForwarding is enabled (should be 'no')" if {
	sshd_config["allowtcpforwarding"] == "yes"
}

# CIS 5.2.20 - MaxStartups
config_violations contains "CIS 5.2.20: SSH MaxStartups not configured" if {
	not sshd_config["maxstartups"]
}

# CIS 5.2.21 - MaxSessions
config_violations contains sprintf("CIS 5.2.21: SSH MaxSessions is %v (should be 10 or less)", [sessions]) if {
	sessions := to_number(sshd_config["maxsessions"])
	sessions > 10
}

report := {
	"compliant": compliant,
	"violations": violations,
	"total_violations": count(violations),
	"permission_violations": count(permission_violations),
	"config_violations": count(config_violations),
	"crypto_violations": count(crypto_violations),
	"controls_checked": 21,
	"section": "5.2 SSH Server Configuration",
	"benchmark": "CIS RHEL 8 v3.0.0",
}
