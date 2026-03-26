package cis_rhel9.ssh

# CIS RHEL 9 Section 5.2.x - SSH Server Configuration
# Validates SSH daemon configuration for security hardening

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

# Aggregate all violations
violations := array.concat(
	array.concat([v | some v in permission_violations], [v | some v in config_violations]),
	[v | some v in crypto_violations],
)

# =============================================================================
# HELPER: Parse sshd_config
# =============================================================================

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

# =============================================================================
# CIS 5.2.1 - SSH CONFIG FILE PERMISSIONS
# =============================================================================

permission_violations contains "CIS 5.2.1: /etc/ssh/sshd_config permissions not 0600" if {
	mode := input.ssh.config_permissions.mode
	mode != "0600"
}

permission_violations contains "CIS 5.2.1: /etc/ssh/sshd_config not owned by root" if {
	owner := input.ssh.config_permissions.pw_name
	owner != "root"
}

permission_violations contains "CIS 5.2.1: /etc/ssh/sshd_config group not root" if {
	group := input.ssh.config_permissions.gr_name
	group != "root"
}

# =============================================================================
# CIS 5.2.2 - SSH PRIVATE KEY PERMISSIONS
# =============================================================================

permission_violations contains sprintf("CIS 5.2.2: SSH private key %s has incorrect permissions (mode: %s, should be 0600)", [key.stat.path, key.stat.mode]) if {
	some key in input.ssh.private_key_permissions
	key.stat.mode != "0600"
}

permission_violations contains sprintf("CIS 5.2.2: SSH private key %s not owned by root (owner: %s)", [key.stat.path, key.stat.pw_name]) if {
	some key in input.ssh.private_key_permissions
	key.stat.pw_name != "root"
}

# =============================================================================
# CIS 5.2.3 - SSH PUBLIC KEY PERMISSIONS
# =============================================================================

permission_violations contains sprintf("CIS 5.2.3: SSH public key %s permissions too permissive (mode: %s)", [key.path, key.mode]) if {
	some key in input.ssh.public_key_permissions
	mode_num := to_number(key.mode)
	mode_num > 644
}

# =============================================================================
# CIS 5.2.4 - SSH LOGLEVEL
# =============================================================================

config_violations contains "CIS 5.2.4: SSH LogLevel not set to appropriate value (should be INFO or VERBOSE)" if {
	loglevel := sshd_config["loglevel"]
	not loglevel in ["INFO", "VERBOSE"]
}

config_violations contains "CIS 5.2.4: SSH LogLevel not configured" if {
	not sshd_config["loglevel"]
}

# =============================================================================
# CIS 5.2.5 - SSH X11 FORWARDING
# =============================================================================

config_violations contains "CIS 5.2.5: SSH X11Forwarding is enabled (should be 'no')" if {
	x11 := sshd_config["x11forwarding"]
	x11 == "yes"
}

# =============================================================================
# CIS 5.2.6 - SSH MAXAUTHTRIES
# =============================================================================

config_violations contains sprintf("CIS 5.2.6: SSH MaxAuthTries is %v (should be 4 or less)", [tries]) if {
	tries_str := sshd_config["maxauthtries"]
	tries := to_number(tries_str)
	tries > 4
}

config_violations contains "CIS 5.2.6: SSH MaxAuthTries not configured" if {
	not sshd_config["maxauthtries"]
}

# =============================================================================
# CIS 5.2.7 - SSH IGNORERHOSTS
# =============================================================================

config_violations contains "CIS 5.2.7: SSH IgnoreRhosts not enabled" if {
	ignore := sshd_config["ignorerhosts"]
	ignore != "yes"
}

config_violations contains "CIS 5.2.7: SSH IgnoreRhosts not configured" if {
	not sshd_config["ignorerhosts"]
}

# =============================================================================
# CIS 5.2.8 - SSH HOSTBASED AUTHENTICATION
# =============================================================================

config_violations contains "CIS 5.2.8: SSH HostbasedAuthentication is enabled (should be 'no')" if {
	hostbased := sshd_config["hostbasedauthentication"]
	hostbased == "yes"
}

# =============================================================================
# CIS 5.2.9 - SSH ROOT LOGIN
# =============================================================================

config_violations contains sprintf("CIS 5.2.9: SSH PermitRootLogin is '%v' (should be 'no')", [permit]) if {
	permit := sshd_config["permitrootlogin"]
	permit != "no"
}

config_violations contains "CIS 5.2.9: SSH PermitRootLogin not configured" if {
	not sshd_config["permitrootlogin"]
}

# =============================================================================
# CIS 5.2.10 - SSH EMPTY PASSWORDS
# =============================================================================

config_violations contains "CIS 5.2.10: SSH PermitEmptyPasswords is enabled (should be 'no')" if {
	permit := sshd_config["permitemptypasswords"]
	permit == "yes"
}

# =============================================================================
# CIS 5.2.11 - SSH USER ENVIRONMENT
# =============================================================================

config_violations contains "CIS 5.2.11: SSH PermitUserEnvironment is enabled (should be 'no')" if {
	permit := sshd_config["permituserenvironment"]
	permit == "yes"
}

# =============================================================================
# CIS 5.2.12 - SSH CIPHERS
# =============================================================================

weak_ciphers := {
	"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
	"arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
	"cast128-cbc", "rijndael-cbc@lysator.liu.se"
}

crypto_violations contains sprintf("CIS 5.2.12: Weak SSH cipher '%s' is allowed", [cipher]) if {
	ciphers_str := sshd_config["ciphers"]
	cipher_list := split(ciphers_str, ",")
	some cipher in cipher_list
	cipher in weak_ciphers
}

# =============================================================================
# CIS 5.2.13 - SSH MAC ALGORITHMS
# =============================================================================

weak_macs := {
	"hmac-md5", "hmac-md5-96", "hmac-ripemd160",
	"hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com",
	"hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
	"hmac-ripemd160-etm@openssh.com", "hmac-sha1-etm@openssh.com",
	"hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com",
	"umac-128-etm@openssh.com"
}

crypto_violations contains sprintf("CIS 5.2.13: Weak SSH MAC '%s' is allowed", [mac]) if {
	macs_str := sshd_config["macs"]
	mac_list := split(macs_str, ",")
	some mac in mac_list
	mac in weak_macs
}

# =============================================================================
# CIS 5.2.14 - SSH KEY EXCHANGE ALGORITHMS
# =============================================================================

weak_kex := {
	"diffie-hellman-group1-sha1",
	"diffie-hellman-group14-sha1",
	"diffie-hellman-group-exchange-sha1"
}

crypto_violations contains sprintf("CIS 5.2.14: Weak SSH KexAlgorithm '%s' is allowed", [kex]) if {
	kex_str := sshd_config["kexalgorithms"]
	kex_list := split(kex_str, ",")
	some kex in kex_list
	kex in weak_kex
}

# =============================================================================
# CIS 5.2.15 - SSH IDLE TIMEOUT
# =============================================================================

config_violations contains sprintf("CIS 5.2.15: SSH ClientAliveInterval is %v seconds (should be 300 or less)", [interval]) if {
	interval_str := sshd_config["clientaliveinterval"]
	interval := to_number(interval_str)
	interval > 300
}

config_violations contains "CIS 5.2.15: SSH ClientAliveInterval not configured" if {
	not sshd_config["clientaliveinterval"]
}

config_violations contains sprintf("CIS 5.2.15: SSH ClientAliveCountMax is %v (should be 3 or less)", [count_max]) if {
	count_str := sshd_config["clientalivecountmax"]
	count_max := to_number(count_str)
	count_max > 3
}

# =============================================================================
# CIS 5.2.16 - SSH LOGIN GRACE TIME
# =============================================================================

config_violations contains sprintf("CIS 5.2.16: SSH LoginGraceTime is %v seconds (should be 60 or less)", [grace]) if {
	grace_str := sshd_config["logingracetime"]
	grace := to_number(grace_str)
	grace > 60
}

# =============================================================================
# CIS 5.2.17 - SSH BANNER
# =============================================================================

config_violations contains "CIS 5.2.17: SSH Banner not configured" if {
	not sshd_config["banner"]
}

config_violations contains "CIS 5.2.17: SSH Banner set to 'none'" if {
	banner := sshd_config["banner"]
	banner == "none"
}

# =============================================================================
# CIS 5.2.18 - SSH PAM
# =============================================================================

config_violations contains "CIS 5.2.18: SSH UsePAM not enabled" if {
	usepam := sshd_config["usepam"]
	usepam != "yes"
}

config_violations contains "CIS 5.2.18: SSH UsePAM not configured" if {
	not sshd_config["usepam"]
}

# =============================================================================
# CIS 5.2.19 - SSH TCP FORWARDING
# =============================================================================

config_violations contains "CIS 5.2.19: SSH AllowTcpForwarding is enabled (should be 'no')" if {
	allow := sshd_config["allowtcpforwarding"]
	allow == "yes"
}

# =============================================================================
# CIS 5.2.20 - SSH MAXSTARTUPS
# =============================================================================

config_violations contains "CIS 5.2.20: SSH MaxStartups not configured" if {
	not sshd_config["maxstartups"]
}

# =============================================================================
# CIS 5.2.21 - SSH MAXSESSIONS
# =============================================================================

config_violations contains sprintf("CIS 5.2.21: SSH MaxSessions is %v (should be 10 or less)", [sessions]) if {
	sessions_str := sshd_config["maxsessions"]
	sessions := to_number(sessions_str)
	sessions > 10
}

# =============================================================================
# SUMMARY REPORT
# =============================================================================

report := {
	"compliant": compliant,
	"violations": violations,
	"total_violations": count(violations),
	"permission_violations": count(permission_violations),
	"config_violations": count(config_violations),
	"crypto_violations": count(crypto_violations),
	"controls_checked": 21,
	"section": "5.2 SSH Server Configuration",
}
