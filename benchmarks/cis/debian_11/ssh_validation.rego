package cis_debian_11.ssh

# CIS Debian Linux 11 Benchmark v1.0.0 - Section 5.2: Configure SSH Server

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in config_violations], [v | some v in crypto_violations]),
	[v | some v in permission_violations],
)

# CIS 5.2.1: Ensure permissions on /etc/ssh/sshd_config are configured
permission_violations contains msg if {
	input.ssh.sshd_config_mode != "0600"
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
	some key in input.ssh.private_key_files
	to_number(key.mode) > 600
	msg := sprintf("CIS 5.2.2: SSH private host key %s has mode %s, should be 0600", [key.path, key.mode])
}

# CIS 5.2.3: Ensure permissions on SSH public host key files
permission_violations contains msg if {
	some key in input.ssh.public_key_files
	to_number(key.mode) > 644
	msg := sprintf("CIS 5.2.3: SSH public host key %s has mode %s, should be 0644", [key.path, key.mode])
}

# CIS 5.2.4: Ensure SSH access is limited
config_violations contains msg if {
	not contains(input.ssh.sshd_config_raw, "AllowUsers")
	not contains(input.ssh.sshd_config_raw, "AllowGroups")
	not contains(input.ssh.sshd_config_raw, "DenyUsers")
	not contains(input.ssh.sshd_config_raw, "DenyGroups")
	msg := "CIS 5.2.4: SSH access is not limited via AllowUsers/AllowGroups/DenyUsers/DenyGroups"
}

# CIS 5.2.5: Ensure SSH LogLevel is appropriate
config_violations contains msg if {
	not contains(input.ssh.sshd_config_raw, "LogLevel VERBOSE")
	not contains(input.ssh.sshd_config_raw, "LogLevel INFO")
	msg := "CIS 5.2.5: SSH LogLevel is not set to VERBOSE or INFO"
}

# CIS 5.2.6: Ensure SSH PAM is enabled
config_violations contains msg if {
	contains(input.ssh.sshd_config_raw, "UsePAM no")
	msg := "CIS 5.2.6: SSH UsePAM is disabled"
}

# CIS 5.2.7: Ensure SSH root login is disabled
config_violations contains msg if {
	not contains(input.ssh.sshd_config_raw, "PermitRootLogin no")
	not contains(input.ssh.sshd_config_raw, "PermitRootLogin prohibit-password")
	not contains(input.ssh.sshd_config_raw, "PermitRootLogin forced-commands-only")
	msg := "CIS 5.2.7: SSH root login is not disabled"
}

# CIS 5.2.8: Ensure SSH HostbasedAuthentication is disabled
config_violations contains msg if {
	contains(input.ssh.sshd_config_raw, "HostbasedAuthentication yes")
	msg := "CIS 5.2.8: SSH HostbasedAuthentication is enabled"
}

# CIS 5.2.9: Ensure SSH PermitEmptyPasswords is disabled
config_violations contains msg if {
	contains(input.ssh.sshd_config_raw, "PermitEmptyPasswords yes")
	msg := "CIS 5.2.9: SSH PermitEmptyPasswords is enabled"
}

# CIS 5.2.10: Ensure SSH PermitUserEnvironment is disabled
config_violations contains msg if {
	contains(input.ssh.sshd_config_raw, "PermitUserEnvironment yes")
	msg := "CIS 5.2.10: SSH PermitUserEnvironment is enabled"
}

# CIS 5.2.11: Ensure SSH IgnoreRhosts is enabled
config_violations contains msg if {
	contains(input.ssh.sshd_config_raw, "IgnoreRhosts no")
	msg := "CIS 5.2.11: SSH IgnoreRhosts is disabled"
}

# CIS 5.2.12: Ensure SSH X11Forwarding is disabled
config_violations contains msg if {
	contains(input.ssh.sshd_config_raw, "X11Forwarding yes")
	msg := "CIS 5.2.12: SSH X11Forwarding is enabled"
}

# CIS 5.2.13: Ensure SSH AllowTcpForwarding is disabled
config_violations contains msg if {
	contains(input.ssh.sshd_config_raw, "AllowTcpForwarding yes")
	msg := "CIS 5.2.13: SSH AllowTcpForwarding is enabled"
}

# CIS 5.2.14: Ensure SSH warning banner is configured
config_violations contains msg if {
	not contains(input.ssh.sshd_config_raw, "Banner")
	msg := "CIS 5.2.14: SSH warning banner (Banner) is not configured"
}

config_violations contains msg if {
	contains(input.ssh.sshd_config_raw, "Banner none")
	msg := "CIS 5.2.14: SSH banner is set to none"
}

# CIS 5.2.15: Ensure SSH MaxAuthTries is set to 4 or less
config_violations contains msg if {
	some line in split(input.ssh.sshd_config_raw, "\n")
	startswith(trim_space(line), "MaxAuthTries")
	parts := split(trim_space(line), " ")
	count(parts) >= 2
	to_number(parts[1]) > 4
	msg := sprintf("CIS 5.2.15: SSH MaxAuthTries is %s, should be 4 or less", [parts[1]])
}

# CIS 5.2.16: Ensure SSH MaxStartups is configured
config_violations contains msg if {
	not contains(input.ssh.sshd_config_raw, "MaxStartups")
	msg := "CIS 5.2.16: SSH MaxStartups is not configured"
}

# CIS 5.2.17: Ensure SSH MaxSessions is set to 10 or less
config_violations contains msg if {
	some line in split(input.ssh.sshd_config_raw, "\n")
	startswith(trim_space(line), "MaxSessions")
	parts := split(trim_space(line), " ")
	count(parts) >= 2
	to_number(parts[1]) > 10
	msg := sprintf("CIS 5.2.17: SSH MaxSessions is %s, should be 10 or less", [parts[1]])
}

# CIS 5.2.18: Ensure SSH LoginGraceTime is set to one minute or less
config_violations contains msg if {
	some line in split(input.ssh.sshd_config_raw, "\n")
	startswith(trim_space(line), "LoginGraceTime")
	parts := split(trim_space(line), " ")
	count(parts) >= 2
	to_number(parts[1]) > 60
	msg := sprintf("CIS 5.2.18: SSH LoginGraceTime is %s seconds, should be 60 or less", [parts[1]])
}

# CIS 5.2.19: Ensure SSH Idle Timeout Interval is configured
config_violations contains msg if {
	not contains(input.ssh.sshd_config_raw, "ClientAliveInterval")
	msg := "CIS 5.2.19: SSH ClientAliveInterval is not configured"
}

config_violations contains msg if {
	not contains(input.ssh.sshd_config_raw, "ClientAliveCountMax")
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
	"benchmark": "CIS Debian 11 v1.0.0",
}
