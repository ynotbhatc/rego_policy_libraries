package cis_rhel9.ssh_validation

import rego.v1

# CIS RHEL 9 Benchmark v2.0.0 - Section 5.1: SSH Server Configuration
# Validates SSH daemon configuration for secure remote access

# =============================================================================
# CIS 5.1.1 - Ensure permissions on /etc/ssh/sshd_config are configured
# =============================================================================

validate_sshd_config_permissions if {
    input.ssh.sshd_config_stat.exists
    input.ssh.sshd_config_stat.mode == "0600"
    input.ssh.sshd_config_stat.owner == "root"
    input.ssh.sshd_config_stat.group == "root"
}

violations contains {
    "control_id": "5.1.1",
    "title": "Ensure permissions on /etc/ssh/sshd_config are configured",
    "severity": "high",
    "description": "The /etc/ssh/sshd_config file must be owned by root and have mode 0600",
    "status": "fail",
    "finding": sprintf("sshd_config permissions: mode=%v owner=%v group=%v", [
        input.ssh.sshd_config_stat.mode,
        input.ssh.sshd_config_stat.owner,
        input.ssh.sshd_config_stat.group
    ]),
    "remediation": "Run: chown root:root /etc/ssh/sshd_config && chmod 0600 /etc/ssh/sshd_config"
} if {
    not validate_sshd_config_permissions
}

# =============================================================================
# CIS 5.1.2 - Ensure permissions on SSH private host key files are configured
# =============================================================================

validate_ssh_private_key_permissions(key) if {
    key.mode == "0600"
    key.owner == "root"
    key.group in ["root", "ssh_keys"]
}

violations contains {
    "control_id": "5.1.2",
    "title": "Ensure permissions on SSH private host key files are configured",
    "severity": "critical",
    "description": "SSH private host keys must be protected with mode 0600 and owned by root",
    "status": "fail",
    "finding": sprintf("Private key %v has incorrect permissions: mode=%v owner=%v group=%v", [
        key.path,
        key.mode,
        key.owner,
        key.group
    ]),
    "remediation": sprintf("Run: chown root:root %v && chmod 0600 %v", [key.path, key.path])
} if {
    some key in input.ssh.private_host_keys
    not validate_ssh_private_key_permissions(key)
}

# =============================================================================
# CIS 5.1.3 - Ensure permissions on SSH public host key files are configured
# =============================================================================

validate_ssh_public_key_permissions(key) if {
    key.mode == "0644"
    key.owner == "root"
    key.group == "root"
}

violations contains {
    "control_id": "5.1.3",
    "title": "Ensure permissions on SSH public host key files are configured",
    "severity": "medium",
    "description": "SSH public host keys should have mode 0644 and be owned by root",
    "status": "fail",
    "finding": sprintf("Public key %v has incorrect permissions: mode=%v owner=%v group=%v", [
        key.path,
        key.mode,
        key.owner,
        key.group
    ]),
    "remediation": sprintf("Run: chown root:root %v && chmod 0644 %v", [key.path, key.path])
} if {
    some key in input.ssh.public_host_keys
    not validate_ssh_public_key_permissions(key)
}

# =============================================================================
# CIS 5.1.4 - Ensure SSH access is limited
# =============================================================================

validate_ssh_access_limited if {
    count(input.ssh.config.AllowUsers) > 0
}

validate_ssh_access_limited if {
    count(input.ssh.config.AllowGroups) > 0
}

validate_ssh_access_limited if {
    count(input.ssh.config.DenyUsers) > 0
}

validate_ssh_access_limited if {
    count(input.ssh.config.DenyGroups) > 0
}

violations contains {
    "control_id": "5.1.4",
    "title": "Ensure SSH access is limited",
    "severity": "high",
    "description": "SSH access should be limited using AllowUsers, AllowGroups, DenyUsers, or DenyGroups",
    "status": "fail",
    "finding": "No SSH access restrictions configured (AllowUsers, AllowGroups, DenyUsers, DenyGroups)",
    "remediation": "Edit /etc/ssh/sshd_config and add AllowUsers or AllowGroups directive to limit SSH access"
} if {
    not validate_ssh_access_limited
}

# =============================================================================
# CIS 5.1.5 - Ensure SSH LogLevel is appropriate
# =============================================================================

validate_ssh_loglevel if {
    input.ssh.config.LogLevel in ["INFO", "VERBOSE"]
}

violations contains {
    "control_id": "5.1.5",
    "title": "Ensure SSH LogLevel is appropriate",
    "severity": "medium",
    "description": "SSH LogLevel should be set to INFO or VERBOSE for adequate logging",
    "status": "fail",
    "finding": sprintf("SSH LogLevel is set to: %v", [input.ssh.config.LogLevel]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'LogLevel INFO' or 'LogLevel VERBOSE'"
} if {
    not validate_ssh_loglevel
}

# =============================================================================
# CIS 5.1.6 - Ensure SSH PAM is enabled
# =============================================================================

validate_ssh_pam_enabled if {
    input.ssh.config.UsePAM == "yes"
}

violations contains {
    "control_id": "5.1.6",
    "title": "Ensure SSH PAM is enabled",
    "severity": "high",
    "description": "SSH should use PAM for additional authentication and session management",
    "status": "fail",
    "finding": sprintf("SSH UsePAM is set to: %v", [input.ssh.config.UsePAM]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'UsePAM yes'"
} if {
    not validate_ssh_pam_enabled
}

# =============================================================================
# CIS 5.1.7 - Ensure SSH root login is disabled
# =============================================================================

validate_ssh_root_login_disabled if {
    input.ssh.config.PermitRootLogin == "no"
}

violations contains {
    "control_id": "5.1.7",
    "title": "Ensure SSH root login is disabled",
    "severity": "critical",
    "description": "Direct root login via SSH should be disabled",
    "status": "fail",
    "finding": sprintf("SSH PermitRootLogin is set to: %v", [input.ssh.config.PermitRootLogin]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'PermitRootLogin no'"
} if {
    not validate_ssh_root_login_disabled
}

# =============================================================================
# CIS 5.1.8 - Ensure SSH HostbasedAuthentication is disabled
# =============================================================================

validate_ssh_hostbased_disabled if {
    input.ssh.config.HostbasedAuthentication == "no"
}

violations contains {
    "control_id": "5.1.8",
    "title": "Ensure SSH HostbasedAuthentication is disabled",
    "severity": "high",
    "description": "SSH host-based authentication should be disabled",
    "status": "fail",
    "finding": sprintf("SSH HostbasedAuthentication is set to: %v", [input.ssh.config.HostbasedAuthentication]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'HostbasedAuthentication no'"
} if {
    not validate_ssh_hostbased_disabled
}

# =============================================================================
# CIS 5.1.9 - Ensure SSH PermitEmptyPasswords is disabled
# =============================================================================

validate_ssh_empty_passwords_disabled if {
    input.ssh.config.PermitEmptyPasswords == "no"
}

violations contains {
    "control_id": "5.1.9",
    "title": "Ensure SSH PermitEmptyPasswords is disabled",
    "severity": "critical",
    "description": "SSH should not permit empty passwords",
    "status": "fail",
    "finding": sprintf("SSH PermitEmptyPasswords is set to: %v", [input.ssh.config.PermitEmptyPasswords]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'PermitEmptyPasswords no'"
} if {
    not validate_ssh_empty_passwords_disabled
}

# =============================================================================
# CIS 5.1.10 - Ensure SSH PermitUserEnvironment is disabled
# =============================================================================

validate_ssh_user_environment_disabled if {
    input.ssh.config.PermitUserEnvironment == "no"
}

violations contains {
    "control_id": "5.1.10",
    "title": "Ensure SSH PermitUserEnvironment is disabled",
    "severity": "high",
    "description": "SSH should not permit user environment variables",
    "status": "fail",
    "finding": sprintf("SSH PermitUserEnvironment is set to: %v", [input.ssh.config.PermitUserEnvironment]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'PermitUserEnvironment no'"
} if {
    not validate_ssh_user_environment_disabled
}

# =============================================================================
# CIS 5.1.11 - Ensure SSH IgnoreRhosts is enabled
# =============================================================================

validate_ssh_ignore_rhosts if {
    input.ssh.config.IgnoreRhosts == "yes"
}

violations contains {
    "control_id": "5.1.11",
    "title": "Ensure SSH IgnoreRhosts is enabled",
    "severity": "high",
    "description": "SSH should ignore .rhosts and .shosts files",
    "status": "fail",
    "finding": sprintf("SSH IgnoreRhosts is set to: %v", [input.ssh.config.IgnoreRhosts]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'IgnoreRhosts yes'"
} if {
    not validate_ssh_ignore_rhosts
}

# =============================================================================
# CIS 5.1.12 - Ensure SSH X11 forwarding is disabled
# =============================================================================

validate_ssh_x11_forwarding_disabled if {
    input.ssh.config.X11Forwarding == "no"
}

violations contains {
    "control_id": "5.1.12",
    "title": "Ensure SSH X11 forwarding is disabled",
    "severity": "medium",
    "description": "SSH X11 forwarding should be disabled unless specifically required",
    "status": "fail",
    "finding": sprintf("SSH X11Forwarding is set to: %v", [input.ssh.config.X11Forwarding]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'X11Forwarding no'"
} if {
    not validate_ssh_x11_forwarding_disabled
}

# =============================================================================
# CIS 5.1.13 - Ensure only strong ciphers are used
# =============================================================================

weak_ciphers := [
    "3des-cbc",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "arcfour",
    "arcfour128",
    "arcfour256",
    "blowfish-cbc",
    "cast128-cbc",
    "rijndael-cbc@lysator.liu.se"
]

validate_ssh_strong_ciphers if {
    count([cipher |
        some cipher in input.ssh.config.Ciphers
        cipher in weak_ciphers
    ]) == 0
}

violations contains {
    "control_id": "5.1.13",
    "title": "Ensure only strong ciphers are used",
    "severity": "high",
    "description": "SSH should only use strong encryption ciphers",
    "status": "fail",
    "finding": sprintf("SSH is configured with weak ciphers: %v", [input.ssh.config.Ciphers]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr'"
} if {
    not validate_ssh_strong_ciphers
}

# =============================================================================
# CIS 5.1.14 - Ensure only strong MAC algorithms are used
# =============================================================================

weak_macs := [
    "hmac-md5",
    "hmac-md5-96",
    "hmac-ripemd160",
    "hmac-sha1",
    "hmac-sha1-96",
    "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com",
    "hmac-ripemd160-etm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
    "umac-64-etm@openssh.com"
]

validate_ssh_strong_macs if {
    count([mac |
        some mac in input.ssh.config.MACs
        mac in weak_macs
    ]) == 0
}

violations contains {
    "control_id": "5.1.14",
    "title": "Ensure only strong MAC algorithms are used",
    "severity": "high",
    "description": "SSH should only use strong MAC algorithms",
    "status": "fail",
    "finding": sprintf("SSH is configured with weak MACs: %v", [input.ssh.config.MACs]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256'"
} if {
    not validate_ssh_strong_macs
}

# =============================================================================
# CIS 5.1.15 - Ensure only strong Key Exchange algorithms are used
# =============================================================================

weak_kex := [
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1"
]

validate_ssh_strong_kex if {
    count([kex |
        some kex in input.ssh.config.KexAlgorithms
        kex in weak_kex
    ]) == 0
}

violations contains {
    "control_id": "5.1.15",
    "title": "Ensure only strong Key Exchange algorithms are used",
    "severity": "high",
    "description": "SSH should only use strong key exchange algorithms",
    "status": "fail",
    "finding": sprintf("SSH is configured with weak key exchange algorithms: %v", [input.ssh.config.KexAlgorithms]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256'"
} if {
    not validate_ssh_strong_kex
}

# =============================================================================
# CIS 5.1.16 - Ensure SSH Idle Timeout Interval is configured
# =============================================================================

validate_ssh_idle_timeout if {
    to_number(input.ssh.config.ClientAliveInterval) > 0
    to_number(input.ssh.config.ClientAliveInterval) <= 900
    to_number(input.ssh.config.ClientAliveCountMax) <= 3
}

violations contains {
    "control_id": "5.1.16",
    "title": "Ensure SSH Idle Timeout Interval is configured",
    "severity": "medium",
    "description": "SSH idle timeout should be configured to automatically disconnect idle sessions",
    "status": "fail",
    "finding": sprintf("SSH timeout settings: ClientAliveInterval=%v ClientAliveCountMax=%v", [
        input.ssh.config.ClientAliveInterval,
        input.ssh.config.ClientAliveCountMax
    ]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3'"
} if {
    not validate_ssh_idle_timeout
}

# =============================================================================
# CIS 5.1.17 - Ensure SSH LoginGraceTime is set to one minute or less
# =============================================================================

validate_ssh_login_grace_time if {
    to_number(input.ssh.config.LoginGraceTime) > 0
    to_number(input.ssh.config.LoginGraceTime) <= 60
}

violations contains {
    "control_id": "5.1.17",
    "title": "Ensure SSH LoginGraceTime is set to one minute or less",
    "severity": "medium",
    "description": "SSH LoginGraceTime should be limited to reduce connection resource usage",
    "status": "fail",
    "finding": sprintf("SSH LoginGraceTime is set to: %v seconds", [input.ssh.config.LoginGraceTime]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'LoginGraceTime 60'"
} if {
    not validate_ssh_login_grace_time
}

# =============================================================================
# CIS 5.1.18 - Ensure SSH warning banner is configured
# =============================================================================

validate_ssh_banner if {
    input.ssh.config.Banner != "none"
    input.ssh.config.Banner != ""
}

violations contains {
    "control_id": "5.1.18",
    "title": "Ensure SSH warning banner is configured",
    "severity": "low",
    "description": "SSH should display a warning banner before authentication",
    "status": "fail",
    "finding": sprintf("SSH Banner is set to: %v", [input.ssh.config.Banner]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'Banner /etc/issue.net'"
} if {
    not validate_ssh_banner
}

# =============================================================================
# CIS 5.1.19 - Ensure SSH MaxAuthTries is set to 4 or less
# =============================================================================

validate_ssh_max_auth_tries if {
    to_number(input.ssh.config.MaxAuthTries) <= 4
    to_number(input.ssh.config.MaxAuthTries) > 0
}

violations contains {
    "control_id": "5.1.19",
    "title": "Ensure SSH MaxAuthTries is set to 4 or less",
    "severity": "medium",
    "description": "SSH should limit authentication attempts to prevent brute force attacks",
    "status": "fail",
    "finding": sprintf("SSH MaxAuthTries is set to: %v", [input.ssh.config.MaxAuthTries]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'MaxAuthTries 4'"
} if {
    not validate_ssh_max_auth_tries
}

# =============================================================================
# CIS 5.1.20 - Ensure SSH MaxStartups is configured
# =============================================================================

validate_ssh_max_startups if {
    input.ssh.config.MaxStartups != ""
    # Format is "start:rate:full" like "10:30:60"
    contains(input.ssh.config.MaxStartups, ":")
}

violations contains {
    "control_id": "5.1.20",
    "title": "Ensure SSH MaxStartups is configured",
    "severity": "medium",
    "description": "SSH MaxStartups should be configured to limit concurrent unauthenticated connections",
    "status": "fail",
    "finding": sprintf("SSH MaxStartups is set to: %v", [input.ssh.config.MaxStartups]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'MaxStartups 10:30:60'"
} if {
    not validate_ssh_max_startups
}

# =============================================================================
# CIS 5.1.21 - Ensure SSH MaxSessions is limited
# =============================================================================

validate_ssh_max_sessions if {
    to_number(input.ssh.config.MaxSessions) <= 10
    to_number(input.ssh.config.MaxSessions) > 0
}

violations contains {
    "control_id": "5.1.21",
    "title": "Ensure SSH MaxSessions is limited",
    "severity": "low",
    "description": "SSH should limit the number of concurrent sessions per connection",
    "status": "fail",
    "finding": sprintf("SSH MaxSessions is set to: %v", [input.ssh.config.MaxSessions]),
    "remediation": "Edit /etc/ssh/sshd_config and set 'MaxSessions 10'"
} if {
    not validate_ssh_max_sessions
}

# =============================================================================
# Summary Functions
# =============================================================================

# Collect all SSH violations
ssh_violations := violations

# Count total SSH controls
total_ssh_controls := 21

# Count passed SSH controls
passed_ssh_controls := total_ssh_controls - count(ssh_violations)

# SSH compliance percentage
ssh_compliance_percentage := (passed_ssh_controls / total_ssh_controls) * 100
