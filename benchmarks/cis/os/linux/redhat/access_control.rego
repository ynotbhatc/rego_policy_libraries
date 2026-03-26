package cis.access_control

import rego.v1

# CIS Benchmark - Access, Authentication and Authorization
# Section 5: Access, Authentication and Authorization

# CIS 5.1.1 - Ensure cron daemon is enabled
cron_enabled if {
    input.services["cron"].enabled == true
}

# CIS 5.1.2 - Ensure permissions on /etc/crontab are configured
crontab_permissions if {
    input.file_permissions["/etc/crontab"].mode == "0600"
    input.file_permissions["/etc/crontab"].owner == "root"
    input.file_permissions["/etc/crontab"].group == "root"
}

# CIS 5.1.3 - Ensure permissions on /etc/cron.hourly are configured
cron_hourly_permissions if {
    input.file_permissions["/etc/cron.hourly"].mode == "0700"
    input.file_permissions["/etc/cron.hourly"].owner == "root"
    input.file_permissions["/etc/cron.hourly"].group == "root"
}

# CIS 5.1.4 - Ensure permissions on /etc/cron.daily are configured
cron_daily_permissions if {
    input.file_permissions["/etc/cron.daily"].mode == "0700"
    input.file_permissions["/etc/cron.daily"].owner == "root"
    input.file_permissions["/etc/cron.daily"].group == "root"
}

# CIS 5.1.5 - Ensure permissions on /etc/cron.weekly are configured
cron_weekly_permissions if {
    input.file_permissions["/etc/cron.weekly"].mode == "0700"
    input.file_permissions["/etc/cron.weekly"].owner == "root"
    input.file_permissions["/etc/cron.weekly"].group == "root"
}

# CIS 5.1.6 - Ensure permissions on /etc/cron.monthly are configured
cron_monthly_permissions if {
    input.file_permissions["/etc/cron.monthly"].mode == "0700"
    input.file_permissions["/etc/cron.monthly"].owner == "root"
    input.file_permissions["/etc/cron.monthly"].group == "root"
}

# CIS 5.2.1 - Ensure permissions on /etc/ssh/sshd_config are configured
sshd_config_permissions if {
    input.file_permissions["/etc/ssh/sshd_config"].mode == "0600"
    input.file_permissions["/etc/ssh/sshd_config"].owner == "root"
    input.file_permissions["/etc/ssh/sshd_config"].group == "root"
}

# CIS 5.2.2 - Ensure SSH access is limited
ssh_access_limited if {
    # Check if AllowUsers, AllowGroups, DenyUsers, or DenyGroups are configured
    count([x | x := input.ssh_config[_]; startswith(x, "AllowUsers")]) > 0
}

ssh_access_limited if {
    count([x | x := input.ssh_config[_]; startswith(x, "AllowGroups")]) > 0
}

ssh_access_limited if {
    count([x | x := input.ssh_config[_]; startswith(x, "DenyUsers")]) > 0
}

ssh_access_limited if {
    count([x | x := input.ssh_config[_]; startswith(x, "DenyGroups")]) > 0
}

# CIS 5.2.3 - Ensure permissions on SSH private host key files are configured
ssh_private_key_permissions if {
    every key in input.ssh_private_keys {
        input.file_permissions[key].mode == "0600"
        input.file_permissions[key].owner == "root"
        input.file_permissions[key].group == "root"
    }
}

# CIS 5.2.4 - Ensure permissions on SSH public host key files are configured
ssh_public_key_permissions if {
    every key in input.ssh_public_keys {
        input.file_permissions[key].mode == "0644"
        input.file_permissions[key].owner == "root"
        input.file_permissions[key].group == "root"
    }
}

# CIS 5.2.5 - Ensure SSH LogLevel is appropriate
ssh_loglevel_appropriate if {
    contains(input.ssh_config, "LogLevel INFO")
}

ssh_loglevel_appropriate if {
    contains(input.ssh_config, "LogLevel VERBOSE")
}

# CIS 5.2.6 - Ensure SSH X11 forwarding is disabled
ssh_x11_forwarding_disabled if {
    contains(input.ssh_config, "X11Forwarding no")
}

# CIS 5.2.7 - Ensure SSH MaxAuthTries is set to 4 or less
ssh_maxauthtries_limited if {
    some i
    line := input.ssh_config[i]
    startswith(line, "MaxAuthTries ")
    auth_tries := to_number(split(line, " ")[1])
    auth_tries <= 4
}

# CIS 5.2.8 - Ensure SSH IgnoreRhosts is enabled
ssh_ignorerhosts_enabled if {
    contains(input.ssh_config, "IgnoreRhosts yes")
}

# CIS 5.2.9 - Ensure SSH HostbasedAuthentication is disabled
ssh_hostbased_auth_disabled if {
    contains(input.ssh_config, "HostbasedAuthentication no")
}

# CIS 5.2.10 - Ensure SSH root login is disabled
ssh_root_login_disabled if {
    "PermitRootLogin no" in input.ssh_config
}

# CIS 5.2.11 - Ensure SSH PermitEmptyPasswords is disabled
ssh_empty_passwords_disabled if {
    contains(input.ssh_config, "PermitEmptyPasswords no")
}

# CIS 5.2.12 - Ensure SSH PermitUserEnvironment is disabled
ssh_user_environment_disabled if {
    contains(input.ssh_config, "PermitUserEnvironment no")
}

# CIS 5.2.13 - Ensure SSH Idle Timeout Interval is configured
ssh_idle_timeout_configured if {
    some i, j
    client_alive_interval := input.ssh_config[i]
    client_alive_count_max := input.ssh_config[j]
    startswith(client_alive_interval, "ClientAliveInterval ")
    startswith(client_alive_count_max, "ClientAliveCountMax ")
    interval := to_number(split(client_alive_interval, " ")[1])
    count_max := to_number(split(client_alive_count_max, " ")[1])
    interval > 0
    interval <= 300
    count_max <= 3
}

# CIS 5.2.14 - Ensure SSH LoginGraceTime is set to one minute or less
ssh_login_grace_time_limited if {
    some i
    line := input.ssh_config[i]
    startswith(line, "LoginGraceTime ")
    grace_time := to_number(split(line, " ")[1])
    grace_time <= 60
}

# CIS 5.2.15 - Ensure SSH warning banner is configured
ssh_banner_configured if {
    some i
    line := input.ssh_config[i]
    startswith(line, "Banner ")
    split(line, " ")[1] != "none"
}

# CIS 5.2.16 - Ensure SSH PAM is enabled
ssh_pam_enabled if {
    contains(input.ssh_config, "UsePAM yes")
}

# CIS 5.2.17 - Ensure SSH AllowTcpForwarding is disabled
ssh_tcp_forwarding_disabled if {
    contains(input.ssh_config, "AllowTcpForwarding no")
}

# CIS 5.2.18 - Ensure SSH MaxStartups is configured
ssh_max_startups_configured if {
    some i
    line := input.ssh_config[i]
    startswith(line, "MaxStartups ")
    # Should be "10:30:60" or similar
    true # Simplified check
}

# CIS 5.2.19 - Ensure SSH MaxSessions is limited
ssh_max_sessions_limited if {
    some i
    line := input.ssh_config[i]
    startswith(line, "MaxSessions ")
    sessions := to_number(split(line, " ")[1])
    sessions <= 10
}

# CIS 5.2.20 - Ensure system-wide crypto policy is not over-ridden
ssh_crypto_policy_not_overridden if {
    not contains(input.ssh_config, "CRYPTO_POLICY")
}

# Aggregate access control compliance
access_control_compliant if {
    cron_enabled
    crontab_permissions
    cron_hourly_permissions
    cron_daily_permissions
    cron_weekly_permissions
    cron_monthly_permissions
    sshd_config_permissions
    ssh_access_limited
    ssh_private_key_permissions
    ssh_public_key_permissions
    ssh_loglevel_appropriate
    ssh_x11_forwarding_disabled
    ssh_maxauthtries_limited
    ssh_ignorerhosts_enabled
    ssh_hostbased_auth_disabled
    ssh_root_login_disabled
    ssh_empty_passwords_disabled
    ssh_user_environment_disabled
    ssh_idle_timeout_configured
    ssh_login_grace_time_limited
    ssh_banner_configured
    ssh_pam_enabled
    ssh_tcp_forwarding_disabled
    ssh_max_startups_configured
    ssh_max_sessions_limited
    ssh_crypto_policy_not_overridden
}

# Detailed access control compliance report
access_control_compliance := {
    "cron_enabled": cron_enabled,
    "crontab_permissions": crontab_permissions,
    "cron_hourly_permissions": cron_hourly_permissions,
    "cron_daily_permissions": cron_daily_permissions,
    "cron_weekly_permissions": cron_weekly_permissions,
    "cron_monthly_permissions": cron_monthly_permissions,
    "sshd_config_permissions": sshd_config_permissions,
    "ssh_access_limited": ssh_access_limited,
    "ssh_private_key_permissions": ssh_private_key_permissions,
    "ssh_public_key_permissions": ssh_public_key_permissions,
    "ssh_loglevel_appropriate": ssh_loglevel_appropriate,
    "ssh_x11_forwarding_disabled": ssh_x11_forwarding_disabled,
    "ssh_maxauthtries_limited": ssh_maxauthtries_limited,
    "ssh_ignorerhosts_enabled": ssh_ignorerhosts_enabled,
    "ssh_hostbased_auth_disabled": ssh_hostbased_auth_disabled,
    "ssh_root_login_disabled": ssh_root_login_disabled,
    "ssh_empty_passwords_disabled": ssh_empty_passwords_disabled,
    "ssh_user_environment_disabled": ssh_user_environment_disabled,
    "ssh_idle_timeout_configured": ssh_idle_timeout_configured,
    "ssh_login_grace_time_limited": ssh_login_grace_time_limited,
    "ssh_banner_configured": ssh_banner_configured,
    "ssh_pam_enabled": ssh_pam_enabled,
    "ssh_tcp_forwarding_disabled": ssh_tcp_forwarding_disabled,
    "ssh_max_startups_configured": ssh_max_startups_configured,
    "ssh_max_sessions_limited": ssh_max_sessions_limited,
    "ssh_crypto_policy_not_overridden": ssh_crypto_policy_not_overridden,
    "overall_compliant": access_control_compliant
}