# METADATA
# title: "CIS Benchmark - Access, Authentication and Authorization"
# custom:
#   class: security
#   framework: cis_os
#   source: cis
#   domains: [linux]
#   coverage:
#     checks: 26
#     cited: 0
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package cis.access_control

import rego.v1

# CIS Benchmark - Access, Authentication and Authorization
# Section 5: Access, Authentication and Authorization

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

# SSH configuration as normalized lines (whitespace collapsed, comments dropped).
# The fact may be an array of lines or the raw file text.
ssh_config_lines := lines if {
    is_array(input.ssh_config)
    lines := [norm |
        some raw in input.ssh_config
        norm := regex.replace(trim_space(raw), `\s+`, " ")
        not startswith(norm, "#")
        norm != ""
    ]
} else := lines if {
    is_string(input.ssh_config)
    lines := [norm |
        some raw in split(input.ssh_config, "\n")
        norm := regex.replace(trim_space(raw), `\s+`, " ")
        not startswith(norm, "#")
        norm != ""
    ]
}

# CIS 5.1.1 - Ensure cron daemon is enabled
default cron_enabled := false

cron_enabled if {
    input.services["cron"].enabled == true
}

# CIS 5.1.2 - Ensure permissions on /etc/crontab are configured
default crontab_permissions := false

crontab_permissions if {
    mode_within(input.file_permissions["/etc/crontab"].mode, "0600")
    input.file_permissions["/etc/crontab"].owner == "root"
    input.file_permissions["/etc/crontab"].group == "root"
}

# CIS 5.1.3 - Ensure permissions on /etc/cron.hourly are configured
default cron_hourly_permissions := false

cron_hourly_permissions if {
    mode_within(input.file_permissions["/etc/cron.hourly"].mode, "0700")
    input.file_permissions["/etc/cron.hourly"].owner == "root"
    input.file_permissions["/etc/cron.hourly"].group == "root"
}

# CIS 5.1.4 - Ensure permissions on /etc/cron.daily are configured
default cron_daily_permissions := false

cron_daily_permissions if {
    mode_within(input.file_permissions["/etc/cron.daily"].mode, "0700")
    input.file_permissions["/etc/cron.daily"].owner == "root"
    input.file_permissions["/etc/cron.daily"].group == "root"
}

# CIS 5.1.5 - Ensure permissions on /etc/cron.weekly are configured
default cron_weekly_permissions := false

cron_weekly_permissions if {
    mode_within(input.file_permissions["/etc/cron.weekly"].mode, "0700")
    input.file_permissions["/etc/cron.weekly"].owner == "root"
    input.file_permissions["/etc/cron.weekly"].group == "root"
}

# CIS 5.1.6 - Ensure permissions on /etc/cron.monthly are configured
default cron_monthly_permissions := false

cron_monthly_permissions if {
    mode_within(input.file_permissions["/etc/cron.monthly"].mode, "0700")
    input.file_permissions["/etc/cron.monthly"].owner == "root"
    input.file_permissions["/etc/cron.monthly"].group == "root"
}

# CIS 5.2.1 - Ensure permissions on /etc/ssh/sshd_config are configured
default sshd_config_permissions := false

sshd_config_permissions if {
    mode_within(input.file_permissions["/etc/ssh/sshd_config"].mode, "0600")
    input.file_permissions["/etc/ssh/sshd_config"].owner == "root"
    input.file_permissions["/etc/ssh/sshd_config"].group == "root"
}

# CIS 5.2.2 - Ensure SSH access is limited
default ssh_access_limited := false

ssh_access_limited if {
    # Check if AllowUsers, AllowGroups, DenyUsers, or DenyGroups are configured
    count([x | x := ssh_config_lines[_]; startswith(x, "AllowUsers")]) > 0
}

ssh_access_limited if {
    count([x | x := ssh_config_lines[_]; startswith(x, "AllowGroups")]) > 0
}

ssh_access_limited if {
    count([x | x := ssh_config_lines[_]; startswith(x, "DenyUsers")]) > 0
}

ssh_access_limited if {
    count([x | x := ssh_config_lines[_]; startswith(x, "DenyGroups")]) > 0
}

# CIS 5.2.3 - Ensure permissions on SSH private host key files are configured
default ssh_private_key_permissions := false

ssh_private_key_permissions if {
    count(input.ssh_private_keys) > 0
    every key in input.ssh_private_keys {
        mode_within(input.file_permissions[key].mode, "0600")
        input.file_permissions[key].owner == "root"
        input.file_permissions[key].group == "root"
    }
}

# CIS 5.2.4 - Ensure permissions on SSH public host key files are configured
default ssh_public_key_permissions := false

ssh_public_key_permissions if {
    count(input.ssh_public_keys) > 0
    every key in input.ssh_public_keys {
        mode_within(input.file_permissions[key].mode, "0644")
        input.file_permissions[key].owner == "root"
        input.file_permissions[key].group == "root"
    }
}

# CIS 5.2.5 - Ensure SSH LogLevel is appropriate
default ssh_loglevel_appropriate := false

ssh_loglevel_appropriate if {
    "LogLevel INFO" in ssh_config_lines
}

ssh_loglevel_appropriate if {
    "LogLevel VERBOSE" in ssh_config_lines
}

# CIS 5.2.6 - Ensure SSH X11 forwarding is disabled
default ssh_x11_forwarding_disabled := false

ssh_x11_forwarding_disabled if {
    "X11Forwarding no" in ssh_config_lines
}

# CIS 5.2.7 - Ensure SSH MaxAuthTries is set to 4 or less
default ssh_maxauthtries_limited := false

ssh_maxauthtries_limited if {
    some i
    line := ssh_config_lines[i]
    startswith(line, "MaxAuthTries ")
    auth_tries := to_number(split(line, " ")[1])
    auth_tries <= 4
}

# CIS 5.2.8 - Ensure SSH IgnoreRhosts is enabled
default ssh_ignorerhosts_enabled := false

ssh_ignorerhosts_enabled if {
    "IgnoreRhosts yes" in ssh_config_lines
}

# CIS 5.2.9 - Ensure SSH HostbasedAuthentication is disabled
default ssh_hostbased_auth_disabled := false

ssh_hostbased_auth_disabled if {
    "HostbasedAuthentication no" in ssh_config_lines
}

# CIS 5.2.10 - Ensure SSH root login is disabled
default ssh_root_login_disabled := false

ssh_root_login_disabled if {
    "PermitRootLogin no" in ssh_config_lines
}

# CIS 5.2.11 - Ensure SSH PermitEmptyPasswords is disabled
default ssh_empty_passwords_disabled := false

ssh_empty_passwords_disabled if {
    "PermitEmptyPasswords no" in ssh_config_lines
}

# CIS 5.2.12 - Ensure SSH PermitUserEnvironment is disabled
default ssh_user_environment_disabled := false

ssh_user_environment_disabled if {
    "PermitUserEnvironment no" in ssh_config_lines
}

# CIS 5.2.13 - Ensure SSH Idle Timeout Interval is configured
default ssh_idle_timeout_configured := false

ssh_idle_timeout_configured if {
    some i, j
    client_alive_interval := ssh_config_lines[i]
    client_alive_count_max := ssh_config_lines[j]
    startswith(client_alive_interval, "ClientAliveInterval ")
    startswith(client_alive_count_max, "ClientAliveCountMax ")
    interval := to_number(split(client_alive_interval, " ")[1])
    count_max := to_number(split(client_alive_count_max, " ")[1])
    interval > 0
    interval <= 300
    count_max <= 3
}

# CIS 5.2.14 - Ensure SSH LoginGraceTime is set to one minute or less
default ssh_login_grace_time_limited := false

ssh_login_grace_time_limited if {
    some i
    line := ssh_config_lines[i]
    startswith(line, "LoginGraceTime ")
    grace_time := to_number(split(line, " ")[1])
    grace_time <= 60
}

# CIS 5.2.15 - Ensure SSH warning banner is configured
default ssh_banner_configured := false

ssh_banner_configured if {
    some i
    line := ssh_config_lines[i]
    startswith(line, "Banner ")
    split(line, " ")[1] != "none"
}

# CIS 5.2.16 - Ensure SSH PAM is enabled
default ssh_pam_enabled := false

ssh_pam_enabled if {
    "UsePAM yes" in ssh_config_lines
}

# CIS 5.2.17 - Ensure SSH AllowTcpForwarding is disabled
default ssh_tcp_forwarding_disabled := false

ssh_tcp_forwarding_disabled if {
    "AllowTcpForwarding no" in ssh_config_lines
}

# CIS 5.2.18 - Ensure SSH MaxStartups is configured
default ssh_max_startups_configured := false

ssh_max_startups_configured if {
    some line in ssh_config_lines
    startswith(line, "MaxStartups ")
    # CIS: 10:30:60 or more restrictive (start:rate:full), or a bare start count of 10 or less
    m := regex.find_all_string_submatch_n(`^MaxStartups (\d+):(\d+):(\d+)$`, line, 1)
    to_number(m[0][1]) <= 10
    to_number(m[0][2]) <= 30
    to_number(m[0][3]) <= 60
}

ssh_max_startups_configured if {
    some line in ssh_config_lines
    m := regex.find_all_string_submatch_n(`^MaxStartups (\d+)$`, line, 1)
    to_number(m[0][1]) <= 10
}

# CIS 5.2.19 - Ensure SSH MaxSessions is limited
default ssh_max_sessions_limited := false

ssh_max_sessions_limited if {
    some i
    line := ssh_config_lines[i]
    startswith(line, "MaxSessions ")
    sessions := to_number(split(line, " ")[1])
    sessions <= 10
}

# CIS 5.2.20 - Ensure system-wide crypto policy is not over-ridden
default ssh_crypto_policy_not_overridden := false

ssh_crypto_policy_not_overridden if {
    count(ssh_config_lines) > 0
    not ssh_crypto_policy_override_present
}

ssh_crypto_policy_override_present if {
    some line in ssh_config_lines
    contains(line, "CRYPTO_POLICY")
}

# Aggregate access control compliance
default access_control_compliant := false

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