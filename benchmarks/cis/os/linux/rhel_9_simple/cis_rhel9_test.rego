package cis.rhel9.test

# Simplified CIS RHEL 9 Compliance Policy for Testing
# This validates a subset of CIS RHEL 9 Benchmark controls

import rego.v1

# CIS 1.1.1.1 - Ensure mounting of cramfs filesystems is disabled
cramfs_disabled if {
    not input.modules["cramfs"].loaded
}

# CIS 1.1.1.2 - Ensure mounting of freevxfs filesystems is disabled
freevxfs_disabled if {
    not input.modules["freevxfs"].loaded
}

# CIS 1.1.1.3 - Ensure mounting of jffs2 filesystems is disabled
jffs2_disabled if {
    not input.modules["jffs2"].loaded
}

# CIS 1.1.1.4 - Ensure mounting of hfs filesystems is disabled
hfs_disabled if {
    not input.modules["hfs"].loaded
}

# CIS 5.2.1 - Ensure permissions on /etc/ssh/sshd_config are configured
sshd_config_perms if {
    input.files["/etc/ssh/sshd_config"].mode == "0600"
    input.files["/etc/ssh/sshd_config"].owner == "root"
    input.files["/etc/ssh/sshd_config"].group == "root"
}

# CIS 5.2.4 - Ensure SSH X11 forwarding is disabled
ssh_x11_disabled if {
    input.ssh_config.X11Forwarding == "no"
}

# CIS 5.2.5 - Ensure SSH MaxAuthTries is set to 4 or less
ssh_max_auth_tries if {
    to_number(input.ssh_config.MaxAuthTries) <= 4
}

# CIS 5.2.7 - Ensure SSH root login is disabled
ssh_root_login_disabled if {
    input.ssh_config.PermitRootLogin == "no"
}

# CIS 5.2.12 - Ensure SSH PermitUserEnvironment is disabled
ssh_user_env_disabled if {
    input.ssh_config.PermitUserEnvironment == "no"
}

# CIS 5.2.15 - Ensure SSH warning banner is configured
ssh_banner_configured if {
    input.ssh_config.Banner != ""
    input.ssh_config.Banner != "none"
}

# Aggregate results
results := {
    "filesystem_modules": {
        "cramfs_disabled": cramfs_disabled,
        "freevxfs_disabled": freevxfs_disabled,
        "jffs2_disabled": jffs2_disabled,
        "hfs_disabled": hfs_disabled,
    },
    "ssh_configuration": {
        "sshd_config_perms": sshd_config_perms,
        "x11_forwarding_disabled": ssh_x11_disabled,
        "max_auth_tries": ssh_max_auth_tries,
        "root_login_disabled": ssh_root_login_disabled,
        "permit_user_env_disabled": ssh_user_env_disabled,
        "banner_configured": ssh_banner_configured,
    },
}

# Count passed and failed checks
passed_checks := count([check | some category, checks in results; some check, status in checks; status == true])
failed_checks := count([check | some category, checks in results; some check, status in checks; status == false])
total_checks := passed_checks + failed_checks

# Compliance score
compliance_score := (passed_checks / total_checks) * 100

# Overall compliance decision
compliant if {
    compliance_score >= 80  # 80% compliance threshold
}

# Summary report
summary := {
    "total_checks": total_checks,
    "passed": passed_checks,
    "failed": failed_checks,
    "compliance_score": compliance_score,
    "compliant": compliant,
    "results": results,
}
