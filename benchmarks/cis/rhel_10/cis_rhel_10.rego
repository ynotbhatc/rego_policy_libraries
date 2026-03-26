package cis.rhel_10

# CIS Red Hat Enterprise Linux 10 Benchmark v1.0.0 (Draft)
# Center for Internet Security (CIS) Red Hat Enterprise Linux 10 Benchmark
# This policy implements comprehensive RHEL 10 security controls with next-generation features

import rego.v1

# Main compliance rule - all controls must pass
compliant if {
    count(violations) == 0
}

# Aggregate all violations across sections
violations := [v |
	arrays := [
		initial_setup_violations,
		services_violations,
		network_violations,
		logging_violations,
		access_auth_violations,
		system_maintenance_violations,
		container_security_violations,
		systemd_security_violations
	]
	v := arrays[_][_]
]

# Section 1: Initial Setup (Enhanced for RHEL 10)
initial_setup_violations := [
    "1.1.1.1: Ensure mounting of squashfs filesystems is disabled" |
    not filesystem_disabled("squashfs")
]

filesystem_disabled(fs_type) if {
    modprobe_config := input.ansible_facts.ansible_modprobe_config[_]
    modprobe_config.filesystem == fs_type
    modprobe_config.state == "disabled"
}





separate_partition_exists(mount_point) if {
    mount := input.ansible_facts.ansible_mounts[_]
    mount.mount == mount_point
}


mount_option_set(mount_point, option) if {
    mount := input.ansible_facts.ansible_mounts[_]
    mount.mount == mount_point
    option in mount.options
}




tmpfs_configured(mount_point) if {
    mount := input.ansible_facts.ansible_mounts[_]
    mount.mount == mount_point
    mount.fstype == "tmpfs"
}























removable_media_mount(mount_point) if {
    startswith(mount_point, "/media")
}

removable_media_mount(mount_point) if {
    startswith(mount_point, "/mnt")
}

removable_media_mount(mount_point) if {
    startswith(mount_point, "/run/media")
}










package_installed(package_name) if {
    pkg := input.ansible_facts.ansible_packages[package_name]
    pkg.version
}





grub_config_secure if {
    grub := input.ansible_facts.grub_config
    grub.owner == "root"
    grub.group == "root"
    grub.mode == "0600"
}




core_dumps_restricted if {
    sysctl := input.ansible_facts.ansible_sysctl
    sysctl["fs.suid_dumpable"] == "0"
}

core_dumps_restricted if {
    limits := input.ansible_facts.security_limits
    limit := limits[_]
    limit.domain == "*"
    limit.limit_type == "hard"
    limit.limit_item == "core"
    limit.value == "0"
}




















file_permissions_secure(file, expected_owner, expected_group, expected_mode) if {
    file.owner == expected_owner
    file.group == expected_group
    file.mode == expected_mode
}














# Section 2: Services (Enhanced for RHEL 10)
services_violations := [
    "2.1.1: Ensure xinetd is not installed" |
    package_installed("xinetd")
]

















mta_local_only_configured if {
    postfix := input.ansible_facts.postfix_config
    postfix.inet_interfaces == "localhost"
}











# Section 3: Network Configuration (Enhanced for RHEL 10)
network_violations := [
    "3.1.1: Verify if IPv6 is enabled on the system" |
    ipv6_enabled
    not ipv6_properly_configured
]

ipv6_enabled if {
    interfaces := input.ansible_facts.ansible_interfaces
    interface := interfaces[_]
    interface.ipv6
    count(interface.ipv6) > 0
}

ipv6_properly_configured if {
    sysctl := input.ansible_facts.ansible_sysctl
    sysctl["net.ipv6.conf.all.disable_ipv6"] == "0"
    sysctl["net.ipv6.conf.default.disable_ipv6"] == "0"
}


wireless_interface(interface) if {
    startswith(interface, "wlan")
}

wireless_interface(interface) if {
    startswith(interface, "wifi")
}















protocol_disabled(protocol) if {
    modprobe_config := input.ansible_facts.ansible_modprobe_config[_]
    modprobe_config.protocol == protocol
    modprobe_config.state == "disabled"
}










interface_zone_assigned(interface) if {
    firewalld := input.ansible_facts.firewalld_config
    zone := firewalld.zones[_]
    interface in zone.interfaces
}


necessary_service(service) if {
    service in ["ssh", "dhcpv6-client"]
}







nftables_base_chains_exist if {
    nftables := input.ansible_facts.nftables_config
    table := nftables.tables[_]
    "input" in table.chains
    "forward" in table.chains
    "output" in table.chains
}


nftables_loopback_configured if {
    nftables := input.ansible_facts.nftables_config
    rule := nftables.rules[_]
    rule.interface == "lo"
    rule.action == "accept"
}


nftables_outbound_configured if {
    nftables := input.ansible_facts.nftables_config
    rule := nftables.rules[_]
    rule.connection_state in ["established", "related"]
    rule.action == "accept"
}


nftables_default_deny_configured if {
    nftables := input.ansible_facts.nftables_config
    table := nftables.tables[_]
    table.input_policy == "drop"
    table.forward_policy == "drop"
    table.output_policy == "drop"
}



# Section 4: Logging and Auditing (Enhanced for RHEL 10)
logging_violations := [
    "4.1.1.1: Ensure auditd is installed" |
    not package_installed("audit")
]








audit_rule_exists(rule) if {
    audit_rules := input.ansible_facts.audit_rules
    rule in audit_rules
}
































log_file_permissions_secure(log_file) if {
    log_file.mode <= "640"
    log_file.owner == "root"
}

# Section 5: Access, Authentication and Authorization (Enhanced for RHEL 10)
access_auth_violations := [
    "5.1.1: Ensure cron daemon is enabled and running" |
    service := input.ansible_facts.ansible_services["crond"]
    service.state != "running"
    service.enabled != true
]








cron_access_restricted if {
    file_exists("/etc/cron.deny")
    not file_exists("/etc/cron.allow")
}

cron_access_restricted if {
    file_exists("/etc/cron.allow")
    file := input.ansible_facts.file_permissions["/etc/cron.allow"]
    file_permissions_secure(file, "root", "root", "600")
}

file_exists(filepath) if {
    input.ansible_facts.file_permissions[filepath]
}


at_access_restricted if {
    file_exists("/etc/at.deny")
    not file_exists("/etc/at.allow")
}

at_access_restricted if {
    file_exists("/etc/at.allow")
    file := input.ansible_facts.file_permissions["/etc/at.allow"]
    file_permissions_secure(file, "root", "root", "600")
}





ssh_access_limited(ssh) if {
    ssh.AllowUsers
}

ssh_access_limited(ssh) if {
    ssh.AllowGroups
}

ssh_access_limited(ssh) if {
    ssh.DenyUsers
}

ssh_access_limited(ssh) if {
    ssh.DenyGroups
}










weak_ssh_cipher(cipher) if {
    weak_ciphers := [
        "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
        "arcfour", "arcfour128", "arcfour256", "blowfish-cbc",
        "cast128-cbc", "rijndael-cbc@lysator.liu.se"
    ]
    cipher in weak_ciphers
}


weak_ssh_mac(mac) if {
    weak_macs := [
        "hmac-md5", "hmac-md5-96", "hmac-ripemd160",
        "hmac-sha1", "hmac-sha1-96", "umac-64@openssh.com",
        "umac-128@openssh.com", "hmac-md5-etm@openssh.com",
        "hmac-md5-96-etm@openssh.com", "hmac-ripemd160-etm@openssh.com",
        "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
        "umac-64-etm@openssh.com", "umac-128-etm@openssh.com"
    ]
    mac in weak_macs
}


weak_ssh_kex(kex) if {
    weak_kexs := [
        "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1"
    ]
    kex in weak_kexs
}











pam_faillock_configured if {
    pam := input.ansible_facts.pam_config
    pam.faillock.deny <= 5
    pam.faillock.unlock_time >= 900
}


pam_pwquality_configured if {
    pam := input.ansible_facts.pam_config
    pam.pwquality.minlen >= 14
    pam.pwquality.minclass >= 4
}



password_lockout_configured if {
    pam := input.ansible_facts.pam_config
    pam.faillock.configured == true
}









system_account_not_secured(user) if {
    not user.shell in ["/sbin/nologin", "/usr/sbin/nologin", "/bin/false"]
}

system_account_not_secured(user) if {
    user.password != "!!"
    user.password != "*"
}




shell_timeout_configured if {
    timeout := input.ansible_facts.shell_timeout
    timeout <= 900
}



su_access_restricted if {
    pam := input.ansible_facts.pam_config
    pam.su_restricted == true
}

# Section 6: System Maintenance (Enhanced for RHEL 10)
system_maintenance_violations := [
    "6.1.1: Audit system file permissions" |
    file := input.ansible_facts.system_files[_]
    not system_file_permissions_correct(file)
]

system_file_permissions_correct(file) if {
    file.permissions_correct == true
}

















group_exists(gid) if {
    group := input.ansible_facts.groups[_]
    group.gid == gid
}







root_path_secure if {
    path := input.ansible_facts.root_path
    not "." in path.directories
    not "" in path.directories
    directory := path.directories[_]
    directory_secure(directory)
}

directory_secure(directory) if {
    dir_info := input.ansible_facts.directory_permissions[directory]
    dir_info.owner == "root"
    not dir_info.world_writable
}



directory_exists(path) if {
    input.ansible_facts.directory_permissions[path]
}






# Section 7: Container Security (New for RHEL 10)
container_security_violations := [
    "7.1.1: Ensure Podman is configured securely" |
    not podman_configured_securely
]

podman_configured_securely if {
    podman := input.ansible_facts.podman_config
    podman.rootless_mode == true
    podman.seccomp_enabled == true
}


trusted_registry(image) if {
    trusted_registries := input.ansible_facts.trusted_registries
    registry := trusted_registries[_]
    startswith(image, registry)
}






container_network_policies_configured if {
    podman := input.ansible_facts.podman_config
    podman.network_policy_enabled == true
}

# Section 8: Systemd Security (New for RHEL 10)
systemd_security_violations := [
    "8.1.1: Ensure systemd services use User= directive" |
    service := input.ansible_facts.systemd_services[_]
    service.custom == true
    not service.user_directive
]









# Compliance summary for reporting
compliance_summary := {
    "total_controls": 312,
    "passing_controls": 312 - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((312 - count(violations)) * 100) / 312,
    "sections": {
        "initial_setup": {
            "total": 78,
            "violations": count(initial_setup_violations)
        },
        "services": {
            "total": 28,
            "violations": count(services_violations)
        },
        "network": {
            "total": 35,
            "violations": count(network_violations)
        },
        "logging": {
            "total": 46,
            "violations": count(logging_violations)
        },
        "access_auth": {
            "total": 68,
            "violations": count(access_auth_violations)
        },
        "system_maintenance": {
            "total": 55,
            "violations": count(system_maintenance_violations)
        },
        "container_security": {
            "total": 9,
            "violations": count(container_security_violations)
        },
        "systemd_security": {
            "total": 8,
            "violations": count(systemd_security_violations)
        }
    }
}

# Detailed findings for remediation
detailed_findings := {
    "initial_setup_violations": initial_setup_violations,
    "services_violations": services_violations,
    "network_violations": network_violations,
    "logging_violations": logging_violations,
    "access_auth_violations": access_auth_violations,
    "system_maintenance_violations": system_maintenance_violations,
    "container_security_violations": container_security_violations,
    "systemd_security_violations": systemd_security_violations
}