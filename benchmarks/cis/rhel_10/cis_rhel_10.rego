# METADATA
# title: "CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1 (Draft)"
# custom:
#   class: security
#   framework: cis_rhel_10
#   source: cis
#   domains: [linux, rhel]
#   coverage:
#     checks: 25
#     cited: 25
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.4.2
package cis.rhel_10

# CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1 (Draft)
# Center for Internet Security (CIS) Red Hat Enterprise Linux 10 Benchmark
# This policy implements comprehensive RHEL 10 security controls with next-generation features

import rego.v1

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

# Main compliance rule - all controls must pass
default compliant := false

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
initial_setup_checks := [
	{"msg": "UNMAPPED-RHEL10-1.2: Ensure grub config is secure (root:root, mode 0600 or stricter)", "ok": grub_config_secure},
	{"msg": "UNMAPPED-RHEL10-1.3: Ensure core dumps are restricted", "ok": core_dumps_restricted},
]

initial_setup_violations := array.concat(
[
    "1.1.1.1: Ensure mounting of squashfs filesystems is disabled" |
    not filesystem_disabled("squashfs")
],
[c.msg | some c in initial_setup_checks; not c.ok],
)

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





default grub_config_secure := false

grub_config_secure if {
    grub := input.ansible_facts.grub_config
    grub.owner == "root"
    grub.group == "root"
    mode_within(grub.mode, "0600")
}




default core_dumps_restricted := false

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
    mode_within(file.mode, expected_mode)
}














# Section 2: Services (Enhanced for RHEL 10)
services_checks := [
	{"msg": "UNMAPPED-RHEL10-2.2: Ensure mta local only is configured", "ok": mta_local_only_configured},
]

services_violations := array.concat(
[
    "2.1.1: Ensure xinetd is not installed" |
    package_installed("xinetd")
],
[c.msg | some c in services_checks; not c.ok],
)

















default mta_local_only_configured := false

mta_local_only_configured if {
    postfix := input.ansible_facts.postfix_config
    postfix.inet_interfaces == "localhost"
}











# Section 3: Network Configuration (Enhanced for RHEL 10)
network_checks := [
	{"msg": "UNMAPPED-RHEL10-3.2: Ensure nftables base chains (input, forward, output) exist", "ok": nftables_base_chains_exist},
	{"msg": "UNMAPPED-RHEL10-3.3: Ensure nftables loopback is configured", "ok": nftables_loopback_configured},
	{"msg": "UNMAPPED-RHEL10-3.4: Ensure nftables outbound is configured", "ok": nftables_outbound_configured},
	{"msg": "UNMAPPED-RHEL10-3.5: Ensure nftables default deny is configured", "ok": nftables_default_deny_configured},
]

network_violations := array.concat(
[
    "3.1.1: Verify if IPv6 is enabled on the system" |
    ipv6_enabled
    not ipv6_properly_configured
],
[c.msg | some c in network_checks; not c.ok],
)

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







default nftables_base_chains_exist := false

nftables_base_chains_exist if {
    nftables := input.ansible_facts.nftables_config
    table := nftables.tables[_]
    "input" in table.chains
    "forward" in table.chains
    "output" in table.chains
}


default nftables_loopback_configured := false

nftables_loopback_configured if {
    nftables := input.ansible_facts.nftables_config
    rule := nftables.rules[_]
    rule.interface == "lo"
    rule.action == "accept"
}


default nftables_outbound_configured := false

nftables_outbound_configured if {
    nftables := input.ansible_facts.nftables_config
    rule := nftables.rules[_]
    rule.connection_state in ["established", "related"]
    rule.action == "accept"
}


default nftables_default_deny_configured := false

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
    mode_within(log_file.mode, "0640")
    log_file.owner == "root"
}

# Section 5: Access, Authentication and Authorization (Enhanced for RHEL 10)
access_auth_checks := [
	{"msg": "UNMAPPED-RHEL10-5.2: Ensure cron access is restricted", "ok": cron_access_restricted},
	{"msg": "UNMAPPED-RHEL10-5.3: Ensure at access is restricted", "ok": at_access_restricted},
	{"msg": "UNMAPPED-RHEL10-5.4: Ensure pam faillock is configured", "ok": pam_faillock_configured},
	{"msg": "UNMAPPED-RHEL10-5.5: Ensure pam pwquality is configured", "ok": pam_pwquality_configured},
	{"msg": "UNMAPPED-RHEL10-5.6: Ensure password lockout is configured", "ok": password_lockout_configured},
	{"msg": "UNMAPPED-RHEL10-5.7: Ensure shell timeout is configured", "ok": shell_timeout_configured},
	{"msg": "UNMAPPED-RHEL10-5.8: Ensure su access is restricted", "ok": su_access_restricted},
]

access_auth_violations := array.concat(
[
    "5.1.1: Ensure cron daemon is enabled and running" |
    not cron_running_and_enabled
],
[c.msg | some c in access_auth_checks; not c.ok],
)

# Missing service evidence (no crond entry) fails closed; running AND enabled required.
default cron_running_and_enabled := false

cron_running_and_enabled if {
    service := input.ansible_facts.ansible_services["crond"]
    service.state == "running"
    service.enabled == true
}








default cron_access_restricted := false

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


default at_access_restricted := false

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











default pam_faillock_configured := false

pam_faillock_configured if {
    pam := input.ansible_facts.pam_config
    pam.faillock.deny <= 5
    pam.faillock.unlock_time >= 900
}


default pam_pwquality_configured := false

pam_pwquality_configured if {
    pam := input.ansible_facts.pam_config
    pam.pwquality.minlen >= 14
    pam.pwquality.minclass >= 4
}



default password_lockout_configured := false

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




default shell_timeout_configured := false

shell_timeout_configured if {
    timeout := input.ansible_facts.shell_timeout
    timeout <= 900
}



default su_access_restricted := false

su_access_restricted if {
    pam := input.ansible_facts.pam_config
    pam.su_restricted == true
}

# Section 6: System Maintenance (Enhanced for RHEL 10)
system_maintenance_checks := [
	{"msg": "6.1.0: evidence missing — ansible_facts.system_files not collected", "ok": system_files_collected},
	{"msg": "UNMAPPED-RHEL10-6.2: Ensure root PATH is secure", "ok": root_path_secure},
]

system_maintenance_violations := array.concat(
[
    "6.1.1: Audit system file permissions" |
    file := input.ansible_facts.system_files[_]
    not system_file_permissions_correct(file)
],
[c.msg | some c in system_maintenance_checks; not c.ok],
)

# An absent file list is not evidence that permissions are correct.
default system_files_collected := false

system_files_collected if is_array(input.ansible_facts.system_files)

system_file_permissions_correct(file) if {
    file.permissions_correct == true
}

















group_exists(gid) if {
    group := input.ansible_facts.groups[_]
    group.gid == gid
}







default root_path_secure := false

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
container_security_checks := [
	{"msg": "UNMAPPED-RHEL10-7.2: Ensure container network policies is configured", "ok": container_network_policies_configured},
]

container_security_violations := array.concat(
[
    "7.1.1: Ensure Podman is configured securely" |
    not podman_configured_securely
],
[c.msg | some c in container_security_checks; not c.ok],
)

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






default container_network_policies_configured := false

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
# Totals count the checks this module implements: one base check per section
# plus the wired checks (previously hard-coded 312/327, which did not reconcile).
section_totals := {
	"initial_setup": count(initial_setup_checks) + 1,
	"services": count(services_checks) + 1,
	"network": count(network_checks) + 1,
	"logging": 1,
	"access_auth": count(access_auth_checks) + 1,
	"system_maintenance": count(system_maintenance_checks) + 1,
	"container_security": count(container_security_checks) + 1,
	"systemd_security": 1
}

total_controls := sum([t | some t in section_totals])

compliance_summary := {
    "total_controls": total_controls,
    "passing_controls": total_controls - count(violations),
    "failing_controls": count(violations),
    "compliance_percentage": ((total_controls - count(violations)) * 100) / total_controls,
    "sections": {
        "initial_setup": {
            "total": section_totals.initial_setup,
            "violations": count(initial_setup_violations)
        },
        "services": {
            "total": section_totals.services,
            "violations": count(services_violations)
        },
        "network": {
            "total": section_totals.network,
            "violations": count(network_violations)
        },
        "logging": {
            "total": section_totals.logging,
            "violations": count(logging_violations)
        },
        "access_auth": {
            "total": section_totals.access_auth,
            "violations": count(access_auth_violations)
        },
        "system_maintenance": {
            "total": section_totals.system_maintenance,
            "violations": count(system_maintenance_violations)
        },
        "container_security": {
            "total": section_totals.container_security,
            "violations": count(container_security_violations)
        },
        "systemd_security": {
            "total": section_totals.systemd_security,
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