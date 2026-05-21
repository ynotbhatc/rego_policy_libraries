package cis_ubuntu_2204.l2

# CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0 - Level 2 Additional Controls
# Level 2 extends Level 1 with stricter settings suited for high-security
# environments (FedRAMP High, CMMC Level 2/3, DoD, financial services).

import rego.v1

default compliant := false

compliant if { count(violations) == 0 }

# ---------------------------------------------------------------------------
# Section 1.1 - Filesystem (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 1.1.1.2: freevxfs module not disabled" if {
	not input.kernel_modules.freevxfs_disabled
}

violations contains "CIS L2 1.1.1.3: jffs2 module not disabled" if {
	not input.kernel_modules.jffs2_disabled
}

violations contains "CIS L2 1.1.1.4: hfs module not disabled" if {
	not input.kernel_modules.hfs_disabled
}

violations contains "CIS L2 1.1.1.5: hfsplus module not disabled" if {
	not input.kernel_modules.hfsplus_disabled
}

violations contains "CIS L2 1.1.1.6: squashfs module not disabled" if {
	not input.kernel_modules.squashfs_disabled
}

violations contains "CIS L2 1.1.1.7: udf module not disabled" if {
	not input.kernel_modules.udf_disabled
}

violations contains "CIS L2 1.1.2.1: /tmp not on a separate partition" if {
	not input.mounts.tmp_separate_partition
}

violations contains "CIS L2 1.1.2.2: /tmp not mounted with nodev" if {
	input.mounts.tmp_separate_partition
	not input.mounts.tmp_nodev
}

violations contains "CIS L2 1.1.2.3: /tmp not mounted with nosuid" if {
	input.mounts.tmp_separate_partition
	not input.mounts.tmp_nosuid
}

violations contains "CIS L2 1.1.2.4: /tmp not mounted with noexec" if {
	input.mounts.tmp_separate_partition
	not input.mounts.tmp_noexec
}

violations contains "CIS L2 1.1.3.1: /var not on a separate partition" if {
	not input.mounts.var_separate_partition
}

violations contains "CIS L2 1.1.4.1: /var/tmp not on a separate partition" if {
	not input.mounts.var_tmp_separate_partition
}

violations contains "CIS L2 1.1.5.1: /var/log not on a separate partition" if {
	not input.mounts.var_log_separate_partition
}

violations contains "CIS L2 1.1.6.1: /var/log/audit not on a separate partition" if {
	not input.mounts.var_log_audit_separate_partition
}

violations contains "CIS L2 1.1.7.1: /home not on a separate partition" if {
	not input.mounts.home_separate_partition
}

violations contains "CIS L2 1.1.7.2: /home not mounted with nodev" if {
	input.mounts.home_separate_partition
	not input.mounts.home_nodev
}

# ---------------------------------------------------------------------------
# Section 1.3 - AppArmor (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 1.3.1: AppArmor not installed" if {
	not input.apparmor.installed
}

violations contains "CIS L2 1.3.2: AppArmor not enabled at boot" if {
	not input.apparmor.enabled_at_boot
}

violations contains "CIS L2 1.3.3: Not all AppArmor profiles loaded in enforce mode" if {
	input.apparmor.profiles_unconfined_count > 0
}

# ---------------------------------------------------------------------------
# Section 1.5 - Process Hardening (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 1.5.4: Core dumps not restricted (fs.suid_dumpable != 0)" if {
	input.kernel.suid_dumpable != 0
}

violations contains "CIS L2 1.5.4: Hard core dump limit not set to 0 in limits.conf" if {
	not input.kernel.core_hard_limit_zero
}

# ---------------------------------------------------------------------------
# Section 2 - Services (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 2.3.1: ftp client installed" if {
	input.packages.ftp_installed
}

violations contains "CIS L2 2.3.2: ldap-utils (LDAP client) installed" if {
	input.packages.ldap_utils_installed
}

violations contains "CIS L2 2.3.3: nis (NIS client) installed" if {
	input.packages.nis_installed
}

violations contains "CIS L2 2.3.4: telnet client installed" if {
	input.packages.telnet_installed
}

violations contains "CIS L2 2.3.5: rsh-client installed" if {
	input.packages.rsh_client_installed
}

# ---------------------------------------------------------------------------
# Section 3 - Network (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 3.1.2: Wireless interfaces active on server" if {
	input.network.wireless_interfaces_active
}

violations contains "CIS L2 3.3.1: IPv6 router advertisements not disabled (all)" if {
	input.sysctl["net.ipv6.conf.all.accept_ra"] != 0
}

violations contains "CIS L2 3.3.1: IPv6 router advertisements not disabled (default)" if {
	input.sysctl["net.ipv6.conf.default.accept_ra"] != 0
}

violations contains "CIS L2 3.3.2: IPv6 redirects accepted" if {
	input.sysctl["net.ipv6.conf.all.accept_redirects"] != 0
}

# ---------------------------------------------------------------------------
# Section 4 - Audit (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 4.1.3.1: Audit rule for /usr/bin/chsh missing" if {
	not contains(concat("\n", input.auditd.rules), "/usr/bin/chsh")
}

violations contains "CIS L2 4.1.3.2: Audit rule for /usr/bin/newgrp missing" if {
	not contains(concat("\n", input.auditd.rules), "/usr/bin/newgrp")
}

violations contains "CIS L2 4.1.3.3: Audit rule for /usr/bin/chage missing" if {
	not contains(concat("\n", input.auditd.rules), "/usr/bin/chage")
}

violations contains "CIS L2 4.1.3.4: Audit rule for /usr/sbin/usermod missing" if {
	not contains(concat("\n", input.auditd.rules), "/usr/sbin/usermod")
}

violations contains "CIS L2 4.1.4.1: File deletion events not audited" if {
	not contains(concat("\n", input.auditd.rules), "delete")
}

violations contains "CIS L2 4.1.5: sudoers changes not audited" if {
	not contains(concat("\n", input.auditd.rules), "/etc/sudoers")
}

# ---------------------------------------------------------------------------
# Section 5.2 - SSH (L2)
# ---------------------------------------------------------------------------

sshd_config := {key: lower(trim_space(value)) |
	some line in split(input.ssh.sshd_config_raw, "\n")
	trimmed := trim_space(line)
	not startswith(trimmed, "#")
	trimmed != ""
	parts := split(trimmed, " ")
	count(parts) >= 2
	key := lower(parts[0])
	value := concat(" ", array.slice(parts, 1, count(parts)))
}

violations contains "CIS L2 5.2.7: AllowTcpForwarding not set to 'no'" if {
	sshd_config["allowtcpforwarding"] != "no"
}

violations contains "CIS L2 5.2.8: LoginGraceTime not configured" if {
	not sshd_config["logingracetime"]
}

violations contains "CIS L2 5.2.8: LoginGraceTime exceeds 60 seconds" if {
	to_number(sshd_config["logingracetime"]) > 60
}

violations contains "CIS L2 5.2.22: MaxSessions exceeds 10" if {
	to_number(sshd_config["maxsessions"]) > 10
}

# ---------------------------------------------------------------------------
# Section 5.4 - PAM (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 5.4.1.5: INACTIVE password lock not configured" if {
	not input.pam.inactive_lock_days
}

violations contains sprintf("CIS L2 5.4.1.5: INACTIVE lock is %v days (max 30)", [input.pam.inactive_lock_days]) if {
	to_number(input.pam.inactive_lock_days) > 30
}

# ---------------------------------------------------------------------------
# Section 6 - File Integrity (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 6.1.11: Unowned files found on filesystem" if {
	count(input.file_system.unowned_files) > 0
}

violations contains "CIS L2 6.1.12: Ungrouped files found on filesystem" if {
	count(input.file_system.ungrouped_files) > 0
}

violations contains "CIS L2 6.1.13: Unexpected SUID executables found" if {
	count(input.file_system.unexpected_suid_files) > 0
}

violations contains "CIS L2 6.1.14: Unexpected SGID executables found" if {
	count(input.file_system.unexpected_sgid_files) > 0
}

# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

l2_total_controls := 38

compliance_report := {
	"profile":           "level2",
	"benchmark":         "CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0",
	"l2_controls":       l2_total_controls,
	"l2_violations":     count(violations),
	"l2_compliant":      compliant,
	"l2_violation_list": [v | some v in violations],
	"note": "Level 2 controls supplement Level 1. A system must pass Level 1 AND Level 2 to be fully Level 2 compliant.",
}
