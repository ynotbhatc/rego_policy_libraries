package cis_rhel9.l2

# CIS RHEL 9 Benchmark v2.0.0 - Level 2 Additional Controls
# Level 2 extends Level 1 with stricter settings suited for high-security
# environments (FedRAMP High, CMMC Level 2/3, DoD, financial services).
# These controls may impact functionality or system performance.
#
# Profile: Level 2 (includes all Level 1 controls plus these additions)
# Use case: Regulated industries, federal, defense, PCI-DSS, HIPAA

import rego.v1

default compliant := false

compliant if { count(violations) == 0 }

# ---------------------------------------------------------------------------
# Section 1.1 - Filesystem (L2 additions)
# ---------------------------------------------------------------------------

# CIS 1.1.1.2 L2: freevxfs filesystem disabled
violations contains "CIS L2 1.1.1.2: freevxfs filesystem module not disabled" if {
	not input.kernel_modules.freevxfs_disabled
}

# CIS 1.1.1.3 L2: jffs2 filesystem disabled
violations contains "CIS L2 1.1.1.3: jffs2 filesystem module not disabled" if {
	not input.kernel_modules.jffs2_disabled
}

# CIS 1.1.1.4 L2: hfs filesystem disabled
violations contains "CIS L2 1.1.1.4: hfs filesystem module not disabled" if {
	not input.kernel_modules.hfs_disabled
}

# CIS 1.1.1.5 L2: hfsplus filesystem disabled
violations contains "CIS L2 1.1.1.5: hfsplus filesystem module not disabled" if {
	not input.kernel_modules.hfsplus_disabled
}

# CIS 1.1.1.6 L2: squashfs filesystem disabled
violations contains "CIS L2 1.1.1.6: squashfs filesystem module not disabled" if {
	not input.kernel_modules.squashfs_disabled
}

# CIS 1.1.1.7 L2: udf filesystem disabled
violations contains "CIS L2 1.1.1.7: udf filesystem module not disabled" if {
	not input.kernel_modules.udf_disabled
}

# CIS 1.1.2.x L2: /tmp on separate partition with nodev,nosuid,noexec
violations contains "CIS L2 1.1.2.1: /tmp is not on a separate partition" if {
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

# CIS 1.1.3.x L2: /var on separate partition
violations contains "CIS L2 1.1.3.1: /var is not on a separate partition" if {
	not input.mounts.var_separate_partition
}

# CIS 1.1.4.x L2: /var/tmp on separate partition
violations contains "CIS L2 1.1.4.1: /var/tmp is not on a separate partition" if {
	not input.mounts.var_tmp_separate_partition
}

# CIS 1.1.5.x L2: /var/log on separate partition
violations contains "CIS L2 1.1.5.1: /var/log is not on a separate partition" if {
	not input.mounts.var_log_separate_partition
}

# CIS 1.1.6.x L2: /var/log/audit on separate partition
violations contains "CIS L2 1.1.6.1: /var/log/audit is not on a separate partition" if {
	not input.mounts.var_log_audit_separate_partition
}

# CIS 1.1.7.x L2: /home on separate partition
violations contains "CIS L2 1.1.7.1: /home is not on a separate partition" if {
	not input.mounts.home_separate_partition
}

violations contains "CIS L2 1.1.7.2: /home not mounted with nodev" if {
	input.mounts.home_separate_partition
	not input.mounts.home_nodev
}

# ---------------------------------------------------------------------------
# Section 1.5 - Process Hardening (L2 additions)
# ---------------------------------------------------------------------------

# CIS 1.5.4 L2: Core dumps restricted for setuid programs
violations contains "CIS L2 1.5.4: Core dumps not restricted (fs.suid_dumpable != 0)" if {
	input.kernel.suid_dumpable != 0
}

# CIS 1.5.4 L2: Core dump hard limit set to 0 in limits.conf
violations contains "CIS L2 1.5.4: Hard core dump limit not set to 0 in /etc/security/limits.conf" if {
	not input.kernel.core_hard_limit_zero
}

# ---------------------------------------------------------------------------
# Section 2 - Services (L2 additions — additional service removal)
# ---------------------------------------------------------------------------

# CIS 2.3.x L2: Non-essential clients not installed
violations contains "CIS L2 2.3.1: ftp client is installed" if {
	input.packages.ftp_installed
}

violations contains "CIS L2 2.3.2: openldap-clients is installed" if {
	input.packages.openldap_clients_installed
}

violations contains "CIS L2 2.3.3: ypbind (NIS client) is installed" if {
	input.packages.ypbind_installed
}

violations contains "CIS L2 2.3.4: telnet client is installed" if {
	input.packages.telnet_installed
}

# ---------------------------------------------------------------------------
# Section 3 - Network (L2 additions)
# ---------------------------------------------------------------------------

# CIS 3.1.2 L2: Wireless interfaces disabled
violations contains "CIS L2 3.1.2: Wireless interfaces are active (should be disabled on servers)" if {
	input.network.wireless_interfaces_active
}

# CIS 3.3.x L2: Additional IPv6 kernel parameters
violations contains "CIS L2 3.3.1: IPv6 router advertisements not disabled (net.ipv6.conf.all.accept_ra != 0)" if {
	input.sysctl["net.ipv6.conf.all.accept_ra"] != 0
}

violations contains "CIS L2 3.3.1: IPv6 router advertisements not disabled on default interface" if {
	input.sysctl["net.ipv6.conf.default.accept_ra"] != 0
}

violations contains "CIS L2 3.3.2: IPv6 redirects accepted (net.ipv6.conf.all.accept_redirects != 0)" if {
	input.sysctl["net.ipv6.conf.all.accept_redirects"] != 0
}

# ---------------------------------------------------------------------------
# Section 4 - Audit (L2 additions — additional audit rules)
# ---------------------------------------------------------------------------

# CIS 4.1.3.x L2: Additional audit rules for privileged commands
violations contains "CIS L2 4.1.3.1: Audit rule for /usr/bin/chsh not configured" if {
	audit_rules := input.auditd.rules
	not contains(concat("\n", audit_rules), "/usr/bin/chsh")
}

violations contains "CIS L2 4.1.3.2: Audit rule for /usr/bin/newgrp not configured" if {
	audit_rules := input.auditd.rules
	not contains(concat("\n", audit_rules), "/usr/bin/newgrp")
}

violations contains "CIS L2 4.1.3.3: Audit rule for /usr/bin/chage not configured" if {
	audit_rules := input.auditd.rules
	not contains(concat("\n", audit_rules), "/usr/bin/chage")
}

violations contains "CIS L2 4.1.3.4: Audit rule for /usr/sbin/usermod not configured" if {
	audit_rules := input.auditd.rules
	not contains(concat("\n", audit_rules), "/usr/sbin/usermod")
}

violations contains "CIS L2 4.1.3.5: Audit rule for /usr/bin/gpasswd not configured" if {
	audit_rules := input.auditd.rules
	not contains(concat("\n", audit_rules), "/usr/bin/gpasswd")
}

# CIS 4.1.4.x L2: File deletion events audited
violations contains "CIS L2 4.1.4.1: File deletion events (unlink, rename, rmdir) not audited" if {
	audit_rules := input.auditd.rules
	not contains(concat("\n", audit_rules), "delete")
}

# CIS 4.1.5 L2: Sudoers changes audited
violations contains "CIS L2 4.1.5: Changes to sudoers not audited (/etc/sudoers)" if {
	audit_rules := input.auditd.rules
	not contains(concat("\n", audit_rules), "/etc/sudoers")
}

# ---------------------------------------------------------------------------
# Section 5.2 - SSH (L2 additions)
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

# CIS 5.2.7 L2: SSH AllowTcpForwarding disabled
violations contains "CIS L2 5.2.7: AllowTcpForwarding is not set to 'no' — TCP forwarding should be disabled" if {
	sshd_config["allowtcpforwarding"] != "no"
}

# CIS 5.2.8 L2: SSH LoginGraceTime set to 60 or less
violations contains "CIS L2 5.2.8: LoginGraceTime not configured or exceeds 60 seconds" if {
	val := to_number(sshd_config["logingracetime"])
	val > 60
}

violations contains "CIS L2 5.2.8: LoginGraceTime not configured" if {
	not sshd_config["logingracetime"]
}

# CIS 5.2.22 L2: SSH MaxSessions set to 10 or less
violations contains "CIS L2 5.2.22: MaxSessions exceeds 10" if {
	val := to_number(sshd_config["maxsessions"])
	val > 10
}

# ---------------------------------------------------------------------------
# Section 5.4 - PAM (L2 additions)
# ---------------------------------------------------------------------------

# CIS 5.4.1.5 L2: Inactive password lock set to 30 days or less
violations contains "CIS L2 5.4.1.5: INACTIVE password lock not set (useradd -D -f 30)" if {
	not input.pam.inactive_lock_days
}

violations contains sprintf("CIS L2 5.4.1.5: INACTIVE password lock is %v days (should be 30 or less)", [input.pam.inactive_lock_days]) if {
	to_number(input.pam.inactive_lock_days) > 30
}

# ---------------------------------------------------------------------------
# Section 6.1 - File Permissions (L2 additions)
# ---------------------------------------------------------------------------

# CIS 6.1.11 L2: No unowned files
violations contains "CIS L2 6.1.11: Unowned files or directories found on the filesystem" if {
	count(input.file_system.unowned_files) > 0
}

# CIS 6.1.12 L2: No ungrouped files
violations contains "CIS L2 6.1.12: Ungrouped files or directories found on the filesystem" if {
	count(input.file_system.ungrouped_files) > 0
}

# CIS 6.1.13 L2: SUID executables reviewed
violations contains "CIS L2 6.1.13: Unexpected SUID executables found — review required" if {
	count(input.file_system.unexpected_suid_files) > 0
}

# CIS 6.1.14 L2: SGID executables reviewed
violations contains "CIS L2 6.1.14: Unexpected SGID executables found — review required" if {
	count(input.file_system.unexpected_sgid_files) > 0
}

# ---------------------------------------------------------------------------
# Compliance report
# ---------------------------------------------------------------------------

l2_total_controls := 37

compliance_report := {
	"profile":         "level2",
	"benchmark":       "CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0",
	"l2_controls":     l2_total_controls,
	"l2_violations":   count(violations),
	"l2_compliant":    compliant,
	"l2_violation_list": [v | some v in violations],
	"note": "Level 2 controls supplement Level 1. A system must pass Level 1 AND Level 2 to be fully Level 2 compliant.",
}
