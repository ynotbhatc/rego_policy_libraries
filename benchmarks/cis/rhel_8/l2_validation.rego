package cis_rhel8.l2

# CIS RHEL 8 Benchmark v4.0.0 - Level 2 Additional Controls
# Stricter controls for high-security / regulated environments.

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

violations contains "CIS L2 2.3.2: openldap-clients installed" if {
	input.packages.openldap_clients_installed
}

violations contains "CIS L2 2.3.3: ypbind (NIS client) installed" if {
	input.packages.ypbind_installed
}

violations contains "CIS L2 2.3.4: telnet client installed" if {
	input.packages.telnet_installed
}

# ---------------------------------------------------------------------------
# Section 3 - Network (L2)
# ---------------------------------------------------------------------------

violations contains "CIS L2 3.1.2: Wireless interfaces active on server" if {
	input.network.wireless_interfaces_active
}

violations contains "CIS L2 3.3.1: IPv6 router advertisements not disabled" if {
	input.sysctl["net.ipv6.conf.all.accept_ra"] != 0
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

violations contains "CIS L2 5.2.8: LoginGraceTime not configured or exceeds 60s" if {
	not sshd_config["logingracetime"]
}

violations contains "CIS L2 5.2.8: LoginGraceTime exceeds 60 seconds" if {
	to_number(sshd_config["logingracetime"]) > 60
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

compliance_report := {
	"profile":       "level2",
	"benchmark":     "CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0",
	"l2_controls":   36,
	"l2_violations": count(violations),
	"l2_compliant":  compliant,
}
