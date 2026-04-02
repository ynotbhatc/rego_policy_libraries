package stig.rhel_8.file_permissions

# DISA STIG for RHEL 8 - File Permissions Module
# STIG Version: V1R13 | Released: July 2024

import rego.v1

default compliant := false

# =============================================================================
# CAT I
# =============================================================================

# RHEL-08-010200 | V-230264 | CAT I - No world-writable files
default no_world_writable := false
no_world_writable if { not input.file_permissions.world_writable_files }
no_world_writable if { count(input.file_permissions.world_writable_files) == 0 }

status_rhel_08_010200 := "Not_a_Finding" if { no_world_writable } else := "Open"
finding_rhel_08_010200 := {
	"vuln_id": "V-230264",
	"stig_id": "RHEL-08-010200",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must have no world-writable files",
	"status": status_rhel_08_010200,
	"fix_text": "find / -xdev -type f -perm -002 -exec chmod o-w {} \\;",
}

# RHEL-08-010210 | V-230265 | CAT I - No unowned files
default no_unowned := false
no_unowned if { not input.file_permissions.unowned_files }
no_unowned if { count(input.file_permissions.unowned_files) == 0 }

status_rhel_08_010210 := "Not_a_Finding" if { no_unowned } else := "Open"
finding_rhel_08_010210 := {
	"vuln_id": "V-230265",
	"stig_id": "RHEL-08-010210",
	"severity": "CAT I",
	"rule_title": "RHEL 8 must have no files not owned by a valid user",
	"status": status_rhel_08_010210,
	"fix_text": "find / -nouser -xdev",
}

# =============================================================================
# CAT II
# =============================================================================

# RHEL-08-010220 | V-230266 | CAT II - /etc/passwd permissions 0644
default passwd_perms := false
passwd_perms if { input.file_permissions.etc_passwd.mode == "0644" }
passwd_perms if { input.file_permissions.etc_passwd.mode == "644" }

status_rhel_08_010220 := "Not_a_Finding" if { passwd_perms } else := "Open"
finding_rhel_08_010220 := {
	"vuln_id": "V-230266",
	"stig_id": "RHEL-08-010220",
	"severity": "CAT II",
	"rule_title": "RHEL 8 /etc/passwd must have mode 0644 or less",
	"status": status_rhel_08_010220,
	"fix_text": "chmod 0644 /etc/passwd",
}

# RHEL-08-010230 | V-230267 | CAT II - /etc/shadow permissions 0000
default shadow_perms := false
shadow_perms if { input.file_permissions.etc_shadow.mode == "0000" }
shadow_perms if { input.file_permissions.etc_shadow.mode == "000" }

status_rhel_08_010230 := "Not_a_Finding" if { shadow_perms } else := "Open"
finding_rhel_08_010230 := {
	"vuln_id": "V-230267",
	"stig_id": "RHEL-08-010230",
	"severity": "CAT II",
	"rule_title": "RHEL 8 /etc/shadow must have mode 0000",
	"status": status_rhel_08_010230,
	"fix_text": "chmod 0000 /etc/shadow",
}

# RHEL-08-010240 | V-230268 | CAT II - /etc/group permissions 0644
default group_perms := false
group_perms if { input.file_permissions.etc_group.mode == "0644" }
group_perms if { input.file_permissions.etc_group.mode == "644" }

status_rhel_08_010240 := "Not_a_Finding" if { group_perms } else := "Open"
finding_rhel_08_010240 := {
	"vuln_id": "V-230268",
	"stig_id": "RHEL-08-010240",
	"severity": "CAT II",
	"rule_title": "RHEL 8 /etc/group must have mode 0644 or less",
	"status": status_rhel_08_010240,
	"fix_text": "chmod 0644 /etc/group",
}

# RHEL-08-010250 | V-230269 | CAT II - No undocumented SUID files
default no_suid_issues := false
no_suid_issues if { not input.file_permissions.undocumented_suid_files }
no_suid_issues if { count(input.file_permissions.undocumented_suid_files) == 0 }

status_rhel_08_010250 := "Not_a_Finding" if { no_suid_issues } else := "Open"
finding_rhel_08_010250 := {
	"vuln_id": "V-230269",
	"stig_id": "RHEL-08-010250",
	"severity": "CAT II",
	"rule_title": "RHEL 8 must have no unauthorized SUID/SGID executables",
	"status": status_rhel_08_010250,
	"fix_text": "find / -xdev -perm /6000 -type f",
}

# RHEL-08-010260 | V-230270 | CAT II - Library files permissions 0755
default lib_perms := false
lib_perms if { input.file_permissions.library_files_ok == true }

status_rhel_08_010260 := "Not_a_Finding" if { lib_perms } else := "Open"
finding_rhel_08_010260 := {
	"vuln_id": "V-230270",
	"stig_id": "RHEL-08-010260",
	"severity": "CAT II",
	"rule_title": "RHEL 8 library files must have mode 0755 or less",
	"status": status_rhel_08_010260,
	"fix_text": "find /lib /lib64 /usr/lib -perm /022 -exec chmod 755 {} \\;",
}

# RHEL-08-010270 | V-230271 | CAT II - Home directory permissions
default home_perms := false
home_perms if { not input.file_permissions.insecure_home_dirs }
home_perms if { count(input.file_permissions.insecure_home_dirs) == 0 }

status_rhel_08_010270 := "Not_a_Finding" if { home_perms } else := "Open"
finding_rhel_08_010270 := {
	"vuln_id": "V-230271",
	"stig_id": "RHEL-08-010270",
	"severity": "CAT II",
	"rule_title": "RHEL 8 home directories must have mode 0750 or less",
	"status": status_rhel_08_010270,
	"fix_text": "chmod 0750 /home/<username>",
}

# =============================================================================
# COMPLIANCE AGGREGATION
# =============================================================================

cat_i_findings := [
	finding_rhel_08_010200,
	finding_rhel_08_010210,
]

cat_ii_findings := [
	finding_rhel_08_010220,
	finding_rhel_08_010230,
	finding_rhel_08_010240,
	finding_rhel_08_010250,
	finding_rhel_08_010260,
	finding_rhel_08_010270,
]

findings := array.concat(cat_i_findings, cat_ii_findings)

violations contains finding.stig_id if {
	some finding in findings
	finding.status == "Open"
}

open_cat_i contains f if {
	some f in cat_i_findings
	f.status == "Open"
}

compliant if { count(open_cat_i) == 0 }

compliance_report := {
	"module": "file_permissions",
	"total_findings": count(findings),
	"open_findings": count(violations),
	"cat_i_open": count(open_cat_i),
	"findings": findings,
	"compliant": compliant,
}
