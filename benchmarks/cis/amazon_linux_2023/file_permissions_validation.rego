package cis_amazon_linux_2023.file_permissions

# CIS Amazon Linux 2023 Section 6.1.x - System File Permissions
# Validates critical file permissions, ownership, and special attributes

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat(
		[v | some v in critical_file_violations],
		[v | some v in world_writable_violations],
	),
	array.concat(
		[v | some v in ownership_violations],
		[v | some v in suid_sgid_violations],
	),
)

# =============================================================================
# CIS 6.1.2-6.1.9 - CRITICAL SYSTEM FILE PERMISSIONS
# =============================================================================

critical_file_violations contains violation if {
	some file in input.critical_files.analysis
	not file.fully_compliant
	file.exists
	violation := sprintf("CIS 6.1.x: Critical file '%s' has incorrect permissions (mode: %s/%s, owner: %s/%s, group: %s/%s)", [
		file.file,
		file.actual_mode,
		file.expected_mode,
		file.actual_owner,
		file.expected_owner,
		file.actual_group,
		file.expected_group,
	])
}

# Specific checks for highly critical files
critical_file_violations contains violation if {
	some file in input.critical_files.analysis
	file.file == "/etc/shadow"
	not file.mode_compliant
	violation := sprintf("CIS 6.1.6: /etc/shadow has insecure permissions (mode: %s, expected: 0000/0400/0600)", [
		file.actual_mode,
	])
}

critical_file_violations contains violation if {
	some file in input.critical_files.analysis
	file.file == "/etc/gshadow"
	not file.mode_compliant
	violation := sprintf("CIS 6.1.8: /etc/gshadow has insecure permissions (mode: %s, expected: 0000/0400/0600)", [
		file.actual_mode,
	])
}

critical_file_violations contains violation if {
	some file in input.critical_files.analysis
	file.file == "/etc/passwd"
	not file.mode_compliant
	violation := sprintf("CIS 6.1.2: /etc/passwd has incorrect permissions (mode: %s, expected: 0644)", [
		file.actual_mode,
	])
}

critical_file_violations contains violation if {
	some file in input.critical_files.analysis
	file.file == "/etc/group"
	not file.mode_compliant
	violation := sprintf("CIS 6.1.4: /etc/group has incorrect permissions (mode: %s, expected: 0644)", [
		file.actual_mode,
	])
}

# =============================================================================
# CIS 6.1.10 - WORLD-WRITABLE FILES
# =============================================================================

world_writable_violations contains violation if {
	count(input.world_writable.files) > 0
	some file in input.world_writable.files
	violation := sprintf("CIS 6.1.10: World-writable file found: %s (mode: %s, owner: %s)", [
		file.path,
		file.mode,
		file.owner,
	])
}

world_writable_violations contains violation if {
	not input.world_writable.compliant
	input.world_writable.count > 0
	violation := sprintf("CIS 6.1.10: %d world-writable files found on system", [
		input.world_writable.count,
	])
}

# =============================================================================
# CIS 6.1.11 - UNOWNED FILES
# =============================================================================

ownership_violations contains violation if {
	count(input.unowned_files.files) > 0
	some file in input.unowned_files.files
	violation := sprintf("CIS 6.1.11: Unowned file found: %s (UID: %d, mode: %s)", [
		file.path,
		file.uid,
		file.mode,
	])
}

ownership_violations contains violation if {
	not input.unowned_files.compliant
	input.unowned_files.count > 0
	violation := sprintf("CIS 6.1.11: %d unowned files found on system", [
		input.unowned_files.count,
	])
}

# =============================================================================
# CIS 6.1.12 - UNGROUPED FILES
# =============================================================================

ownership_violations contains violation if {
	count(input.ungrouped_files.files) > 0
	some file in input.ungrouped_files.files
	violation := sprintf("CIS 6.1.12: Ungrouped file found: %s (GID: %d, mode: %s)", [
		file.path,
		file.gid,
		file.mode,
	])
}

ownership_violations contains violation if {
	not input.ungrouped_files.compliant
	input.ungrouped_files.count > 0
	violation := sprintf("CIS 6.1.12: %d ungrouped files found on system", [
		input.ungrouped_files.count,
	])
}

# =============================================================================
# CIS 6.1.13 - SUID EXECUTABLES
# =============================================================================

suid_sgid_violations contains violation if {
	some file in input.suid_files.unknown_binaries
	file.review_required
	violation := sprintf("CIS 6.1.13: Unknown SUID binary requires review: %s (mode: %s, owner: %s)", [
		file.path,
		file.mode,
		file.owner,
	])
}

# Warning if too many SUID binaries
suid_sgid_violations contains violation if {
	input.suid_files.total_count > 20
	input.suid_files.unknown_count > 5
	violation := sprintf("CIS 6.1.13: Excessive unknown SUID binaries found (%d unknown out of %d total)", [
		input.suid_files.unknown_count,
		input.suid_files.total_count,
	])
}

# =============================================================================
# CIS 6.1.14 - SGID EXECUTABLES
# =============================================================================

suid_sgid_violations contains violation if {
	input.sgid_files.count > 30
	violation := sprintf("CIS 6.1.14: Excessive SGID binaries found (%d files)", [
		input.sgid_files.count,
	])
}

# =============================================================================
# SSH PRIVATE KEY PERMISSIONS
# =============================================================================

critical_file_violations contains violation if {
	some key in input.ssh_private_keys.analysis
	not key.fully_compliant
	violation := sprintf("SSH Private Key: %s has insecure permissions (mode: %s, owner: %s)", [
		key.path,
		key.mode,
		key.owner,
	])
}

critical_file_violations contains violation if {
	not input.ssh_private_keys.all_compliant
	violation := "SSH Private Keys: One or more SSH host keys have insecure permissions"
}

# =============================================================================
# COMPLIANCE CHECKS
# =============================================================================

compliance_summary := {
	"critical_files_correct": input.compliance_checks.critical_files_correct,
	"no_world_writable_files": input.compliance_checks.no_world_writable_files,
	"no_unowned_files": input.compliance_checks.no_unowned_files,
	"no_ungrouped_files": input.compliance_checks.no_ungrouped_files,
	"suid_files_reviewed": input.compliance_checks.suid_files_reviewed,
	"ssh_keys_secure": input.compliance_checks.ssh_keys_secure,
	"overall_compliant": count(violations) == 0,
}

# =============================================================================
# DETAILED REPORTING
# =============================================================================

# Critical files with issues
non_compliant_critical_files contains file if {
	some f in input.critical_files.analysis
	not f.fully_compliant
	file := {
		"file": f.file,
		"actual_mode": f.actual_mode,
		"expected_mode": f.expected_mode,
		"actual_owner": f.actual_owner,
		"expected_owner": f.expected_owner,
		"mode_compliant": f.mode_compliant,
		"owner_compliant": f.owner_compliant,
		"group_compliant": f.group_compliant,
	}
}

# SUID binary summary
suid_summary := {
	"total_count": input.suid_files.total_count,
	"known_count": input.suid_files.known_count,
	"unknown_count": input.suid_files.unknown_count,
	"requires_review": input.suid_files.requires_review,
	"unknown_binaries": [path |
		some file in input.suid_files.unknown_binaries
		path := file.path
	],
}

# Security risk summary
security_risks := {
	"world_writable_files": input.world_writable.count,
	"unowned_files": input.unowned_files.count,
	"ungrouped_files": input.ungrouped_files.count,
	"unknown_suid_binaries": input.suid_files.unknown_count,
	"sgid_binaries": input.sgid_files.count,
	"non_compliant_critical_files": input.critical_files.non_compliant_count,
}

# Overall risk level
risk_level := "critical" if {
	input.world_writable.count > 0
} else := "critical" if {
	input.critical_files.non_compliant_count > 0
} else := "high" if {
	input.suid_files.unknown_count > 5
} else := "medium" if {
	input.unowned_files.count > 0
} else := "medium" if {
	input.ungrouped_files.count > 0
} else := "low"

report := {
	"compliant": compliant,
	"risk_level": risk_level,
	"total_violations": count(violations),
	"violations": violations,
	"compliance_summary": compliance_summary,
	"security_risks": security_risks,
	"non_compliant_critical_files": non_compliant_critical_files,
	"suid_summary": suid_summary,
	"collection_timestamp": input.collection_timestamp,
}

