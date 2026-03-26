package cis_ubuntu_22_04.file_permissions

# CIS Ubuntu 22.04 LTS Benchmark v1.0.0 - Section 6.1: System File Permissions

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in critical_file_violations], [v | some v in world_writable_violations]),
	array.concat([v | some v in ownership_violations], [v | some v in suid_sgid_violations]),
)

# CIS 6.1.x: Critical system file permissions
critical_file_violations contains msg if {
	some file in input.critical_files.analysis
	not file.fully_compliant
	file.exists
	msg := sprintf("CIS 6.1.x: Critical file '%s' has incorrect permissions (mode: %s/%s, owner: %s/%s, group: %s/%s)", [
		file.file,
		file.actual_mode, file.expected_mode,
		file.actual_owner, file.expected_owner,
		file.actual_group, file.expected_group,
	])
}

critical_file_violations contains msg if {
	some file in input.critical_files.analysis
	file.file == "/etc/shadow"
	not file.mode_compliant
	msg := sprintf("CIS 6.1.6: /etc/shadow has insecure permissions (mode: %s, expected: 0000/0400/0600)", [file.actual_mode])
}

critical_file_violations contains msg if {
	some file in input.critical_files.analysis
	file.file == "/etc/gshadow"
	not file.mode_compliant
	msg := sprintf("CIS 6.1.8: /etc/gshadow has insecure permissions (mode: %s, expected: 0000/0400/0600)", [file.actual_mode])
}

critical_file_violations contains msg if {
	some file in input.critical_files.analysis
	file.file == "/etc/passwd"
	not file.mode_compliant
	msg := sprintf("CIS 6.1.2: /etc/passwd has incorrect permissions (mode: %s, expected: 0644)", [file.actual_mode])
}

critical_file_violations contains msg if {
	some file in input.critical_files.analysis
	file.file == "/etc/group"
	not file.mode_compliant
	msg := sprintf("CIS 6.1.4: /etc/group has incorrect permissions (mode: %s, expected: 0644)", [file.actual_mode])
}

# SSH private keys
critical_file_violations contains msg if {
	some key in input.ssh_private_keys.analysis
	not key.fully_compliant
	msg := sprintf("SSH Private Key: %s has insecure permissions (mode: %s, owner: %s)", [key.path, key.mode, key.owner])
}

critical_file_violations contains msg if {
	not input.ssh_private_keys.all_compliant
	msg := "SSH Private Keys: One or more SSH host keys have insecure permissions"
}

# CIS 6.1.10: World-writable files
world_writable_violations contains msg if {
	count(input.world_writable.files) > 0
	some file in input.world_writable.files
	msg := sprintf("CIS 6.1.10: World-writable file found: %s (mode: %s, owner: %s)", [file.path, file.mode, file.owner])
}

world_writable_violations contains msg if {
	not input.world_writable.compliant
	input.world_writable.count > 0
	msg := sprintf("CIS 6.1.10: %d world-writable files found on system", [input.world_writable.count])
}

# CIS 6.1.11: Unowned files
ownership_violations contains msg if {
	count(input.unowned_files.files) > 0
	some file in input.unowned_files.files
	msg := sprintf("CIS 6.1.11: Unowned file found: %s (UID: %d, mode: %s)", [file.path, file.uid, file.mode])
}

ownership_violations contains msg if {
	not input.unowned_files.compliant
	input.unowned_files.count > 0
	msg := sprintf("CIS 6.1.11: %d unowned files found on system", [input.unowned_files.count])
}

# CIS 6.1.12: Ungrouped files
ownership_violations contains msg if {
	count(input.ungrouped_files.files) > 0
	some file in input.ungrouped_files.files
	msg := sprintf("CIS 6.1.12: Ungrouped file found: %s (GID: %d, mode: %s)", [file.path, file.gid, file.mode])
}

ownership_violations contains msg if {
	not input.ungrouped_files.compliant
	input.ungrouped_files.count > 0
	msg := sprintf("CIS 6.1.12: %d ungrouped files found on system", [input.ungrouped_files.count])
}

# CIS 6.1.13: SUID executables
suid_sgid_violations contains msg if {
	some file in input.suid_files.unknown_binaries
	file.review_required
	msg := sprintf("CIS 6.1.13: Unknown SUID binary requires review: %s (mode: %s, owner: %s)", [file.path, file.mode, file.owner])
}

suid_sgid_violations contains msg if {
	input.suid_files.total_count > 20
	input.suid_files.unknown_count > 5
	msg := sprintf("CIS 6.1.13: Excessive unknown SUID binaries found (%d unknown out of %d total)", [input.suid_files.unknown_count, input.suid_files.total_count])
}

# CIS 6.1.14: SGID executables
suid_sgid_violations contains msg if {
	input.sgid_files.count > 30
	msg := sprintf("CIS 6.1.14: Excessive SGID binaries found (%d files)", [input.sgid_files.count])
}

risk_level := "critical" if {
	input.world_writable.count > 0
} else := "critical" if {
	input.critical_files.non_compliant_count > 0
} else := "high" if {
	input.suid_files.unknown_count > 5
} else := "medium" if {
	input.unowned_files.count > 0
} else := "low"

report := {
	"compliant": compliant,
	"risk_level": risk_level,
	"total_violations": count(violations),
	"violations": violations,
	"security_risks": {
		"world_writable_files": input.world_writable.count,
		"unowned_files": input.unowned_files.count,
		"ungrouped_files": input.ungrouped_files.count,
		"unknown_suid_binaries": input.suid_files.unknown_count,
		"sgid_binaries": input.sgid_files.count,
		"non_compliant_critical_files": input.critical_files.non_compliant_count,
	},
	"section": "6.1 System File Permissions",
	"benchmark": "CIS Ubuntu 22.04 v1.0.0",
}
