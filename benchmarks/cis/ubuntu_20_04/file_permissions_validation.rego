# METADATA
# title: "CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 6.1: System File Permissions"
# custom:
#   class: security
#   framework: cis_ubuntu_20_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 29
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package cis_ubuntu_20_04.file_permissions

# CIS Ubuntu 20.04 LTS Benchmark v3.0.0 - Section 6.1: System File Permissions

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in critical_file_violations], [v | some v in world_writable_violations]),
	array.concat([v | some v in ownership_violations], [v | some v in suid_sgid_violations]),
)

# Missing evidence must not pass: every section the checks below judge has to be collected.
# A section is "present" when it is a non-empty object ({} is not evidence).
section_present(key) if count(object.get(input, key, {})) > 0

critical_file_violations contains msg if {
	not section_present("critical_files")
	msg := "CIS 6.1.x: evidence missing — critical_files not collected"
}

world_writable_violations contains msg if {
	not section_present("world_writable")
	msg := "CIS 6.1.10: evidence missing — world_writable not collected"
}

ownership_violations contains msg if {
	not section_present("unowned_files")
	msg := "CIS 6.1.11: evidence missing — unowned_files not collected"
}

ownership_violations contains msg if {
	not section_present("ungrouped_files")
	msg := "CIS 6.1.12: evidence missing — ungrouped_files not collected"
}

suid_sgid_violations contains msg if {
	not section_present("suid_files")
	msg := "CIS 6.1.13: evidence missing — suid_files not collected"
}

suid_sgid_violations contains msg if {
	not section_present("sgid_files")
	msg := "CIS 6.1.14: evidence missing — sgid_files not collected"
}

# CIS 6.1.x: Critical system file permissions
critical_file_violations contains msg if {
	some file in input.critical_files.analysis
	file.fully_compliant == false
	file.exists == true
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
	file.mode_compliant == false
	msg := sprintf("CIS 6.1.6: /etc/shadow has insecure permissions (mode: %s, expected: 0000/0400/0600)", [file.actual_mode])
}

critical_file_violations contains msg if {
	some file in input.critical_files.analysis
	file.file == "/etc/gshadow"
	file.mode_compliant == false
	msg := sprintf("CIS 6.1.8: /etc/gshadow has insecure permissions (mode: %s, expected: 0000/0400/0600)", [file.actual_mode])
}

critical_file_violations contains msg if {
	some file in input.critical_files.analysis
	file.file == "/etc/passwd"
	file.mode_compliant == false
	msg := sprintf("CIS 6.1.2: /etc/passwd has incorrect permissions (mode: %s, expected: 0644)", [file.actual_mode])
}

critical_file_violations contains msg if {
	some file in input.critical_files.analysis
	file.file == "/etc/group"
	file.mode_compliant == false
	msg := sprintf("CIS 6.1.4: /etc/group has incorrect permissions (mode: %s, expected: 0644)", [file.actual_mode])
}

# SSH private keys
critical_file_violations contains msg if {
	some key in input.ssh_private_keys.analysis
	key.fully_compliant == false
	msg := sprintf("SSH Private Key: %s has insecure permissions (mode: %s, owner: %s)", [key.path, key.mode, key.owner])
}

critical_file_violations contains msg if {
	input.ssh_private_keys.all_compliant == false
	msg := "SSH Private Keys: One or more SSH host keys have insecure permissions"
}

# CIS 6.1.10: World-writable files
world_writable_violations contains msg if {
	count(object.get(input, ["world_writable", "files"], [])) > 0
	some file in input.world_writable.files
	msg := sprintf("CIS 6.1.10: World-writable file found: %s (mode: %s, owner: %s)", [file.path, file.mode, file.owner])
}

world_writable_violations contains msg if {
	not input.world_writable.compliant == true
	is_number(input.world_writable.count)
	input.world_writable.count > 0
	msg := sprintf("CIS 6.1.10: %d world-writable files found on system", [input.world_writable.count])
}

world_writable_violations contains msg if {
	not is_number(object.get(input, ["world_writable", "count"], 0))
	msg := "CIS 6.1.10: evidence missing — world_writable.count is not a number"
}

# CIS 6.1.11: Unowned files
ownership_violations contains msg if {
	count(object.get(input, ["unowned_files", "files"], [])) > 0
	some file in input.unowned_files.files
	msg := sprintf("CIS 6.1.11: Unowned file found: %s (UID: %d, mode: %s)", [file.path, file.uid, file.mode])
}

ownership_violations contains msg if {
	not input.unowned_files.compliant == true
	is_number(input.unowned_files.count)
	input.unowned_files.count > 0
	msg := sprintf("CIS 6.1.11: %d unowned files found on system", [input.unowned_files.count])
}

ownership_violations contains msg if {
	not is_number(object.get(input, ["unowned_files", "count"], 0))
	msg := "CIS 6.1.11: evidence missing — unowned_files.count is not a number"
}

# CIS 6.1.12: Ungrouped files
ownership_violations contains msg if {
	count(object.get(input, ["ungrouped_files", "files"], [])) > 0
	some file in input.ungrouped_files.files
	msg := sprintf("CIS 6.1.12: Ungrouped file found: %s (GID: %d, mode: %s)", [file.path, file.gid, file.mode])
}

ownership_violations contains msg if {
	not input.ungrouped_files.compliant == true
	is_number(input.ungrouped_files.count)
	input.ungrouped_files.count > 0
	msg := sprintf("CIS 6.1.12: %d ungrouped files found on system", [input.ungrouped_files.count])
}

ownership_violations contains msg if {
	not is_number(object.get(input, ["ungrouped_files", "count"], 0))
	msg := "CIS 6.1.12: evidence missing — ungrouped_files.count is not a number"
}

# CIS 6.1.13: SUID executables
suid_sgid_violations contains msg if {
	some file in input.suid_files.unknown_binaries
	file.review_required == true
	msg := sprintf("CIS 6.1.13: Unknown SUID binary requires review: %s (mode: %s, owner: %s)", [file.path, file.mode, file.owner])
}

suid_sgid_violations contains msg if {
	is_number(input.suid_files.total_count)
	input.suid_files.total_count > 20
	is_number(input.suid_files.unknown_count)
	input.suid_files.unknown_count > 5
	msg := sprintf("CIS 6.1.13: Excessive unknown SUID binaries found (%d unknown out of %d total)", [input.suid_files.unknown_count, input.suid_files.total_count])
}

suid_sgid_violations contains msg if {
	not is_number(object.get(input, ["suid_files", "unknown_count"], 0))
	msg := "CIS 6.1.13: evidence missing — suid_files.unknown_count is not a number"
}

suid_sgid_violations contains msg if {
	not is_number(object.get(input, ["suid_files", "total_count"], 0))
	msg := "CIS 6.1.13: evidence missing — suid_files.total_count is not a number"
}

# CIS 6.1.14: SGID executables
suid_sgid_violations contains msg if {
	is_number(input.sgid_files.count)
	input.sgid_files.count > 30
	msg := sprintf("CIS 6.1.14: Excessive SGID binaries found (%d files)", [input.sgid_files.count])
}

suid_sgid_violations contains msg if {
	not is_number(object.get(input, ["sgid_files", "count"], 0))
	msg := "CIS 6.1.14: evidence missing — sgid_files.count is not a number"
}

# yes/no fields of collected rows: every row must answer with a boolean
critical_file_violations contains msg if {
	some i, row in input.critical_files.analysis
	some key in ["fully_compliant", "exists"]
	msg := sprintf("CIS 6.1.x: evidence missing — critical_files.analysis[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# mode_compliant is read for the four account database files
mode_checked_files := {"/etc/passwd": "6.1.2", "/etc/group": "6.1.4", "/etc/shadow": "6.1.6", "/etc/gshadow": "6.1.8"}

critical_file_violations contains msg if {
	some i, row in input.critical_files.analysis
	ctl := mode_checked_files[row.file]
	msg := sprintf("CIS %s: evidence missing — critical_files.analysis[%d].mode_compliant %s", [ctl, i, row_flag_problem(row, "mode_compliant")])
}

# yes/no fields of collected rows: every row must answer with a boolean
critical_file_violations contains msg if {
	some i, row in input.ssh_private_keys.analysis
	some key in ["fully_compliant"]
	msg := sprintf("SSH Private Key: evidence missing — ssh_private_keys.analysis[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# yes/no fields of collected rows: every row must answer with a boolean
suid_sgid_violations contains msg if {
	some i, row in input.suid_files.unknown_binaries
	some key in ["review_required"]
	msg := sprintf("CIS 6.1.13: evidence missing — suid_files.unknown_binaries[%d].%s %s", [i, key, row_flag_problem(row, key)])
}

# <section>.compliant is the collector's own summary: optional, but a boolean when sent
sweep_sections := {"world_writable": "6.1.10", "unowned_files": "6.1.11", "ungrouped_files": "6.1.12"}

sweep_violations contains msg if {
	some section, ctl in sweep_sections
	v := object.get(input, [section, "compliant"], null)
	not is_null(v)
	not is_boolean(v)
	msg := sprintf("CIS %s: evidence missing — %s.compliant is not a boolean (got %s)", [ctl, section, type_name(v)])
}

# the sweep result is its count or its file list; with neither there is nothing to judge
sweep_violations contains msg if {
	some section, ctl in sweep_sections
	section_present(section)
	number_missing([section, "count"])
	not is_array(object.get(input, [section, "files"], null))
	msg := sprintf("CIS %s: evidence missing — %s.count (or %s.files) not collected", [ctl, section, section])
}

world_writable_violations contains msg if {
	some msg in sweep_violations
	startswith(msg, "CIS 6.1.10:")
}

ownership_violations contains msg if {
	some msg in sweep_violations
	not startswith(msg, "CIS 6.1.10:")
}

suid_sgid_violations contains msg if {
	section_present("suid_files")
	number_missing(["suid_files", "unknown_count"])
	msg := "CIS 6.1.13: evidence missing — suid_files.unknown_count not collected"
}

suid_sgid_violations contains msg if {
	section_present("suid_files")
	number_missing(["suid_files", "total_count"])
	msg := "CIS 6.1.13: evidence missing — suid_files.total_count not collected"
}

suid_sgid_violations contains msg if {
	section_present("sgid_files")
	number_missing(["sgid_files", "count"])
	msg := "CIS 6.1.14: evidence missing — sgid_files.count not collected"
}

risk_level := "critical" if {
	is_number(input.world_writable.count)
	input.world_writable.count > 0
} else := "critical" if {
	is_number(input.critical_files.non_compliant_count)
	input.critical_files.non_compliant_count > 0
} else := "high" if {
	is_number(input.suid_files.unknown_count)
	input.suid_files.unknown_count > 5
} else := "medium" if {
	is_number(input.unowned_files.count)
	input.unowned_files.count > 0
} else := "low"

# ---------------------------------------------------------------------------
# Evidence rule: a yes/no fact is answered only by a JSON boolean. A missing fact, null, a string
# ("true", "false", "no") or a number is an evidence problem: the control fails and the finding names it.
# ---------------------------------------------------------------------------
flag_problem(path) := "not collected" if is_null(object.get(input, path, null))

flag_problem(path) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(input, path, null)
	not is_null(v)
	not is_boolean(v)
}

flag_evidence(prefix, path) := sprintf("%s: evidence missing — %s %s", [prefix, concat(".", path), flag_problem(path)])

# the same for a yes/no field of one collected row
row_flag_problem(row, key) := "not collected" if is_null(object.get(row, key, null))

row_flag_problem(row, key) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(row, key, null)
	not is_null(v)
	not is_boolean(v)
}

# a number that must be collected: missing and null are "not collected" (a wrong type is reported by the rule that reads it)
number_missing(path) if is_null(object.get(input, path, null))

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags := [
	["SSH Private Keys", ["ssh_private_keys", "all_compliant"]],
]

critical_file_violations contains msg if {
	some [prefix, path] in required_flags
	msg := flag_evidence(prefix, path)
}

report := {
	"compliant": compliant,
	"risk_level": risk_level,
	"total_violations": count(violations),
	"violations": violations,
	"security_risks": {
		"world_writable_files": object.get(input, ["world_writable", "count"], null),
		"unowned_files": object.get(input, ["unowned_files", "count"], null),
		"ungrouped_files": object.get(input, ["ungrouped_files", "count"], null),
		"unknown_suid_binaries": object.get(input, ["suid_files", "unknown_count"], null),
		"sgid_binaries": object.get(input, ["sgid_files", "count"], null),
		"non_compliant_critical_files": object.get(input, ["critical_files", "non_compliant_count"], null),
	},
	"section": "6.1 System File Permissions",
	"benchmark": "CIS Ubuntu 20.04 v3.0.0",
}
