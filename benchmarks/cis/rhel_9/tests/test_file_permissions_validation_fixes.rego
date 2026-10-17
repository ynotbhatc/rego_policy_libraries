package cis_rhel9.file_permissions_test

import rego.v1

# Validation fixes 2026-10-17: any section that was not collected is a violation.

good := {
	"critical_files": {"analysis": [{"file": "/etc/passwd", "exists": true, "fully_compliant": true, "mode_compliant": true}], "all_compliant": true, "non_compliant_count": 0},
	"world_writable": {"files": [], "count": 0, "compliant": true},
	"unowned_files": {"files": [], "count": 0, "compliant": true},
	"ungrouped_files": {"files": [], "count": 0, "compliant": true},
	"suid_files": {"total_count": 10, "unknown_count": 0, "unknown_binaries": []},
	"sgid_files": {"count": 3},
	"ssh_private_keys": {"analysis": [], "all_compliant": true},
}

test_fileperms_good_input_compliant if {
	data.cis_rhel9.file_permissions.compliant with input as good
}

test_fileperms_empty_object_sections_not_compliant if {
	not data.cis_rhel9.file_permissions.compliant with input as {"critical_files": {}, "world_writable": {}, "unowned_files": {}, "ungrouped_files": {}, "suid_files": {}, "sgid_files": {}, "ssh_private_keys": {}}
}

test_fileperms_each_missing_section_is_violation if {
	every sec in ["critical_files", "world_writable", "unowned_files", "ungrouped_files", "suid_files", "sgid_files", "ssh_private_keys"] {
		not data.cis_rhel9.file_permissions.compliant with input as json.remove(good, [concat("", ["/", sec])])
	}
}

test_fileperms_missing_section_message if {
	i := json.remove(good, ["/unowned_files"])
	"CIS 6.1.11: evidence missing — unowned_files.count not collected" in data.cis_rhel9.file_permissions.violations with input as i
}

test_fileperms_report_populated_when_failing if {
	r := data.cis_rhel9.file_permissions.report with input as json.remove(good, ["/world_writable"])
	r.compliant == false
	r.total_violations > 0
	is_object(r.compliance_summary)
}
