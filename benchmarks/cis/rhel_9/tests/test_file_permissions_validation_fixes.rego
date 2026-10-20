package cis_rhel9.file_permissions_test

import rego.v1

# Validation fixes 2026-10-17: any section that was not collected is a violation.
# Re-pointed to CIS RHEL 9 v3.0.0 (2026-10-20): same test names, v3 recommendation ids.
# v2 6.1.x -> v3 7.1.x. The v3 automated checks read critical_files, world_writable, sticky_bit,
# unowned_files and ungrouped_files (SUID/SGID review, v3 7.1.13, is an attestation).

good := {"critical_files": {"analysis": [{"file": "/etc/other", "exists": true, "actual_mode": "0644", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/passwd", "exists": true, "actual_mode": "0644", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/passwd-", "exists": true, "actual_mode": "0644", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/group", "exists": true, "actual_mode": "0644", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/group-", "exists": true, "actual_mode": "0644", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/shadow", "exists": true, "actual_mode": "0000", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/shadow-", "exists": true, "actual_mode": "0000", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/gshadow", "exists": true, "actual_mode": "0000", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/gshadow-", "exists": true, "actual_mode": "0000", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/shells", "exists": true, "actual_mode": "0644", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/security/opasswd", "exists": true, "actual_mode": "0600", "actual_owner": "root", "actual_group": "root"}, {"file": "/etc/security/opasswd.old", "exists": false}]}, "world_writable": {"files": [], "count": 0}, "sticky_bit": {"world_writable_without_sticky": []}, "unowned_files": {"files": [], "count": 0}, "ungrouped_files": {"files": [], "count": 0}, "attest": {"suid_sgid_files_reviewed": true}}

test_fileperms_good_input_compliant if {
	data.cis_rhel9.file_permissions.compliant with input as good
}

test_fileperms_empty_object_sections_not_compliant if {
	not data.cis_rhel9.file_permissions.compliant with input as {"critical_files": {}, "world_writable": {}, "sticky_bit": {}, "unowned_files": {}, "ungrouped_files": {}, "attest": {"suid_sgid_files_reviewed": true}}
}

test_fileperms_each_missing_section_is_violation if {
	every sec in ["critical_files", "world_writable", "sticky_bit", "unowned_files", "ungrouped_files"] {
		not data.cis_rhel9.file_permissions.compliant with input as json.remove(good, [concat("", ["/", sec])])
	}
}

test_fileperms_missing_section_message if {
	i := json.remove(good, ["/unowned_files"])
	"7.1.12: evidence missing — unowned_files.files/ungrouped_files.files not collected" in data.cis_rhel9.file_permissions.violations with input as i
}

test_fileperms_report_populated_when_failing if {
	r := data.cis_rhel9.file_permissions.report with input as json.remove(good, ["/world_writable"])
	r.compliant == false
	r.total_violations > 0
	is_object(r.compliance_summary)
}

# a truncated world-writable sweep (the mapper's truncated flag) is not evidence of none
test_fileperms_truncated_world_writable_is_not_a_pass if {
	i := json.patch(good, [{"op": "add", "path": "/world_writable/truncated", "value": true}])
	"7.1.11: evidence missing — world_writable.files/sticky_bit.world_writable_without_sticky not collected" in data.cis_rhel9.file_permissions.violations with input as i
}
