package cis_ubuntu_22_04.file_permissions_test

import rego.v1

# Validation fix 2026-10-17: sections that were not collected (critical files, offender
# counts) produced no violation; the smoke test could not tell.

pkg := data.cis_ubuntu_22_04.file_permissions

good := {
	"critical_files": {"analysis": [], "non_compliant_count": 0},
	"ssh_private_keys": {"analysis": [], "all_compliant": true},
	"world_writable": {"files": [], "count": 0, "compliant": true},
	"unowned_files": {"files": [], "count": 0, "compliant": true},
	"ungrouped_files": {"files": [], "count": 0, "compliant": true},
	"suid_files": {"unknown_binaries": [], "total_count": 10, "unknown_count": 0},
	"sgid_files": {"count": 3},
}

test_good_compliant if {
	pkg.compliant with input as good
}

test_each_missing_section_violates if {
	every section in ["critical_files", "world_writable", "unowned_files", "ungrouped_files", "suid_files", "sgid_files"] {
		not pkg.compliant with input as object.remove(good, [section])
	}
}

test_missing_world_writable_message if {
	v := pkg.violations with input as object.remove(good, ["world_writable"])
	"CIS 6.1.x: evidence missing — world_writable.count not collected" in v
}

test_world_writable_found_violates if {
	not pkg.compliant with input as object.union(good, {"world_writable": {"files": [{"path": "/x", "mode": "0666", "owner": "root"}], "count": 1, "compliant": false}})
}

test_noncompliant_critical_file_violates if {
	f := {"file": "/etc/shadow", "exists": true, "fully_compliant": false, "mode_compliant": false, "actual_mode": "0644", "expected_mode": "0640", "actual_owner": "root", "expected_owner": "root", "actual_group": "shadow", "expected_group": "shadow"}
	not pkg.compliant with input as object.union(good, {"critical_files": {"analysis": [f], "non_compliant_count": 1}})
}
