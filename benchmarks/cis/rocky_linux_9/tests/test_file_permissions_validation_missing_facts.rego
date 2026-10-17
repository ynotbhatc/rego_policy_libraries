package cis_rocky_linux_9.file_permissions_test

import rego.v1

good := {
	"critical_files": {"analysis": [], "non_compliant_count": 0},
	"ssh_private_keys": {"all_compliant": true},
	"world_writable": {"count": 0, "compliant": true, "files": []},
	"unowned_files": {"count": 0, "compliant": true, "files": []},
	"ungrouped_files": {"count": 0, "compliant": true, "files": []},
	"suid_files": {"total_count": 10, "unknown_count": 0, "unknown_binaries": []},
	"sgid_files": {"count": 3},
}

test_full_evidence_compliant if data.cis_rocky_linux_9.file_permissions.compliant with input as good

test_only_ssh_keys_fact_not_compliant if {
	inp := {"ssh_private_keys": {"all_compliant": true}}
	not data.cis_rocky_linux_9.file_permissions.compliant with input as inp
	v := data.cis_rocky_linux_9.file_permissions.violations with input as inp
	count(v) == 6
}

test_each_missing_section_flagged if {
	every k in ["critical_files", "world_writable", "unowned_files", "ungrouped_files", "suid_files", "sgid_files"] {
		inp := object.remove(good, [k])
		not data.cis_rocky_linux_9.file_permissions.compliant with input as inp
	}
}
