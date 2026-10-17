package cis_debian_11.file_permissions_test

import rego.v1

good := {
	"critical_files": {"analysis": [{"file": "/etc/passwd", "exists": true, "fully_compliant": true, "mode_compliant": true}], "non_compliant_count": 0},
	"ssh_private_keys": {"analysis": [], "all_compliant": true},
	"world_writable": {"files": [], "compliant": true, "count": 0},
	"unowned_files": {"files": [], "compliant": true, "count": 0},
	"ungrouped_files": {"files": [], "compliant": true, "count": 0},
	"suid_files": {"unknown_binaries": [], "total_count": 10, "unknown_count": 0},
	"sgid_files": {"count": 3},
}

test_clean_input_compliant if {
	data.cis_debian_11.file_permissions.compliant with input as good
}

test_world_writable_file_violates if {
	i := json.patch(good, [
		{"op": "replace", "path": "/world_writable/files", "value": [{"path": "/tmp/x", "mode": "0777", "owner": "root"}]},
		{"op": "replace", "path": "/world_writable/compliant", "value": false},
		{"op": "replace", "path": "/world_writable/count", "value": 1},
	])
	not data.cis_debian_11.file_permissions.compliant with input as i
	data.cis_debian_11.file_permissions.risk_level == "critical" with input as i
}

test_bad_passwd_mode_violates if {
	i := json.patch(good, [{"op": "replace", "path": "/critical_files/analysis/0", "value": {"file": "/etc/passwd", "exists": true, "fully_compliant": false, "mode_compliant": false, "actual_mode": "0666"}}])
	some m in data.cis_debian_11.file_permissions.violations with input as i
	contains(m, "CIS 6.1.2")
}

test_missing_ssh_key_evidence_violates if {
	not data.cis_debian_11.file_permissions.compliant with input as object.remove(good, ["ssh_private_keys"])
}
