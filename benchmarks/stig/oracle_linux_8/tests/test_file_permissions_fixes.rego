package stig.oracle_linux_8.file_permissions_test

import rego.v1

# Validation fixes 2026-10-17: missing offender lists are Open, and compliant requires evidence.

good := {"file_permissions": {
	"unowned_files": [], "ungrouped_files": [], "insecure_home_dirs": [],
	"library_files_ok": true, "library_dirs_owned_root": true, "system_commands_ok": true,
}}

test_file_permissions_good_input_compliant if {
	data.stig.oracle_linux_8.file_permissions.compliant with input as good
	data.stig.oracle_linux_8.file_permissions.compliance_report.open_findings == 0 with input as good
}

test_file_permissions_empty_input_not_compliant if {
	not data.stig.oracle_linux_8.file_permissions.compliant with input as {}
}

test_file_permissions_missing_lists_are_open if {
	m := data.stig.oracle_linux_8.file_permissions
	i := {"file_permissions": {"library_files_ok": true, "library_dirs_owned_root": true, "system_commands_ok": true}}
	m.status_ol08_00_010780 == "Open" with input as i
	m.status_ol08_00_010790 == "Open" with input as i
	m.status_ol08_00_010730 == "Open" with input as i
}

test_file_permissions_nonempty_list_is_open if {
	i := json.patch(good, [{"op": "replace", "path": "/file_permissions/unowned_files", "value": ["/tmp/x"]}])
	data.stig.oracle_linux_8.file_permissions.status_ol08_00_010780 == "Open" with input as i
}

test_file_permissions_report_populated_on_empty_input if {
	r := data.stig.oracle_linux_8.file_permissions.compliance_report with input as {}
	r.compliant == false
	r.open_findings == 6
}
