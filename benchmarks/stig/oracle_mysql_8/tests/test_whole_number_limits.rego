package stig.oracle_mysql_8.whole_number_limits_test

# max_user_connections, validate_password.length and audit_log_rotate_on_size are counts or sizes: a fraction
# is not a value MySQL can hold and does not pass (owner ruling 2026-11-24, "fix the STIG, do it right").

import rego.v1

green := data.stig.oracle_mysql_8_test.green_fixture

open_ids(inp) := {f.stig_id |
	r := data.stig.oracle_mysql_8.main.compliance_report with input as inp
	some f in r.open_findings
}

set(name, v) := json.patch(green, [{"op": "replace", "path": concat("/", ["", "mysql", "variables", name]), "value": v}])

test_fraction_is_open if {
	open_ids(set("max_user_connections", 50.5)) == {"MYS8-00-000200"}
	open_ids(set("validate_password.length", 15.5)) == {"MYS8-00-005000"}
	open_ids(set("audit_log_rotate_on_size", 1.5)) == {"MYS8-00-009600"}
}

test_whole_numbers_pass if {
	open_ids(set("max_user_connections", 50)) == set()
	open_ids(set("validate_password.length", 15)) == set()
	open_ids(set("audit_log_rotate_on_size", 1073741824)) == set()
}
