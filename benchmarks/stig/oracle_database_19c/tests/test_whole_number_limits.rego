package stig.oracle_database_19c.whole_number_limits_test

# A limit that is a count (sessions, failed logins, idle minutes) is a whole JSON number; a fraction is not a
# value the DBMS can hold and does not pass (owner ruling 2026-11-24, "fix the STIG, do it right"). Limits
# expressed in days (DBA_PROFILES PASSWORD_*_TIME, INACTIVE_ACCOUNT_TIME) may be fractions of a day.

import rego.v1

green := data.stig.oracle_database_19c_test.green_fixture

open_ids(inp) := {f.stig_id |
	r := data.stig.oracle_database_19c.main.compliance_report with input as inp
	some f in r.open_findings
}

set(path, v) := json.patch(green, [{"op": "replace", "path": path, "value": v}])

test_fraction_on_a_count_is_open if {
	open_ids(set("/oracle/profiles/ORA_STIG_PROFILE/SESSIONS_PER_USER", 2.5)) == {"O19C-00-000100"}
	open_ids(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", 2.5)) == {"O19C-00-012400"}
	open_ids(set("/oracle/parameters/max_idle_time", 0.5)) == {"O19C-00-000300"}
}

test_whole_number_on_a_count_passes if {
	open_ids(set("/oracle/profiles/ORA_STIG_PROFILE/SESSIONS_PER_USER", 2)) == set()
	open_ids(set("/oracle/profiles/ORA_STIG_PROFILE/FAILED_LOGIN_ATTEMPTS", 3.0)) == set()
}

test_fraction_of_a_day_still_passes if {
	open_ids(set("/oracle/profiles/ORA_STIG_PROFILE/INACTIVE_ACCOUNT_TIME", 0.5)) == set()
	open_ids(set("/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_LIFE_TIME", 59.5)) == set()
	open_ids(set("/oracle/profiles/ORA_STIG_PROFILE/PASSWORD_GRACE_TIME", 0.0034)) == set()
}
