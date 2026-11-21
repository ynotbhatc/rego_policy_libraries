package nist.sp800_171.physical_protection_numeric_guards_test

import rego.v1

test_non_number_log_retention_not_met if {
	every v in ["1", null, "x"] {
		not data.nist.sp800_171.physical_protection.physical_access_logs with input as {"nist_800_171": {"physical_protection": {"access_logs": {
			"logs_maintained": true,
			"covers_all_entry_points": true,
			"retention_period_days": v,
			"reviewed_periodically": true,
		}}}}
	}
}

test_numeric_log_retention_unchanged if {
	data.nist.sp800_171.physical_protection.physical_access_logs with input as {"nist_800_171": {"physical_protection": {"access_logs": {
		"logs_maintained": true,
		"covers_all_entry_points": true,
		"retention_period_days": 90,
		"reviewed_periodically": true,
	}}}}
}
