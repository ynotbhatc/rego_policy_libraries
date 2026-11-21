package nist.sp800_171.audit_accountability_numeric_guards_test

import rego.v1

test_non_number_retention_not_met if {
	every v in ["1", null, "x"] {
		not data.nist.sp800_171.audit_accountability.audit_logs_created_retained with input as {"nist_800_171": {"audit_accountability": {"audit_logs": {
			"logging_enabled": true,
			"retention_period_days": v,
			"covers_all_systems": true,
		}}}}
	}
}

test_numeric_retention_unchanged if {
	data.nist.sp800_171.audit_accountability.audit_logs_created_retained with input as {"nist_800_171": {"audit_accountability": {"audit_logs": {
		"logging_enabled": true,
		"retention_period_days": 90,
		"covers_all_systems": true,
	}}}}
}
