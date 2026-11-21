package ncsc_caf.numeric_guards_test

import rego.v1

# A string sorts above every number and null below: neither may satisfy a CAF threshold.
test_non_number_coverage_not_strong if {
	every v in ["1", null, "x"] {
		not data.ncsc_caf.a3_asset_management._a3a_coverage_strong with input as {"asset_management": {"coverage_pct": v}}
	}
}

test_non_number_backup_age_not_recent if {
	every v in ["1", null, "x"] {
		not data.ncsc_caf.b5_resilience._b5c_backup_recent with input as {"resilience": {"backups": {"backup_age_hours": v}}}
	}
}

test_non_number_feed_count_not_sufficient if {
	every v in ["1", null, "x"] {
		not data.ncsc_caf.c1_security_monitoring._c1f_feed_count_sufficient with input as {"security_monitoring": {"threat_intel": {"feed_count": v}}}
	}
}

test_numeric_thresholds_unchanged if {
	data.ncsc_caf.a3_asset_management._a3a_coverage_strong with input as {"asset_management": {"coverage_pct": 96}}
	not data.ncsc_caf.a3_asset_management._a3a_coverage_strong with input as {"asset_management": {"coverage_pct": 90}}
	data.ncsc_caf.b5_resilience._b5c_backup_recent with input as {"resilience": {"backups": {"backup_age_hours": 12}}}
	data.ncsc_caf.c1_security_monitoring._c1f_feed_count_sufficient with input as {"security_monitoring": {"threat_intel": {"feed_count": 2}}}
}
