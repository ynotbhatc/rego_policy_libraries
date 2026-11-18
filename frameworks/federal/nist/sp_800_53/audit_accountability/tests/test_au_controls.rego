package nist.sp800_53.audit_accountability_logic_test

# AU-11 retention is an organization-defined period (audit 2026-11-17): no fixed 365-day floor.

import data.nist.sp800_53.audit_accountability as au
import rego.v1

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

_au(x) := r if {
	r := au.compliance_report with input as {"au_controls": x}
}

test_au11_meets_org_period_passes if {
	count(_finding(_au({"retention_period_days": 90, "odp": {"retention_period_days": 90}}), "AU-11")) == 0
}

test_au11_below_org_period_fails if {
	f := _finding(_au({"retention_period_days": 180, "odp": {"retention_period_days": 1095}}), "AU-11")
	count(f) == 1
	contains(f[0], "1095")
}

test_au11_missing_odp_is_missing_evidence if {
	f := _finding(_au({"retention_period_days": 3650}), "AU-11")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_au11_missing_retention_is_missing_evidence if {
	f := _finding(_au({"odp": {"retention_period_days": 365}}), "AU-11")
	count(f) == 1
	contains(f[0], "retention_period_days")
}

test_au_one_finding_per_evaluated_id_on_empty_input if {
	r := au.compliance_report with input as {}
	count(r.violations) == 12
	every id in au.evaluated_controls {
		count(_finding(r, id)) == 1
	}
}

# AU-8: UTC / offset, not synchronisation (AU-8(1) withdrawn, moved to SC-45(1)).
test_au8_utc_passes if {
	count(_finding(_au({"time_stamps": {"utc_or_offset_recorded": true}}), "AU-8")) == 0
}

test_au8_sync_alone_is_not_au8_evidence if {
	count(_finding(_au({"time_stamps": {"synchronized": true}}), "AU-8")) == 1
}

test_au8_false_fails if {
	count(_finding(_au({"time_stamps": {"utc_or_offset_recorded": false}}), "AU-8")) == 1
}
