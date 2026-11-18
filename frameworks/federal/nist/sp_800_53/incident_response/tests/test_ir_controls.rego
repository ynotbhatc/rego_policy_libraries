package nist.sp800_53.incident_response_logic_test

# IR-2 / IR-3 frequencies are organization-defined; IR-5 is "track and document incidents".

import data.nist.sp800_53.incident_response as ir
import rego.v1

_finding(r, id) := [v | some v in r.violations; startswith(v, concat("", ["NIST ", id, ":"]))]

_ir(x) := r if {
	r := ir.compliance_report with input as {"ir_controls": x}
}

test_ir2_within_org_frequency_passes if {
	count(_finding(_ir({"training": {"days_since_last": 500, "odp": {"frequency_days": 730}}}), "IR-2")) == 0
}

test_ir2_beyond_org_frequency_fails if {
	f := _finding(_ir({"training": {"days_since_last": 200, "odp": {"frequency_days": 180}}}), "IR-2")
	count(f) == 1
	contains(f[0], "180")
}

test_ir2_missing_odp_is_missing_evidence if {
	f := _finding(_ir({"training": {"days_since_last": 10}}), "IR-2")
	count(f) == 1
	contains(f[0], "evidence missing")
	contains(f[0], "frequency_days")
}

test_ir2_old_within_year_boolean_not_evidence if {
	f := _finding(_ir({"training": {"completed_within_year": true}}), "IR-2")
	count(f) == 1
	contains(f[0], "evidence missing")
}

test_ir3_within_org_frequency_passes if {
	count(_finding(_ir({"testing": {"days_since_last": 90, "odp": {"frequency_days": 365}}}), "IR-3")) == 0
}

test_ir3_beyond_org_frequency_fails if {
	count(_finding(_ir({"testing": {"days_since_last": 400, "odp": {"frequency_days": 365}}}), "IR-3")) == 1
}

test_ir3_missing_observation_is_missing_evidence if {
	f := _finding(_ir({"testing": {"odp": {"frequency_days": 365}}}), "IR-3")
	count(f) == 1
	contains(f[0], "days_since_last")
}

test_ir5_tracking_passes if {
	count(_finding(_ir({"incident_tracking": {"tracked_and_documented": true}}), "IR-5")) == 0
}

test_ir5_continuous_monitoring_is_not_ir5_evidence if {
	count(_finding(_ir({"monitoring": {"continuous": true}}), "IR-5")) == 1
}

test_ir5_not_tracked_fails if {
	count(_finding(_ir({"incident_tracking": {"tracked_and_documented": false}}), "IR-5")) == 1
}

test_ir_one_finding_per_id_on_empty_input if {
	r := ir.compliance_report with input as {}
	count(r.violations) == 9
	every id in ir.evaluated_controls {
		count(_finding(r, id)) == 1
	}
}
