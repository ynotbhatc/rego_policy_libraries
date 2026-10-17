package digital_sovereignty.cyber_resilience_sovereignty_fixes_test

import rego.v1

cr := data.digital_sovereignty.cyber_resilience_sovereignty

metrics(m) := {"cyber_resilience": {"metrics": m}}

has_control(vs, c) if {
	some v in vs
	v.control == c
}

test_null_mttr_does_not_pass if not cr.mttr_within_threshold with input as metrics({"mttr_tracked": true, "mttr_hours": null, "mttr_threshold_hours": 24})

test_null_threshold_does_not_pass if not cr.mttr_within_threshold with input as metrics({"mttr_tracked": true, "mttr_hours": 4, "mttr_threshold_hours": null})

test_mttr_within_threshold_passes if cr.mttr_within_threshold with input as metrics({"mttr_tracked": true, "mttr_hours": 4, "mttr_threshold_hours": 24})

test_mttr_over_threshold_fails if not cr.mttr_within_threshold with input as metrics({"mttr_tracked": true, "mttr_hours": 48, "mttr_threshold_hours": 24})

test_null_mttr_reports_cr009 if has_control(cr.violations, "CR-009") with input as metrics({"mttr_tracked": true, "mttr_hours": null, "mttr_threshold_hours": 24})

test_missing_mttr_still_reports_cr009 if has_control(cr.violations, "CR-009") with input as metrics({"mttr_tracked": true})

test_cr009_not_reported_when_ok if not has_control(cr.violations, "CR-009") with input as metrics({"mttr_tracked": true, "mttr_hours": 4, "mttr_threshold_hours": 24})

test_cr009_description_includes_values if {
	some v in cr.violations with input as metrics({"mttr_tracked": true, "mttr_hours": 48.5, "mttr_threshold_hours": 24})
	v.control == "CR-009"
	contains(v.description, "48.5")
}
