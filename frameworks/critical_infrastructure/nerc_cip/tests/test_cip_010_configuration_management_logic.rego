package nerc_cip.cip_010_test

import rego.v1

import data.nerc_cip.cip_010 as c

# Validation 2026-10-17: impact filter and ISO-8601 monitoring dates.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

mon(d) := {"enabled": true, "change_detection": true, "alerting_configured": true, "baseline_comparison": true, "last_review_date": d}

base := {
	"bes_cyber_systems": [
		{"system_id": "H1", "impact_categorization": "high"},
		{"system_id": "L1", "impact_categorization": "low"},
	],
	"configuration_monitoring": {"H1": mon(now_rfc)},
	"vulnerability_assessments": {"H1": {"completion_date": now_rfc, "documented": true, "remediation_plan_exists": true, "authenticated_scan_used": true}},
}

test_low_impact_system_does_not_fail_monitoring if {
	c.unauthorized_change_monitoring with input as base
	c.configuration_monitoring_timely with input as base
	c.authenticated_scanning_used with input as base
}

test_stale_iso_review_fails_timely if {
	i := json.patch(base, [{"op": "replace", "path": "/configuration_monitoring/H1/last_review_date", "value": "2019-01-01T00:00:00Z"}])
	not c.configuration_monitoring_timely with input as i
}

test_high_impact_without_monitoring_fails if {
	i := json.remove(base, ["configuration_monitoring/H1"])
	not c.unauthorized_change_monitoring with input as i
	not c.configuration_monitoring_timely with input as i
}

test_numeric_ns_review_date_still_accepted if {
	i := json.patch(base, [{"op": "replace", "path": "/configuration_monitoring/H1/last_review_date", "value": time.now_ns()}])
	c.configuration_monitoring_timely with input as i
}

test_vulnerability_assessment_iso_date if {
	c.vulnerability_assessments_performed with input as base
	i := json.patch(base, [{"op": "replace", "path": "/vulnerability_assessments/H1/completion_date", "value": "2019-01-01T00:00:00Z"}])
	not c.vulnerability_assessments_performed with input as i
}

test_missing_inventory_fails if {
	not c.unauthorized_change_monitoring with input as {}
	not c.configuration_monitoring_timely with input as {}
	not c.baseline_configurations_established with input as {}
	not c.vulnerability_assessments_performed with input as {}
}
