package nerc_cip.cip_009_test

import rego.v1

import data.nerc_cip.cip_009 as c

# Validation 2026-10-17: ISO-8601 dates, per-system plan currency, R2.2 gating.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

plan := {
	"documented": true,
	"procedures_defined": true,
	"contact_information_current": true,
	"recovery_time_objectives_defined": true,
	"last_review_date": now_rfc,
}

with_settings := {
	"activation_criteria_documented": true,
	"decision_authority_identified": true,
	"S1": plan,
}

base := {
	"bes_cyber_systems": [{"system_id": "S1", "impact_categorization": "high"}],
	"recovery_plans": with_settings,
	"recovery_testing": {"S1": {"last_test_date": now_rfc, "test_documented": true, "issues_resolved": true}},
	"backup_procedures": {"S1": {"last_test_date": now_rfc, "test_documented": true, "restoration_verified": true}},
}

test_iso_review_dates_are_current_with_scalar_settings if {
	c.recovery_plans_current with input as base
}

test_stale_iso_review_not_current if {
	i := json.patch(base, [{"op": "replace", "path": "/recovery_plans/S1/last_review_date", "value": "2019-01-01T00:00:00Z"}])
	not c.recovery_plans_current with input as i
}

test_iso_test_dates_accepted if {
	c.recovery_testing_performed with input as base
	c.backup_testing_performed with input as base
}

test_stale_iso_recovery_test_fails if {
	i := json.patch(base, [{"op": "replace", "path": "/recovery_testing/S1/last_test_date", "value": "2019-01-01T00:00:00Z"}])
	not c.recovery_testing_performed with input as i
}

test_missing_inventory_fails_system_rules if {
	not c.recovery_plans_current with input as {}
	not c.recovery_plans_documented with input as {}
	not c.recovery_testing_performed with input as {}
	not c.backup_testing_performed with input as {}
	not c.backup_processes_documented with input as {}
}

test_late_post_event_update_fails_and_is_listed if {
	ev := {"plan_review_triggered": true, "event_date": "2026-01-01T00:00:00Z", "plan_review_completion_date": "2026-09-01T00:00:00Z"}
	i := object.union(base, {"qualifying_recovery_events": [ev]})
	not c.post_event_plan_updates with input as i
	count([v | some v in c.violations with input as i; v.requirement == "R2.2"]) == 1
}

test_timely_post_event_update_iso if {
	ev := {"plan_review_triggered": true, "event_date": "2026-01-01T00:00:00Z", "plan_review_completion_date": "2026-02-01T00:00:00Z"}
	c.post_event_plan_updates with input as object.union(base, {"qualifying_recovery_events": [ev]})
}
