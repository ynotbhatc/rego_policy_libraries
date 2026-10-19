package nerc_cip.cip_014_test

import rego.v1

import data.nerc_cip.cip_014 as c

# Decisions 2026-10-19: dates may be ISO-8601 (documented) or epoch ns.

with_station(i) := object.union(i, {"applicable_transmission_stations": [{"station_id": "s1"}]})

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

test_iso_topology_change_within_60_days_passes if {
	c.assessment_updated_after_changes with input as {"transmission_topology_changes": [{
		"assessment_triggered": true,
		"change_date": "2026-01-01T00:00:00Z",
		"assessment_completion_date": "2026-01-20T00:00:00Z",
	}]}
}

test_iso_topology_change_after_60_days_fails if {
	not c.assessment_updated_after_changes with input as {"transmission_topology_changes": [{
		"assessment_triggered": true,
		"change_date": "2026-01-01T00:00:00Z",
		"assessment_completion_date": "2026-06-20T00:00:00Z",
	}]}
}

test_ns_topology_change_within_60_days_passes if {
	c.assessment_updated_after_changes with input as {"transmission_topology_changes": [{
		"assessment_triggered": true,
		"change_date": 1767225600000000000,
		"assessment_completion_date": 1768867200000000000,
	}]}
}

station_input(review_date) := {
	"applicable_transmission_stations": [{"station_id": "s1"}],
	"station_security_plans": {"s1": {"last_review_date": review_date}},
}

test_iso_plan_review_date_is_current if {
	c.security_plans_reviewed with input as station_input(now_rfc)
}

test_ns_plan_review_date_is_current if {
	c.security_plans_reviewed with input as station_input(time.now_ns())
}

test_old_iso_plan_review_date_fails if {
	not c.security_plans_reviewed with input as station_input("2015-01-01T00:00:00Z")
}

test_iso_third_party_review_within_60_days if {
	i := {"station_security_plans": {"s1": {
		"initial_completion_date": "2026-01-01T00:00:00Z",
		"third_party_review": {"performed": true, "unaffiliated": true, "relevant_expertise": true, "documented": true, "date": "2026-02-01T00:00:00Z"},
	}}}
	c.physical_security_plan_third_party_reviewed with input as with_station(i)
}

test_iso_implementation_within_12_months if {
	i := {
		"transmission_risk_assessment": {"third_party_verification": {"last_verification_date": "2026-01-01T00:00:00Z"}},
		"station_security_plans": {"s1": {"implementation_completed": true, "implementation_date": "2026-06-01T00:00:00Z"}},
	}
	c.plan_implementation_timely with input as with_station(i)
}
