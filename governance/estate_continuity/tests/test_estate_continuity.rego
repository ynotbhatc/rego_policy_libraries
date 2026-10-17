package estate_continuity.main_test

import data.estate_continuity.main
import rego.v1

# One healthy host; each test overrides the fields it is about.
base := {
	"name": "web-01",
	"in_inventory": true,
	"provider": "aws_ec2",
	"provider_state": "running",
	"hours_since_evaluated": 3,
	"hours_since_first_seen": 900,
	"last_attempt": {"outcome": "ok", "hours_ago": 3},
}

record := {"declared": true, "ref": "CHG0012", "by": "J. Smith", "hours_ago": 30}

state_of(h) := r.state if {
	some r in main.compliance_report.hosts with input as {"hosts": [h]}
}

report(hosts) := r if {
	r := main.compliance_report with input as {"hosts": hosts}
}

# ── Guards: nothing to classify is never clean ──────────────────────────────

test_no_input_is_not_compliant if {
	r := main.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 1
}

test_hosts_not_an_array_is_not_compliant if {
	r := main.compliance_report with input as {"hosts": "web-01"}
	r.compliant == false
}

test_empty_host_list_is_not_compliant if {
	r := report([])
	r.compliant == false
	contains(r.violations[0], "no hosts supplied")
}

test_duplicate_names_are_a_finding if {
	r := report([base, base])
	r.compliant == false
	some v in r.violations
	contains(v, "more than once")
}

test_malformed_record_is_a_finding if {
	state_of({"name": "x"}) == "invalid_record"
	state_of({"in_inventory": true}) == "invalid_record"
	state_of({"name": "x", "in_inventory": "yes"}) == "invalid_record"
	r := report([{"in_inventory": true}])
	r.compliant == false
	r.hosts[0].name == "record #0"
}

# ── Healthy and advisory states ─────────────────────────────────────────────

test_active_host_is_compliant if {
	state_of(base) == "active"
	r := report([base])
	r.compliant == true
	r.advisory_count == 0
}

test_late_is_an_advisory_not_a_finding if {
	h := object.union(base, {"hours_since_evaluated": 30, "last_attempt": {"outcome": "unreachable", "hours_ago": 2}})
	state_of(h) == "late"
	r := report([h])
	r.compliant == true
	r.advisory_count == 1
}

test_new_host_inside_grace_is_an_advisory if {
	h := object.union(object.remove(base, ["hours_since_evaluated"]), {"hours_since_first_seen": 10})
	state_of(h) == "new"
	report([h]).compliant == true
}

test_never_evaluated_after_grace_is_stale if {
	h := object.union(object.remove(base, ["hours_since_evaluated", "last_attempt"]), {"hours_since_first_seen": 200})
	state_of(h) == "stale_not_targeted"
	contains(report([h]).violations[0], "never")
}

test_stopped_is_flagged_not_failed_by_default if {
	h := object.union(base, {"provider_state": "stopped", "hours_since_evaluated": 500})
	state_of(h) == "stopped"
	r := report([h])
	r.compliant == true
	r.advisory_count == 1
}

test_stopped_can_be_taken_out_of_scope if {
	h := object.union(base, {"provider_state": "stopped", "hours_since_evaluated": 500})
	r := main.compliance_report with input as {"hosts": [h], "config": {"stopped_in_scope": false}}
	r.hosts[0].state == "stopped_out_of_scope"
	r.advisory_count == 0
}

# ── Not responding ──────────────────────────────────────────────────────────

test_stale_unreachable if {
	h := object.union(base, {"hours_since_evaluated": 340, "last_attempt": {"outcome": "unreachable", "hours_ago": 4}})
	state_of(h) == "stale_unreachable"
	r := report([h])
	r.compliant == false
	contains(r.violations[0], "CA-7")
}

test_stale_failing if {
	h := object.union(base, {"hours_since_evaluated": 80, "last_attempt": {"outcome": "failed", "hours_ago": 4}})
	state_of(h) == "stale_failing"
}

test_stale_no_evidence if {
	h := object.union(base, {"hours_since_evaluated": 80})
	state_of(h) == "stale_no_evidence"
}

test_stale_not_targeted if {
	h := object.union(object.remove(base, ["last_attempt"]), {"hours_since_evaluated": 80})
	state_of(h) == "stale_not_targeted"
}

# ── Disappeared ─────────────────────────────────────────────────────────────

test_gone_from_inventory_without_record_is_missing if {
	h := object.union(base, {"in_inventory": false, "provider_state": "absent"})
	state_of(h) == "missing"
	r := report([h])
	r.compliant == false
	contains(r.violations[0], "unexplained disappearance")
}

test_inventory_absence_with_unknown_provider_is_missing if {
	state_of(object.union(base, {"in_inventory": false, "provider_state": "unknown"})) == "missing"
}

test_stopped_instance_dropped_from_inventory_is_stopped_not_missing if {
	h := object.union(base, {"in_inventory": false, "provider_state": "stopped", "hours_since_evaluated": 90})
	state_of(h) == "stopped"
	report([h]).compliant == true
}

test_running_but_in_no_inventory_is_unmanaged if {
	h := object.union(base, {"in_inventory": false, "provider_state": "running"})
	state_of(h) == "unmanaged_running"
	r := report([h])
	r.compliant == false
	contains(r.violations[0], "nothing is managing")
}

test_provider_terminated_without_record_is_missing if {
	state_of(object.union(base, {"provider_state": "terminated"})) == "missing"
	state_of(object.union(base, {"provider_state": "absent"})) == "missing"
}

test_removed_by_named_actor_without_record_is_still_a_finding if {
	h := object.union(base, {"in_inventory": false, "provider_state": "unknown", "removal_event": {"source": "user", "by": "admin", "hours_ago": 20}})
	state_of(h) == "removed_unrecorded"
	r := report([h])
	r.compliant == false
	contains(r.violations[0], "removed by admin")
}

# ── Retired on purpose ──────────────────────────────────────────────────────

test_recorded_and_gone_is_retired if {
	h := object.union(base, {
		"in_inventory": false, "provider_state": "terminated", "retirement": record,
		"last_attempt": {"outcome": "ok", "hours_ago": 40},
	})
	state_of(h) == "retired"
	report([h]).compliant == true
}

test_recorded_but_still_in_inventory_is_incomplete if {
	h := object.union(base, {"retirement": record, "last_attempt": {"outcome": "unreachable", "hours_ago": 2}})
	state_of(h) == "retirement_incomplete"
	r := report([h])
	r.compliant == true
	r.advisory_count == 1
}

test_retired_host_that_still_answers_is_a_zombie if {
	h := object.union(base, {"retirement": record, "last_attempt": {"outcome": "ok", "hours_ago": 2}})
	state_of(h) == "zombie"
	r := report([h])
	r.compliant == false
	contains(r.violations[0], "28 h after the retirement")
}

test_answer_before_the_retirement_is_not_a_zombie if {
	h := object.union(base, {"in_inventory": false, "provider_state": "absent", "retirement": record, "last_attempt": {"outcome": "ok", "hours_ago": 31}})
	state_of(h) == "retired"
}

test_a_bare_declared_flag_is_not_a_record if {
	h := object.union(base, {"in_inventory": false, "provider_state": "absent", "retirement": {"declared": true}})
	state_of(h) == "missing"
	h2 := object.union(base, {"in_inventory": false, "provider_state": "absent", "retirement": object.remove(record, ["by"])})
	state_of(h2) == "missing"
}

# ── Config ──────────────────────────────────────────────────────────────────

test_config_overrides_windows if {
	h := object.union(base, {"hours_since_evaluated": 30, "last_attempt": {"outcome": "unreachable", "hours_ago": 1}})
	r := main.compliance_report with input as {"hosts": [h], "config": {"freshness_hours": 8, "stale_after_hours": 24}}
	r.hosts[0].state == "stale_unreachable"
}

test_bad_config_falls_back_and_is_reported if {
	r := main.compliance_report with input as {"hosts": [base], "config": {"freshness_hours": "soon"}}
	r.config.freshness_hours == 26
	r.compliant == true
	some a in r.advisories
	contains(a, "config.freshness_hours")
}

test_stale_window_never_shorter_than_freshness if {
	r := main.compliance_report with input as {"hosts": [base], "config": {"freshness_hours": 100, "stale_after_hours": 10}}
	r.config.stale_after_hours >= r.config.freshness_hours
}

test_unknown_provider_state_is_not_trusted_as_running_or_gone if {
	h := object.union(base, {"provider_state": "rebooting"})
	r := report([h])
	r.hosts[0].provider_state == "unknown"
	r.hosts[0].state == "active"
}

test_mixed_estate_counts if {
	r := report([
		base,
		object.union(base, {"name": "db-01", "in_inventory": false, "provider_state": "absent"}),
		object.union(base, {"name": "old-01", "in_inventory": false, "provider_state": "absent", "retirement": record, "last_attempt": {"outcome": "ok", "hours_ago": 50}}),
	])
	r.states.active == 1
	r.states.missing == 1
	r.states.retired == 1
	r.violation_count == 1
	r.compliant == false
}
