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
	r := main.compliance_report with input as {"hosts": []}
	r.compliant == false
	contains(r.violations[0], "no hosts supplied")
}

test_duplicate_names_are_a_finding if {
	r := main.compliance_report with input as {"hosts": [base, base]}
	r.compliant == false
	some v in r.violations
	contains(v, "more than once")
}

test_malformed_record_is_a_finding if {
	s1 := main.compliance_report with input as {"hosts": [{"name": "x"}]}
	s1.hosts[0].state == "invalid_record"
	s2 := main.compliance_report with input as {"hosts": [{"in_inventory": true}]}
	s2.hosts[0].state == "invalid_record"
	s3 := main.compliance_report with input as {"hosts": [{"name": "x", "in_inventory": "yes"}]}
	s3.hosts[0].state == "invalid_record"
	r := main.compliance_report with input as {"hosts": [{"in_inventory": true}]}
	r.compliant == false
	r.hosts[0].name == "record #0"
}

# ── Healthy and advisory states ─────────────────────────────────────────────

test_active_host_is_compliant if {
	s4 := main.compliance_report with input as {"hosts": [base]}
	s4.hosts[0].state == "active"
	r := main.compliance_report with input as {"hosts": [base]}
	r.compliant == true
	r.advisory_count == 0
}

test_late_is_an_advisory_not_a_finding if {
	h := object.union(base, {"hours_since_evaluated": 30, "last_attempt": {"outcome": "unreachable", "hours_ago": 2}})
	s5 := main.compliance_report with input as {"hosts": [h]}
	s5.hosts[0].state == "late"
	r := main.compliance_report with input as {"hosts": [h]}
	r.compliant == true
	r.advisory_count == 1
}

test_new_host_inside_grace_is_an_advisory if {
	h := object.union(object.remove(base, ["hours_since_evaluated"]), {"hours_since_first_seen": 10})
	s6 := main.compliance_report with input as {"hosts": [h]}
	s6.hosts[0].state == "new"
	rr := main.compliance_report with input as {"hosts": [h]}
	rr.compliant == true
}

test_never_evaluated_after_grace_is_stale if {
	h := object.union(object.remove(base, ["hours_since_evaluated", "last_attempt"]), {"hours_since_first_seen": 200})
	s7 := main.compliance_report with input as {"hosts": [h]}
	s7.hosts[0].state == "stale_not_targeted"
	rr := main.compliance_report with input as {"hosts": [h]}
	contains(rr.violations[0], "never")
}

test_stopped_is_flagged_not_failed_by_default if {
	h := object.union(base, {"provider_state": "stopped", "hours_since_evaluated": 500})
	s8 := main.compliance_report with input as {"hosts": [h]}
	s8.hosts[0].state == "stopped"
	r := main.compliance_report with input as {"hosts": [h]}
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
	s9 := main.compliance_report with input as {"hosts": [h]}
	s9.hosts[0].state == "stale_unreachable"
	r := main.compliance_report with input as {"hosts": [h]}
	r.compliant == false
	contains(r.violations[0], "CA-7")
}

test_stale_failing if {
	h := object.union(base, {"hours_since_evaluated": 80, "last_attempt": {"outcome": "failed", "hours_ago": 4}})
	s10 := main.compliance_report with input as {"hosts": [h]}
	s10.hosts[0].state == "stale_failing"
}

test_stale_no_evidence if {
	h := object.union(base, {"hours_since_evaluated": 80})
	s11 := main.compliance_report with input as {"hosts": [h]}
	s11.hosts[0].state == "stale_no_evidence"
}

test_stale_not_targeted if {
	h := object.union(object.remove(base, ["last_attempt"]), {"hours_since_evaluated": 80})
	s12 := main.compliance_report with input as {"hosts": [h]}
	s12.hosts[0].state == "stale_not_targeted"
}

# ── Disappeared ─────────────────────────────────────────────────────────────

test_gone_from_inventory_without_record_is_missing if {
	h := object.union(base, {"in_inventory": false, "provider_state": "absent"})
	s13 := main.compliance_report with input as {"hosts": [h]}
	s13.hosts[0].state == "missing"
	r := main.compliance_report with input as {"hosts": [h]}
	r.compliant == false
	contains(r.violations[0], "unexplained disappearance")
}

test_inventory_absence_with_unknown_provider_is_missing if {
	s14 := main.compliance_report with input as {"hosts": [object.union(base, {"in_inventory": false, "provider_state": "unknown"})]}
	s14.hosts[0].state == "missing"
}

test_stopped_instance_dropped_from_inventory_is_stopped_not_missing if {
	h := object.union(base, {"in_inventory": false, "provider_state": "stopped", "hours_since_evaluated": 90})
	s15 := main.compliance_report with input as {"hosts": [h]}
	s15.hosts[0].state == "stopped"
	rr := main.compliance_report with input as {"hosts": [h]}
	rr.compliant == true
}

test_running_but_in_no_inventory_is_unmanaged if {
	h := object.union(base, {"in_inventory": false, "provider_state": "running"})
	s16 := main.compliance_report with input as {"hosts": [h]}
	s16.hosts[0].state == "unmanaged_running"
	r := main.compliance_report with input as {"hosts": [h]}
	r.compliant == false
	contains(r.violations[0], "nothing is managing")
}

test_provider_terminated_without_record_is_missing if {
	s17 := main.compliance_report with input as {"hosts": [object.union(base, {"provider_state": "terminated"})]}
	s17.hosts[0].state == "missing"
	s18 := main.compliance_report with input as {"hosts": [object.union(base, {"provider_state": "absent"})]}
	s18.hosts[0].state == "missing"
}

test_removed_by_named_actor_without_record_is_still_a_finding if {
	h := object.union(base, {"in_inventory": false, "provider_state": "unknown", "removal_event": {"source": "user", "by": "admin", "hours_ago": 20}})
	s19 := main.compliance_report with input as {"hosts": [h]}
	s19.hosts[0].state == "removed_unrecorded"
	r := main.compliance_report with input as {"hosts": [h]}
	r.compliant == false
	contains(r.violations[0], "removed by admin")
}

# ── Retired on purpose ──────────────────────────────────────────────────────

test_recorded_and_gone_is_retired if {
	h := object.union(base, {
		"in_inventory": false, "provider_state": "terminated", "retirement": record,
		"last_attempt": {"outcome": "ok", "hours_ago": 40},
	})
	s20 := main.compliance_report with input as {"hosts": [h]}
	s20.hosts[0].state == "retired"
	rr := main.compliance_report with input as {"hosts": [h]}
	rr.compliant == true
}

test_recorded_but_still_in_inventory_is_incomplete if {
	h := object.union(base, {"retirement": record, "last_attempt": {"outcome": "unreachable", "hours_ago": 2}})
	s21 := main.compliance_report with input as {"hosts": [h]}
	s21.hosts[0].state == "retirement_incomplete"
	r := main.compliance_report with input as {"hosts": [h]}
	r.compliant == true
	r.advisory_count == 1
}

test_retired_host_that_still_answers_is_a_zombie if {
	h := object.union(base, {"retirement": record, "last_attempt": {"outcome": "ok", "hours_ago": 2}})
	s22 := main.compliance_report with input as {"hosts": [h]}
	s22.hosts[0].state == "zombie"
	r := main.compliance_report with input as {"hosts": [h]}
	r.compliant == false
	contains(r.violations[0], "28 h after the retirement")
}

test_answer_before_the_retirement_is_not_a_zombie if {
	h := object.union(base, {"in_inventory": false, "provider_state": "absent", "retirement": record, "last_attempt": {"outcome": "ok", "hours_ago": 31}})
	s23 := main.compliance_report with input as {"hosts": [h]}
	s23.hosts[0].state == "retired"
}

test_a_bare_declared_flag_is_not_a_record if {
	h := object.union(base, {"in_inventory": false, "provider_state": "absent", "retirement": {"declared": true}})
	s24 := main.compliance_report with input as {"hosts": [h]}
	s24.hosts[0].state == "missing"
	h2 := object.union(base, {"in_inventory": false, "provider_state": "absent", "retirement": object.remove(record, ["by"])})
	s25 := main.compliance_report with input as {"hosts": [h2]}
	s25.hosts[0].state == "missing"
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
	r := main.compliance_report with input as {"hosts": [h]}
	r.hosts[0].provider_state == "unknown"
	r.hosts[0].state == "active"
}

test_mixed_estate_counts if {
	r := main.compliance_report with input as {"hosts": [
		base,
		object.union(base, {"name": "db-01", "in_inventory": false, "provider_state": "absent"}),
		object.union(base, {"name": "old-01", "in_inventory": false, "provider_state": "absent", "retirement": record, "last_attempt": {"outcome": "ok", "hours_ago": 50}}),
	]}
	r.states.active == 1
	r.states.missing == 1
	r.states.retired == 1
	r.violation_count == 1
	r.compliant == false
}
