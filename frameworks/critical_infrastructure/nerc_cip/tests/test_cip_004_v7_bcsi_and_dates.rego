package nerc_cip.cip_004_test

import rego.v1

import data.nerc_cip.cip_004 as c

# Audit 2026-11-23: CIP-004-7 (R6, BCSI access), part labels, and a fixed clock
# for every date rule.

v7_now := time.parse_rfc3339_ns("2026-11-23T12:00:00Z")

v7_person := {
	"person_id": "p1",
	"access_level": "authorized_electronic_access",
	"employment_status": "active",
	"cyber_security_training": {"initial_completed": true, "last_completion_date": "2026-01-10T00:00:00Z", "record_maintained": true},
	"risk_assessment": {"completed": true, "completion_date": "2023-05-01T00:00:00Z", "completed_before_access_granted": true},
	"access_authorization": {"documented": true, "need_to_know_verified": true, "last_review_date": "2026-02-01T00:00:00Z"},
}

v7_entry := {
	"person_id": "p1",
	"access_type": "electronic",
	"authorized_before_provisioning": true,
	"authorization_record": true,
	"need_verified": true,
	"last_verification_date": "2026-02-01T00:00:00Z",
}

v7_good := {
	"security_awareness": {
		"program_documented": true,
		"quarterly_reinforcement": true,
		"methods_documented": true,
		"last_reinforcement_date": "2026-10-01T00:00:00Z",
	},
	"cyber_security_training": {
		"program_documented": true,
		"content": {
			"bes_cyber_system_overview": true,
			"security_controls_overview": true,
			"physical_security": true,
			"electronic_security": true,
			"incident_response": true,
			"acceptable_use": true,
		},
	},
	"personnel": [v7_person],
	"bcsi_access": {"program_documented": true, "provisioned": [v7_entry]},
}

v7_violations(i) := vs if {
	vs := c.violations with input as i with time.now_ns as v7_now
}

v7_reqs(i) := {v.requirement | some v in v7_violations(i)}

v7_person_patch(path, value) := json.patch(v7_good, [{"op": "add", "path": sprintf("/personnel/0/%s", [path]), "value": value}])

v7_entry_patch(ops) := json.patch(v7_good, [object.union(op, {"path": sprintf("/bcsi_access/provisioned/0/%s", [op.path])}) | some op in ops])

test_v7_complete_facts_compliant if {
	c.compliant with input as v7_good with time.now_ns as v7_now
	count(v7_violations(v7_good)) == 0
	c.report.standard == "CIP-004-7" with input as v7_good with time.now_ns as v7_now
}

# ---- labels ---------------------------------------------------------------------

test_v7_every_label_is_a_cip_004_7_part if {
	valid := {"R1.1", "R2", "R2.1", "R2.3", "R3", "R3.5", "R4.1", "R4.3", "R5.1", "R5.4", "R6", "R6.1", "R6.2", "R6.3"}
	every r in v7_reqs({}) {
		r in valid
	}
	stale := v7_person_patch("access_authorization/last_review_date", "2024-01-01T00:00:00Z")
	v7_reqs(stale) == {"R4.3"}
}

# Part 2.3 is 15 calendar months, not 365 days.
test_v7_training_14_months_old_is_current if {
	i := v7_person_patch("cyber_security_training/last_completion_date", "2025-09-20T00:00:00Z")
	c.training_completed_for_all_authorized_personnel with input as i with time.now_ns as v7_now
	old := v7_person_patch("cyber_security_training/last_completion_date", "2025-07-01T00:00:00Z")
	v7_reqs(old) == {"R2.3"}
}

# ---- R6: provisioned access to BCSI (new in CIP-004-7) ---------------------------

test_v7_r6_absent_list_is_evidence_missing if {
	i := json.remove(v7_good, ["/bcsi_access"])
	not c.compliant with input as i with time.now_ns as v7_now
	v7_reqs(i) == {"R6"}
	some v in v7_violations(i)
	startswith(v.description, "evidence missing — input.bcsi_access.provisioned")
}

test_v7_r6_empty_list_states_no_provisioned_access if {
	i := json.patch(v7_good, [{"op": "replace", "path": "/bcsi_access/provisioned", "value": []}])
	c.compliant with input as i with time.now_ns as v7_now
}

test_v7_r6_1_authorization_before_provisioning if {
	i := v7_entry_patch([{"op": "replace", "path": "authorized_before_provisioning", "value": false}])
	v7_reqs(i) == {"R6.1"}
	cec := v7_entry_patch([
		{"op": "replace", "path": "authorized_before_provisioning", "value": false},
		{"op": "add", "path": "cip_exceptional_circumstance", "value": true},
	])
	c.bcsi_access_authorized with input as cec with time.now_ns as v7_now
}

test_v7_r6_2_verification_every_15_months if {
	v7_reqs(v7_entry_patch([{"op": "replace", "path": "last_verification_date", "value": "2025-07-01T00:00:00Z"}])) == {"R6.2"}
	v7_reqs(v7_entry_patch([{"op": "replace", "path": "need_verified", "value": false}])) == {"R6.2"}
	v7_reqs(v7_entry_patch([{"op": "remove", "path": "authorization_record"}])) == {"R6.2"}
}

test_v7_r6_2_future_verification_date_is_a_finding if {
	i := v7_entry_patch([{"op": "replace", "path": "last_verification_date", "value": "2027-01-01T00:00:00Z"}])
	not c.bcsi_access_verified with input as i with time.now_ns as v7_now
	some v in v7_violations(i)
	v.requirement == "R6.2"
	contains(v.description, "later than the evaluation time")
}

# Part 6.3: by the end of the next calendar day after the termination action.
v7_terminated(term, removed) := v7_entry_patch(array.concat(
	[{"op": "add", "path": "termination_date", "value": term}],
	[{"op": "add", "path": "access_removed_date", "value": removed} | removed != null],
))

test_v7_r6_3_removed_next_calendar_day_passes if {
	i := v7_terminated("2026-11-10T09:00:00Z", "2026-11-11T23:30:00Z")
	c.bcsi_access_removed_on_termination with input as i with time.now_ns as v7_now
	count(v7_violations(i)) == 0
}

test_v7_r6_3_removed_two_days_later_fails if {
	v7_reqs(v7_terminated("2026-11-10T09:00:00Z", "2026-11-12T00:30:00Z")) == {"R6.3"}
}

test_v7_r6_3_never_removed_fails_once_window_closed if {
	v7_reqs(v7_terminated("2026-11-10T09:00:00Z", null)) == {"R6.3"}

	# Terminated this morning: the window is still open.
	c.bcsi_access_removed_on_termination with input as v7_terminated("2026-11-23T08:00:00Z", null) with time.now_ns as v7_now
}

test_v7_r6_3_future_removal_date_is_not_a_removal if {
	i := v7_terminated("2026-11-10T09:00:00Z", "2026-12-01T00:00:00Z")
	not c.bcsi_access_removed_on_termination with input as i with time.now_ns as v7_now
	some v in v7_violations(i)
	contains(v.description, "bcsi_access.provisioned[p1].access_removed_date")
	contains(v.description, "later than the evaluation time")
}

test_v7_r6_3_unparseable_termination_date_is_evidence_missing if {
	i := v7_terminated("last week", "2026-11-11T00:00:00Z")
	not c.bcsi_access_removed_on_termination with input as i with time.now_ns as v7_now
	some v in v7_violations(i)
	v.requirement == "R6.3"
	startswith(v.description, "evidence missing")
}

# ---- future and unusable dates on the older requirements ------------------------

test_v7_future_dates_fail_every_recency_rule if {
	future := "2027-06-01T00:00:00Z"
	cases := {
		"R2.3": v7_person_patch("cyber_security_training/last_completion_date", future),
		"R3.5": v7_person_patch("risk_assessment/completion_date", future),
		"R4.3": v7_person_patch("access_authorization/last_review_date", future),
		"R1.1": json.patch(v7_good, [{"op": "replace", "path": "/security_awareness/last_reinforcement_date", "value": future}]),
	}
	every req, i in cases {
		not c.compliant with input as i with time.now_ns as v7_now
		v7_reqs(i) == {req}
		count([v | some v in v7_violations(i); contains(v.description, "later than the evaluation time")]) == 1
	}
}

test_v7_unusable_dates_are_evidence_missing if {
	cases := {
		"R2.3": v7_person_patch("cyber_security_training/last_completion_date", "June"),
		"R4.3": json.remove(v7_good, ["/personnel/0/access_authorization/last_review_date"]),
		"R1.1": json.remove(v7_good, ["/security_awareness/last_reinforcement_date"]),
	}
	every req, i in cases {
		v7_reqs(i) == {req}
		count([v | some v in v7_violations(i); startswith(v.description, "evidence missing")]) == 1
	}
}

test_v7_revocation_dated_in_the_future_is_not_a_revocation if {
	base := json.patch(v7_good, [
		{"op": "replace", "path": "/personnel/0/employment_status", "value": "terminated"},
		{"op": "add", "path": "/personnel/0/termination_date", "value": "2026-11-20T00:00:00Z"},
		{"op": "add", "path": "/personnel/0/access_revocation", "value": {"completed": true, "completion_date": "2026-11-20T10:00:00Z"}},
	])
	c.access_revoked_timely_on_termination with input as base with time.now_ns as v7_now
	i := json.patch(base, [{"op": "replace", "path": "/personnel/0/access_revocation/completion_date", "value": "2026-11-24T00:00:00Z"}])
	not c.access_revoked_timely_on_termination with input as i with time.now_ns as v7_now
	"R5.1" in v7_reqs(i)
}
