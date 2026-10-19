package nerc_cip.cip_008_test

import rego.v1

import data.nerc_cip.cip_008 as c

# Validation 2026-10-17: R5 and R2.2 gate compliance.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

member := {"plan_communicated": true, "training": {"completed": true, "completion_date": time.now_ns()}}

good := {
	"incident_response_plan": {
		"documented": true,
		"approved": true,
		"last_review_date": now_rfc,
		"roles_and_responsibilities": {"defined": true, "primary_lead": {"designated": true}, "backup_lead": {"designated": true}, "contact_list_current": true},
		"processes": {
			"incident_classification_criteria": true,
			"identification_procedures": true,
			"containment_procedures": true,
			"eradication_procedures": true,
			"recovery_procedures": true,
			"post_incident_review": true,
		},
		"reporting": {
			"nerc_notification_process": true,
			"e_isac_notification": true,
			"reporting_timeframe_defined": true,
			"reportable_incident_criteria_defined": true,
		},
		"classification": {
			"reportable_criteria_defined": true,
			"compromised_or_disrupted_operations": {"defined": true},
			"attempted_compromise": {"defined": true},
		},
	},
	"incident_response_testing": {
		"last_test_date": now_rfc,
		"test_documented": true,
		"test_type": "exercise",
		"participants_documented": true,
		"lessons_learned_captured": true,
		"lessons_learned": {"reviewed": true, "plan_updated_if_needed": true},
	},
	"incident_response_team": [member],
	"incident_identification": {"criteria_documented": true, "decision_process_documented": true},
	"reportable_cyber_incidents": false,
}

test_baseline_compliant if {
	c.compliant with input as good
}

# decisions 2026-10-19: an undeclared incident list fails closed.
test_undeclared_incident_list_fails_closed if {
	i := json.remove(good, ["reportable_cyber_incidents"])
	not c.incident_triggered_plan_updates with input as i
	not c.nerc_notification_timely with input as i
	not c.compliant with input as i
	count([v | some v in c.violations with input as i; contains(v.description, "applicability not determined — reportable_cyber_incidents")]) == 1
}

test_explicit_false_incident_list_is_not_applicable if {
	i := object.union(good, {"reportable_cyber_incidents": false})
	c.compliant with input as i
}

test_empty_incident_list_is_not_applicable if {
	c.compliant with input as object.union(good, {"reportable_cyber_incidents": []})
}

test_late_nerc_notification_breaks_compliance if {
	inc := {
		"incident_date": "2026-01-01T00:00:00Z",
		"plan_review_triggered": true,
		"plan_review_completion_date": "2026-01-10T00:00:00Z",
		"reportable_determination_time": "2026-01-01T01:00:00Z",
		"nerc_notification": {"sent": false},
	}
	i := object.union(good, {"reportable_cyber_incidents": [inc]})
	not c.nerc_notification_timely with input as i
	not c.compliant with input as i
	count([v | some v in c.violations with input as i; v.requirement == "R5"]) == 1
}

test_timely_notification_iso_passes if {
	inc := {
		"incident_date": "2026-01-01T00:00:00Z",
		"plan_review_triggered": true,
		"plan_review_completion_date": "2026-01-10T00:00:00Z",
		"reportable_determination_time": "2026-01-01T01:00:00Z",
		"nerc_notification": {"sent": true, "sent_time": "2026-01-01T01:30:00Z"},
	}
	c.compliant with input as object.union(good, {"reportable_cyber_incidents": [inc]})
}

test_late_plan_update_breaks_compliance if {
	inc := {
		"incident_date": "2026-01-01T00:00:00Z",
		"plan_review_triggered": true,
		"plan_review_completion_date": "2026-06-10T00:00:00Z",
		"reportable_determination_time": "2026-01-01T01:00:00Z",
		"nerc_notification": {"sent": true, "sent_time": "2026-01-01T01:30:00Z"},
	}
	i := object.union(good, {"reportable_cyber_incidents": [inc]})
	not c.incident_triggered_plan_updates with input as i
	not c.compliant with input as i
}

test_no_team_fails if {
	i := json.remove(good, ["incident_response_team"])
	not c.incident_response_team_trained with input as i
	not c.plan_communicated_to_personnel with input as i
}
