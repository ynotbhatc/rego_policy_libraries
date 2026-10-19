package nerc_cip.cip_004_test

import rego.v1

import data.nerc_cip.cip_004 as c

# Validation 2026-10-17: dates may be ISO-8601, missing evidence is not a pass.

now_rfc := time.format([time.now_ns(), "UTC", "2006-01-02T15:04:05Z07:00"])

person := {
	"person_id": "p1",
	"access_level": "authorized_electronic_access",
	"cyber_security_training": {"initial_completed": true, "last_completion_date": now_rfc, "record_maintained": true},
	"risk_assessment": {"completed": true, "completion_date": now_rfc, "completed_before_access_granted": true},
	"access_authorization": {"documented": true, "need_to_know_verified": true, "last_review_date": now_rfc},
}

with_person(p) := {"personnel": [p]}

test_good_person_passes_all_personnel_rules if {
	i := with_person(person)
	c.training_completed_for_all_authorized_personnel with input as i
	c.training_records_maintained with input as i
	c.personnel_risk_assessments_current with input as i
	c.pra_before_access_granted with input as i
	c.access_authorization_documented with input as i
	c.access_based_on_need_to_know with input as i
	c.access_authorization_reviewed with input as i
	c.access_revoked_timely_on_termination with input as i
	c.shared_accounts_managed with input as i
}

test_old_iso_review_date_fails_review if {
	p := json.patch(person, [{"op": "replace", "path": "/access_authorization/last_review_date", "value": "2019-01-01T00:00:00Z"}])
	not c.access_authorization_reviewed with input as with_person(p)
}

test_missing_review_date_fails_review if {
	p := json.remove(person, ["access_authorization/last_review_date"])
	not c.access_authorization_reviewed with input as with_person(p)
}

test_missing_pra_before_access_flag_fails if {
	p := json.remove(person, ["risk_assessment/completed_before_access_granted"])
	not c.pra_before_access_granted with input as with_person(p)
}

test_cyber_asset_access_needs_authorization_record if {
	p := json.patch(person, [{"op": "replace", "path": "/access_level", "value": "authorized_cyber_asset_access"}, {"op": "remove", "path": "/access_authorization"}])
	not c.access_authorization_documented with input as with_person(p)
}

test_empty_roster_not_compliant if {
	i := {"personnel": []}
	not c.training_records_maintained with input as i
	not c.training_completed_for_all_authorized_personnel with input as i
	not c.personnel_risk_assessments_current with input as i
	not c.access_authorization_reviewed with input as i
	not c.access_revoked_timely_on_termination with input as {}
}

test_iso_training_and_pra_dates_accepted if {
	p := json.patch(person, [{"op": "replace", "path": "/cyber_security_training/last_completion_date", "value": "2019-01-01T00:00:00Z"}])
	not c.training_completed_for_all_authorized_personnel with input as with_person(p)
}

test_termination_revocation_within_24h_iso if {
	p := {
		"person_id": "t1",
		"employment_status": "terminated",
		"termination_date": "2026-01-01T00:00:00Z",
		"access_revocation": {"completed": true, "completion_date": "2026-01-01T10:00:00Z"},
	}
	c.access_revoked_timely_on_termination with input as with_person(p)
	p2 := json.patch(p, [{"op": "replace", "path": "/access_revocation/completion_date", "value": "2026-01-03T10:00:00Z"}])
	not c.access_revoked_timely_on_termination with input as with_person(p2)
}

# Decisions 2026-10-19: documented flat risk_assessment_completed / _date contract.
flat_person := {
	"person_id": "p2",
	"access_level": "authorized_electronic_access",
	"risk_assessment_completed": true,
	"risk_assessment_date": now_rfc,
}

test_flat_risk_assessment_contract_is_current if {
	c.personnel_risk_assessments_current with input as with_person(flat_person)
}

test_flat_risk_assessment_not_completed_fails if {
	p := json.patch(flat_person, [{"op": "replace", "path": "/risk_assessment_completed", "value": false}])
	not c.personnel_risk_assessments_current with input as with_person(p)
}

test_flat_risk_assessment_old_date_fails if {
	p := json.patch(flat_person, [{"op": "replace", "path": "/risk_assessment_date", "value": "2010-01-01T00:00:00Z"}])
	not c.personnel_risk_assessments_current with input as with_person(p)
}
