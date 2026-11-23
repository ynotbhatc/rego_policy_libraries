package nerc_cip_audit_1123_test

import rego.v1

# Weekly audit 2026-11-23. Two properties, for every CIP detail module:
#   1. a date-recency rule accepts a recent date, and rejects a stale date, a
#      date later than the evaluation time (finding) and an absent or
#      unparseable date (evidence missing);
#   2. every requirement label a finding carries is a requirement or part that
#      exists in the standard version the module cites.
# The clock is pinned with `with time.now_ns as now`.

now := time.parse_rfc3339_ns("2026-11-23T00:00:00Z")

future := "2027-06-01T00:00:00Z"

sys := [{"system_id": "S1", "impact_categorization": "high"}]

# mod / rule: data.nerc_cip[mod][rule]; base: facts that make the rule depend on
# the date alone; ptr: where the date goes; path: how the finding names it.
recency_cases := [
	{
		"mod": "cip_002",
		"rule": "annual_review_performed",
		"base": {"categorization_documentation": {}},
		"ptr": "/categorization_documentation/last_review_date",
		"path": "categorization_documentation.last_review_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	# 2025-10-01 is more than 365 days back: Part 2.2 is 15 calendar months, not a calendar year.
	{
		"mod": "cip_002",
		"rule": "cip_senior_manager_approval",
		"base": {"categorization_documentation": {"cip_senior_manager_approved": true}},
		"ptr": "/categorization_documentation/approval_date",
		"path": "categorization_documentation.approval_date",
		"good": "2025-10-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_006",
		"rule": "physical_security_plan_current",
		"base": {"physical_security_plan": {}},
		"ptr": "/physical_security_plan/last_review_date",
		"path": "physical_security_plan.last_review_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_006",
		"rule": "physical_access_authorization_reviewed",
		"base": {"personnel": [{"person_id": "p1", "access_level": "authorized_unescorted_physical_access", "physical_access_authorization": {}}]},
		"ptr": "/personnel/0/physical_access_authorization/last_review_date",
		"path": "personnel[p1].physical_access_authorization.last_review_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_008",
		"rule": "incident_response_plan_current",
		"base": {"incident_response_plan": {}},
		"ptr": "/incident_response_plan/last_review_date",
		"path": "incident_response_plan.last_review_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_008",
		"rule": "incident_response_testing_performed",
		"base": {"incident_response_testing": {}},
		"ptr": "/incident_response_testing/last_test_date",
		"path": "incident_response_testing.last_test_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_008",
		"rule": "incident_response_team_trained",
		"base": {"incident_response_team": [{"member_id": "m1", "training": {"completed": true}}]},
		"ptr": "/incident_response_team/0/training/completion_date",
		"path": "incident_response_team[m1].training.completion_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_009",
		"rule": "activation_criteria_tested",
		"base": {"recovery_plans": {"activation_criteria_tested": true}},
		"ptr": "/recovery_plans/last_activation_test_date",
		"path": "recovery_plans.last_activation_test_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_009",
		"rule": "recovery_plans_current",
		"base": {"bes_cyber_systems": sys, "recovery_plans": {"S1": {}}},
		"ptr": "/recovery_plans/S1/last_review_date",
		"path": "recovery_plans[S1].last_review_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_009",
		"rule": "recovery_testing_performed",
		"base": {"bes_cyber_systems": sys, "recovery_testing": {"S1": {"test_documented": true, "issues_resolved": true}}},
		"ptr": "/recovery_testing/S1/last_test_date",
		"path": "recovery_testing[S1].last_test_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_009",
		"rule": "backup_testing_performed",
		"base": {"bes_cyber_systems": sys, "backup_procedures": {"S1": {"test_documented": true, "restoration_verified": true}}},
		"ptr": "/backup_procedures/S1/last_test_date",
		"path": "backup_procedures[S1].last_test_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_010",
		"rule": "configuration_monitoring_timely",
		"base": {"bes_cyber_systems": sys, "configuration_monitoring": {"S1": {}}},
		"ptr": "/configuration_monitoring/S1/last_review_date",
		"path": "configuration_monitoring[S1].last_review_date",
		"good": "2026-11-01T00:00:00Z",
		"stale": "2026-09-01T00:00:00Z",
	},
	{
		"mod": "cip_010",
		"rule": "vulnerability_assessments_performed",
		"base": {"bes_cyber_systems": sys, "vulnerability_assessments": {"S1": {"documented": true, "remediation_plan_exists": true}}},
		"ptr": "/vulnerability_assessments/S1/completion_date",
		"path": "vulnerability_assessments[S1].completion_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_011",
		"rule": "bcsi_access_reviewed",
		"base": {"bcsi_access_list": [{"person_id": "p1"}]},
		"ptr": "/bcsi_access_list/0/last_review_date",
		"path": "bcsi_access_list[p1].last_review_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_013",
		"rule": "supply_chain_plan_review_current",
		"base": {"supply_chain_plan": {}},
		"ptr": "/supply_chain_plan/last_review_date",
		"path": "supply_chain_plan.last_review_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_013",
		"rule": "cip_senior_manager_approved",
		"base": {"supply_chain_plan": {"cip_senior_manager_approved": true}},
		"ptr": "/supply_chain_plan/approval_date",
		"path": "supply_chain_plan.approval_date",
		"good": "2026-01-01T00:00:00Z",
		"stale": "2025-06-01T00:00:00Z",
	},
	{
		"mod": "cip_013",
		"rule": "vendor_risk_assessments_performed",
		"base": {"vendors": [{"vendor_id": "V1", "criticality_level": "high"}], "vendor_risk_assessments": {"V1": {"completed": true, "risks_identified": true, "mitigation_plan_exists": true}}},
		"ptr": "/vendor_risk_assessments/V1/completion_date",
		"path": "vendor_risk_assessments[V1].completion_date",
		"good": "2025-01-01T00:00:00Z",
		"stale": "2022-01-01T00:00:00Z",
	},
	{
		"mod": "cip_014",
		"rule": "risk_assessment_current",
		"base": {"transmission_risk_assessment": {}},
		"ptr": "/transmission_risk_assessment/last_assessment_date",
		"path": "transmission_risk_assessment.last_assessment_date",
		"good": "2025-01-01T00:00:00Z",
		"stale": "2023-01-01T00:00:00Z",
	},
	{
		"mod": "cip_014",
		"rule": "third_party_verification_timely",
		"base": {"transmission_risk_assessment": {"third_party_verification": {"timely": true}}},
		"ptr": "/transmission_risk_assessment/third_party_verification/last_verification_date",
		"path": "transmission_risk_assessment.third_party_verification.last_verification_date",
		"good": "2025-01-01T00:00:00Z",
		"stale": "2023-01-01T00:00:00Z",
	},
	{
		"mod": "cip_014",
		"rule": "security_plans_reviewed",
		"base": {"applicable_transmission_stations": [{"station_id": "T1"}], "station_security_plans": {"T1": {}}},
		"ptr": "/station_security_plans/T1/last_review_date",
		"path": "station_security_plans[T1].last_review_date",
		"good": "2025-01-01T00:00:00Z",
		"stale": "2022-01-01T00:00:00Z",
	},
]

with_date(c, d) := json.patch(c.base, [{"op": "add", "path": c.ptr, "value": d}])

rule_holds(c, i) if data.nerc_cip[c.mod][c.rule] == true with input as i with time.now_ns as now

# Descriptions of the findings that name the case's date path.
date_findings(c, i) := {v.description |
	some v in data.nerc_cip[c.mod].violations with input as i with time.now_ns as now
	contains(v.description, sprintf("input.%s ", [c.path]))
}

test_recent_date_passes if {
	every c in recency_cases {
		i := with_date(c, c.good)
		rule_holds(c, i)
		count(date_findings(c, i)) == 0
	}
}

test_stale_date_fails_without_an_evidence_finding if {
	every c in recency_cases {
		i := with_date(c, c.stale)
		not rule_holds(c, i)
		count(date_findings(c, i)) == 0
	}
}

test_future_date_is_a_finding if {
	every c in recency_cases {
		i := with_date(c, future)
		not rule_holds(c, i)
		date_findings(c, i) == {sprintf("input.%s (%s) is later than the evaluation time — a future date is not evidence of a completed activity", [c.path, future])}
	}
}

test_unparseable_date_is_evidence_missing if {
	every c in recency_cases {
		every bad in ["2026-13-45", "last month", true, {}] {
			i := with_date(c, bad)
			not rule_holds(c, i)
			date_findings(c, i) == {sprintf("evidence missing — input.%s not collected or not an RFC 3339 date", [c.path])}
		}
	}
}

test_absent_date_is_evidence_missing if {
	every c in recency_cases {
		not rule_holds(c, c.base)
		date_findings(c, c.base) == {sprintf("evidence missing — input.%s not collected or not an RFC 3339 date", [c.path])}
	}
}

# Epoch nanoseconds stay accepted, with the same future rule.
test_epoch_nanoseconds_follow_the_same_rules if {
	c := recency_cases[0]
	rule_holds(c, with_date(c, now - (10 * 86400000000000)))
	not rule_holds(c, with_date(c, now + 86400000000000))
}

# ---- interval rules: the end date must not lie after the evaluation time --------

test_cip_008_future_plan_review_and_notification if {
	inc := {
		"incident_date": "2026-11-01T00:00:00Z",
		"plan_review_triggered": true,
		"plan_review_completion_date": "2026-11-15T00:00:00Z",
		"reportable_determination_time": "2026-11-01T01:00:00Z",
		"nerc_notification": {"sent": true, "sent_time": "2026-11-01T01:30:00Z"},
	}
	ok := {"reportable_cyber_incidents": [inc]}
	data.nerc_cip.cip_008.incident_triggered_plan_updates with input as ok with time.now_ns as now
	data.nerc_cip.cip_008.nerc_notification_timely with input as ok with time.now_ns as now

	late_review := {"reportable_cyber_incidents": [object.union(inc, {"plan_review_completion_date": "2026-12-15T00:00:00Z"})]}
	not data.nerc_cip.cip_008.incident_triggered_plan_updates with input as late_review with time.now_ns as now
	vs := data.nerc_cip.cip_008.violations with input as late_review with time.now_ns as now
	count([v |
		some v in vs
		startswith(v.description, "input.reportable_cyber_incidents[0].plan_review_completion_date (2026-12-15T00:00:00Z)")
		contains(v.description, "is later than the evaluation time")
	]) == 1

	# The same data read three weeks later is a completed review.
	data.nerc_cip.cip_008.incident_triggered_plan_updates with input as late_review with time.now_ns as time.parse_rfc3339_ns("2026-12-20T00:00:00Z")

	slow := {"reportable_cyber_incidents": [object.union(inc, {"nerc_notification": {"sent": true, "sent_time": "2026-11-01T03:00:00Z"}})]}
	not data.nerc_cip.cip_008.nerc_notification_timely with input as slow with time.now_ns as now
}

test_cip_009_future_post_event_review if {
	ev := {"event_date": "2026-11-01T00:00:00Z", "plan_review_triggered": true, "plan_review_completion_date": "2026-11-15T00:00:00Z"}
	data.nerc_cip.cip_009.post_event_plan_updates with input as {"qualifying_recovery_events": [ev]} with time.now_ns as now
	i := {"qualifying_recovery_events": [object.union(ev, {"plan_review_completion_date": "2026-12-15T00:00:00Z"})]}
	not data.nerc_cip.cip_009.post_event_plan_updates with input as i with time.now_ns as now
}

# An absent qualifying_recovery_events key is "applicability not determined".
test_cip_009_undeclared_events_fail_closed if {
	not data.nerc_cip.cip_009.post_event_plan_updates with input as {}
	data.nerc_cip.cip_009.post_event_plan_updates with input as {"qualifying_recovery_events": false}
	data.nerc_cip.cip_009.post_event_plan_updates with input as {"qualifying_recovery_events": []}
	vs := data.nerc_cip.cip_009.violations with input as {}
	"CIP-009 R3.1: applicability not determined — qualifying_recovery_events not declared" in {v.description | some v in vs}
}

# CIP-014-3 R6 Part 6.2: third party review within 90 calendar days (was 60).
station_plan(review_date) := {
	"applicable_transmission_stations": [{"station_id": "T1"}],
	"station_security_plans": {"T1": {
		"initial_completion_date": "2026-06-01T00:00:00Z",
		"third_party_review": {"performed": true, "unaffiliated": true, "relevant_expertise": true, "documented": true, "date": review_date},
	}},
}

test_cip_014_third_party_review_window_is_90_days if {
	# 81 days after completion
	data.nerc_cip.cip_014.physical_security_plan_third_party_reviewed with input as station_plan("2026-08-21T00:00:00Z") with time.now_ns as now

	# 102 days after completion
	not data.nerc_cip.cip_014.physical_security_plan_third_party_reviewed with input as station_plan("2026-09-11T00:00:00Z") with time.now_ns as now
}

test_cip_014_future_third_party_review_is_a_finding if {
	early := time.parse_rfc3339_ns("2026-07-01T00:00:00Z")
	i := station_plan("2026-08-21T00:00:00Z")
	not data.nerc_cip.cip_014.physical_security_plan_third_party_reviewed with input as i with time.now_ns as early
	vs := data.nerc_cip.cip_014.violations with input as i with time.now_ns as early
	some v in vs
	v.requirement == "R6.2"
	contains(v.description, "station_security_plans[T1].third_party_review.date")
	contains(v.description, "later than the evaluation time")
}

# ---- CIP-015 (array-shaped findings, package nerc_cip_cip015) --------------------

insm(review, doc_review) := {"insm": {
	"categorization_review_date": review,
	"documentation_review": {"documented": true, "reviewer": "A. Reviewer", "last_review_date": doc_review},
}}

cip015_descriptions(i) := {v.description | some v in data.nerc_cip_cip015.cip_015_violations with input as i with time.now_ns as now}

test_cip_015_review_dates if {
	ok := insm("2026-06-01T00:00:00Z", "2026-01-01T00:00:00Z")
	data.nerc_cip_cip015.r1_annual_review_current with input as ok with time.now_ns as now
	data.nerc_cip_cip015.r3_review_current with input as ok with time.now_ns as now

	fut := insm(future, future)
	not data.nerc_cip_cip015.r1_annual_review_current with input as fut with time.now_ns as now
	not data.nerc_cip_cip015.r3_review_current with input as fut with time.now_ns as now
	count([d | some d in cip015_descriptions(fut); contains(d, "later than the evaluation time")]) == 2

	bad := insm("n/a", null)
	not data.nerc_cip_cip015.r1_annual_review_current with input as bad with time.now_ns as now
	"evidence missing — input.insm.categorization_review_date not collected or not an RFC 3339 date" in cip015_descriptions(bad)
	"evidence missing — input.insm.documentation_review.last_review_date not collected or not an RFC 3339 date" in cip015_descriptions(bad)
}

# CIP-015-1 has R1 (Parts 1.1-1.3), R2 retention and R3 protection. The module
# checks R1 only, and says so.
test_cip_015_findings_cite_cip_015_1_parts if {
	i := {"insm": {"systems": [{"system_id": "S1", "impact_categorization": "high", "has_external_routable_connectivity": true, "esp_name": "ESP-1"}]}}
	vs := data.nerc_cip_cip015.cip_015_violations with input as i with time.now_ns as now
	{v.requirement | some v in vs} == {"R1"}
	{v.sub_requirement | some v in vs; v.system_id == "S1"} == {"R1.2", "R1.3"}
	r := data.nerc_cip_cip015.cip_015_compliance_report with input as i with time.now_ns as now
	r.standard == "CIP-015-1"
	r.metadata.us_effective_date == "2028-10-01"
	"R2 retention of INSM data" in r.not_implemented
}

# ---- requirement labels exist in the cited standard version ------------------------

valid_parts := {
	"cip_002": {"R1", "R1.1", "R1.2", "R1.3", "R2.1", "R2.2"},
	"cip_003": {"R1", "R1.1.1", "R1.1.2", "R1.1.3", "R1.1.4", "R1.1.5", "R1.1.6", "R1.1.7", "R1.1.8", "R1.1.9", "R1.2.1", "R1.2.2", "R1.2.3", "R1.2.4", "R1.2.5", "R1.2.6", "R1.2.7", "R2", "R3", "R4"},
	"cip_004": {"R1.1", "R2", "R2.1", "R2.2", "R2.3", "R3", "R3.5", "R4.1", "R4.2", "R4.3", "R5.1", "R5.2", "R5.3", "R5.4", "R6", "R6.1", "R6.2", "R6.3"},
	"cip_005": {"R1", "R1.1", "R1.2", "R1.3", "R1.4", "R1.5", "R2", "R2.1", "R2.2", "R2.3", "R2.4", "R2.5", "R3.1", "R3.2"},
	"cip_006": {"R1", "R1.1", "R1.2", "R1.3", "R1.4", "R1.5", "R1.6", "R1.7", "R1.8", "R1.9", "R1.10", "R2", "R2.1", "R2.2", "R2.3", "R3.1"},
	"cip_007": {"R1", "R1.1", "R1.2", "R2.1", "R2.2", "R2.3", "R2.4", "R3.1", "R3.2", "R3.3", "R4.1", "R4.2", "R4.3", "R4.4", "R5.1", "R5.2", "R5.3", "R5.4", "R5.5", "R5.6", "R5.7"},
	"cip_008": {"R1", "R1.1", "R1.2", "R1.3", "R1.4", "R2.1", "R2.2", "R2.3", "R3", "R3.1", "R3.2", "R4", "R4.1", "R4.2", "R4.3"},
	"cip_009": {"R1", "R1.1", "R1.2", "R1.3", "R1.4", "R1.5", "R2", "R2.1", "R2.2", "R2.3", "R3", "R3.1", "R3.2"},
	"cip_010": {"R1", "R1.1", "R1.2", "R1.3", "R1.4", "R1.5", "R1.6", "R2.1", "R3", "R3.1", "R3.2", "R3.3", "R3.4", "R4"},
	"cip_011": {"R1", "R1.1", "R1.2", "R2", "R2.1", "R2.2"},
	"cip_012": {"R1", "R1.1", "R1.2", "R1.3", "R1.4", "R1.5"},
	"cip_013": {"R1", "R1.1", "R1.2.1", "R1.2.2", "R1.2.3", "R1.2.4", "R1.2.5", "R1.2.6", "R2", "R3"},
	"cip_014": {"R1", "R1.1", "R1.2", "R2", "R2.1", "R2.2", "R2.3", "R2.4", "R3", "R4", "R5", "R6", "R6.1", "R6.2", "R6.3", "R6.4"},
}

# Inputs chosen to make the per-item findings fire as well as the fail-closed ones.
label_inputs := [
	{},
	{
		"bes_cyber_systems": [{"system_id": "S1", "impact_categorization": "high"}, {"system_id": "L1", "impact_categorization": "low"}],
		"personnel": [{"person_id": "p1", "access_level": "authorized_unescorted_physical_access", "employment_status": "terminated", "had_shared_account_access": true}],
		"bcsi_access": {"provisioned": [{"person_id": "p1", "termination_date": "2026-01-01T00:00:00Z"}]},
		"bcsi_access_list": [{"person_id": "p1"}],
		"user_accounts": [{"shared": true}],
		"security_patches": [{"applicable": true}],
		"configuration_changes": [{"is_major_change": true}],
		"electronic_access_control_systems": [{}],
		"physical_access_control_systems": [{}],
		"protected_cyber_assets": [{}],
		"standalone_bes_cyber_assets": [{"impact_categorization": "high"}],
		"bes_environment_changes": [{}],
		"reportable_cyber_incidents": [{}],
		"qualifying_recovery_events": [{}],
		"vendors": [{"vendor_id": "V1", "criticality_level": "high"}],
		"applicable_transmission_stations": [{"station_id": "T1"}],
		"transmission_topology_changes": [{}],
		"system_redeployments": [{}],
		"bcsi_third_party_sharing": [{}],
		"media_disposals": [{}],
		"control_center_communications": {"links": [{}]},
		"low_impact_plan": {"vendor_electronic_remote_access": {"allowed": true}},
		"cybersecurity_organization": {"delegated_authority": {"exists": true}},
	},
]

test_every_finding_label_is_a_part_of_the_cited_standard if {
	every mod, parts in valid_parts {
		every i in label_inputs {
			vs := data.nerc_cip[mod].violations with input as i with time.now_ns as now
			count(vs) > 3
			every v in vs {
				v.requirement in parts
			}
		}
	}
}

# The version each module reports is the one mandatory and enforceable in the US
# on 2026-11-23 (NERC "US Effective Date Status - Functional Applicability").
test_reported_versions_are_the_enforceable_ones if {
	enforceable := {
		"cip_002": "CIP-002-5.1a", "cip_003": "CIP-003-9", "cip_004": "CIP-004-7", "cip_005": "CIP-005-7",
		"cip_006": "CIP-006-6", "cip_007": "CIP-007-6", "cip_008": "CIP-008-6", "cip_009": "CIP-009-6",
		"cip_010": "CIP-010-4", "cip_011": "CIP-011-3", "cip_012": "CIP-012-2", "cip_013": "CIP-013-2",
		"cip_014": "CIP-014-3",
	}
	every mod, version in enforceable {
		r := data.nerc_cip[mod].report with input as {}
		r.standard == version
	}
}
