package tsa_pipeline.deadlines_test

import rego.v1

# The deadlines ARE the assessable content of these directives. Each test pins
# one clock to the directive text so a future edit can't silently loosen it.
#
#   72 hours  SD-01G II.C.3    incident report to CISA
#   24 hours  SD-01G II.C.5.f  supplemental information
#    7 days   SD-01G II.B.1.e  Cybersecurity Coordinator info change
#   60 days   SD-02G II.A.5    "no Critical Cyber Systems" notice
#   45 days   SD-02G VI.C      threshold that makes a change "permanent"
#   50 days   SD-02G VI.D      amendment request filing
#   30 days   SD-02G VI.F      petition for reconsideration
#   12 months SD-02G III.F.1.e incident response plan exercise
#    2 objs   SD-02G III.F.1.e.i  minimum objectives per exercise
#   24 months SD-02G III.G.2.b architecture design review
#   33% / 100% SD-02G III.G.2.d annual / three-year assessment coverage
#   12 months SD-02G III.G.3-4 assessment plan and report submission
#   24 hours  SD-02G IV.C.2.e.ii  maximum packet capture period

violation_matching(violations, needle) if {
	some v in violations
	contains(v, needle)
}

# ── SD-01G II.C.3 — 72-hour CISA reporting ───────────────────────────────────

test_incident_reported_at_72_hours_is_compliant if {
	violations := data.tsa_pipeline.sd01_reporting.violations with input as {"incident_reporting": {"incidents": [{
		"id": "INC-1",
		"reported_to_cisa": true,
		"hours_to_report": 72,
		"sd_reporting_stated": true,
	}]}}
	not violation_matching(violations, "II.C.3: Cybersecurity incident 'INC-1' was reported")
}

test_incident_reported_after_72_hours_violates if {
	violations := data.tsa_pipeline.sd01_reporting.violations with input as {"incident_reporting": {"incidents": [{
		"id": "INC-2",
		"reported_to_cisa": true,
		"hours_to_report": 73,
		"sd_reporting_stated": true,
	}]}}
	violation_matching(violations, "II.C.3: Cybersecurity incident 'INC-2' was reported to CISA 73 hours")
}

test_unreported_incident_violates if {
	violations := data.tsa_pipeline.sd01_reporting.violations with input as {"incident_reporting": {"incidents": [{
		"id": "INC-3",
		"reported_to_cisa": false,
	}]}}
	violation_matching(violations, "II.C.3: Cybersecurity incident 'INC-3' was never reported to CISA")
}

# ── SD-01G II.C.5.f — 24-hour supplemental information ───────────────────────

test_supplemental_after_24_hours_violates if {
	violations := data.tsa_pipeline.sd01_reporting.violations with input as {"incident_reporting": {"incidents": [{
		"id": "INC-4",
		"reported_to_cisa": true,
		"hours_to_report": 10,
		"sd_reporting_stated": true,
		"initial_report_incomplete": true,
		"supplemental_hours_after_available": 25,
	}]}}
	violation_matching(violations, "II.C.5.f: Supplemental information for incident 'INC-4' was provided 25 hours")
}

# ── SD-01G II.B.1.e — 7-day coordinator information update ───────────────────

test_coordinator_info_change_within_7_days_is_compliant if {
	violations := data.tsa_pipeline.sd01_coordinator.violations with input as {"cybersecurity_coordinator": {"days_since_information_change": 7}}
	not violation_matching(violations, "II.B.1.e: Cybersecurity Coordinator information change is")
}

test_coordinator_info_change_after_7_days_violates if {
	violations := data.tsa_pipeline.sd01_coordinator.violations with input as {"cybersecurity_coordinator": {"days_since_information_change": 8}}
	violation_matching(violations, "II.B.1.e: Cybersecurity Coordinator information change is 8 days old")
}

# ── SD-01G II.B.1.c.ii — non-U.S. citizen trusted traveler membership ────────

test_non_us_citizen_without_trusted_traveler_violates if {
	violations := data.tsa_pipeline.sd01_coordinator.violations with input as {"cybersecurity_coordinator": {"primary": {
		"name": "A. Example",
		"us_citizen": false,
	}}}
	violation_matching(violations, "II.B.1.c.ii: Cybersecurity Coordinator 'A. Example' is a non-U.S. citizen")
}

test_non_us_citizen_with_nexus_membership_satisfies_c_ii if {
	violations := data.tsa_pipeline.sd01_coordinator.violations with input as {"cybersecurity_coordinator": {"primary": {
		"name": "A. Example",
		"us_citizen": false,
		"trusted_traveler_program": "NEXUS",
		"known_traveler_number": "123456789",
	}}}

	# Needle must include the colon: "II.B.1.c.ii" is a substring of "II.B.1.c.iii".
	not violation_matching(violations, "II.B.1.c.ii: Cybersecurity Coordinator")
}

# A program name with no identifier proves nothing — must still violate.
test_trusted_traveler_program_without_number_violates if {
	violations := data.tsa_pipeline.sd01_coordinator.violations with input as {"cybersecurity_coordinator": {"primary": {
		"name": "A. Example",
		"us_citizen": false,
		"trusted_traveler_program": "NEXUS",
	}}}
	violation_matching(violations, "II.B.1.c.ii: Cybersecurity Coordinator")
}

# ── SD-02G II.A.5 — 60-day "no Critical Cyber Systems" notice ────────────────

test_no_ccs_notice_after_60_days_violates if {
	violations := data.tsa_pipeline.sd02_critical_cyber_systems.violations with input as {"critical_cyber_systems": {"none_determination": {
		"declared": true,
		"tsa_notified_in_writing": true,
		"days_since_effective_date": 61,
	}}}
	violation_matching(violations, "II.A.5: A 'no Critical Cyber Systems' determination must be notified to TSA in writing within 60 days")
}

test_no_ccs_notice_within_60_days_is_compliant if {
	violations := data.tsa_pipeline.sd02_critical_cyber_systems.violations with input as {"critical_cyber_systems": {"none_determination": {
		"declared": true,
		"tsa_notified_in_writing": true,
		"days_since_effective_date": 60,
	}}}
	not violation_matching(violations, "II.A.5: A 'no Critical Cyber Systems' determination")
}

# ── SD-02G VI.C / VI.D — 45-day permanent change, 50-day filing ──────────────

test_change_of_44_days_is_not_permanent if {
	violations := data.tsa_pipeline.sd02_implementation_plan.violations with input as {"implementation_plan": {"amendments": {"pending_permanent_changes": [{
		"description": "temp firewall exception",
		"duration_days": 44,
		"days_since_effective": 60,
		"amendment_filed": false,
	}]}}}
	not violation_matching(violations, "VI.C: Change 'temp firewall exception'")
	not violation_matching(violations, "VI.D: The amendment request for permanent change 'temp firewall exception'")
}

test_change_of_45_days_is_permanent_and_requires_amendment if {
	violations := data.tsa_pipeline.sd02_implementation_plan.violations with input as {"implementation_plan": {"amendments": {"pending_permanent_changes": [{
		"description": "new SIEM",
		"duration_days": 45,
		"days_since_effective": 10,
		"amendment_filed": false,
	}]}}}
	violation_matching(violations, "VI.C: Change 'new SIEM' is intended to be in effect for 45 days")
}

test_amendment_filed_after_50_days_violates if {
	violations := data.tsa_pipeline.sd02_implementation_plan.violations with input as {"implementation_plan": {"amendments": {"pending_permanent_changes": [{
		"description": "new SIEM",
		"duration_days": 90,
		"days_since_effective": 51,
		"amendment_filed": true,
	}]}}}
	violation_matching(violations, "VI.D: The amendment request for permanent change 'new SIEM' is 51 days past")
}

# ── SD-02G VI.F — 30-day petition for reconsideration ────────────────────────

test_petition_after_30_days_violates if {
	violations := data.tsa_pipeline.sd02_implementation_plan.violations with input as {"implementation_plan": {"amendments": {"denials": [{
		"description": "zone redesign",
		"days_since_denial": 31,
		"petition_filed": false,
		"reconsideration_intended": true,
	}]}}}
	violation_matching(violations, "VI.F: A petition for reconsideration of the denied amendment 'zone redesign'")
}

# ── SD-02G III.F.1.e — annual exercise, minimum two objectives ───────────────

test_exercise_testing_one_objective_violates if {
	violations := data.tsa_pipeline.sd02_incident_response_plan.violations with input as {"incident_response_plan": {"exercises": {"objectives_tested": 1}}}
	violation_matching(violations, "III.F.1.e.i: Annual exercises tested 1 of the objectives")
}

test_exercise_testing_two_objectives_satisfies_minimum if {
	violations := data.tsa_pipeline.sd02_incident_response_plan.violations with input as {"incident_response_plan": {"exercises": {"objectives_tested": 2}}}
	not violation_matching(violations, "III.F.1.e.i: Annual exercises tested")
}

test_exercise_older_than_12_months_violates if {
	violations := data.tsa_pipeline.sd02_incident_response_plan.violations with input as {"incident_response_plan": {"exercises": {
		"conducted_within_last_12_months": true,
		"objectives_tested": 3,
		"months_since_last_exercise": 13,
	}}}
	violation_matching(violations, "III.F.1.e: The last Cybersecurity Incident Response Plan exercise was 13 months ago")
}

# ── SD-02G III.G.2.b — architecture design review every 24 months ────────────

test_architecture_review_at_24_months_is_compliant if {
	violations := data.tsa_pipeline.sd02_assessment_plan.violations with input as {"assessment_plan": {"architecture_design_review": {"months_since_last_review": 24}}}
	not violation_matching(violations, "III.G.2.b: The last cybersecurity architecture design review")
}

test_architecture_review_after_24_months_violates if {
	violations := data.tsa_pipeline.sd02_assessment_plan.violations with input as {"assessment_plan": {"architecture_design_review": {"months_since_last_review": 25}}}
	violation_matching(violations, "III.G.2.b: The last cybersecurity architecture design review was 25 months ago")
}

# ── SD-02G III.G.2.d — one-third annual / 100 percent three-year coverage ────

test_annual_coverage_below_one_third_violates if {
	violations := data.tsa_pipeline.sd02_assessment_plan.violations with input as {"assessment_plan": {"schedule": {"annual_coverage_percent": 32, "three_year_coverage_percent": 100}}}
	violation_matching(violations, "III.G.2.d: The assessment schedule covers 32 percent")
}

test_annual_coverage_of_one_third_is_compliant if {
	violations := data.tsa_pipeline.sd02_assessment_plan.violations with input as {"assessment_plan": {"schedule": {"annual_coverage_percent": 33, "three_year_coverage_percent": 100}}}
	not violation_matching(violations, "III.G.2.d: The assessment schedule covers")
	not violation_matching(violations, "III.G.2.d: The assessment schedule reaches")
}

test_three_year_coverage_below_100_violates if {
	violations := data.tsa_pipeline.sd02_assessment_plan.violations with input as {"assessment_plan": {"schedule": {"annual_coverage_percent": 40, "three_year_coverage_percent": 99}}}
	violation_matching(violations, "III.G.2.d: The assessment schedule reaches 99 percent coverage")
}

# ── SD-02G III.G.3 — annual plan submission within 12 months ─────────────────

test_plan_submitted_after_12_months_violates if {
	violations := data.tsa_pipeline.sd02_assessment_plan.violations with input as {"assessment_plan": {"submission": {"submitted_to_tsa": true, "months_since_previous_approval": 13}}}
	violation_matching(violations, "III.G.3: The Cybersecurity Assessment Plan was submitted 13 months")
}

# ── SD-02G IV.C.2.e.ii — packet capture must not exceed 24 hours ─────────────

test_packet_capture_over_24_hours_violates if {
	violations := data.tsa_pipeline.sd02_records.violations with input as {"records": {"activity_snapshot": {"packet_capture_max_hours": 25}}}
	violation_matching(violations, "IV.C.2.e.ii: Packet capture is configured for a 25-hour period")
}

test_packet_capture_at_24_hours_is_compliant if {
	violations := data.tsa_pipeline.sd02_records.violations with input as {"records": {"activity_snapshot": {"packet_capture_max_hours": 24}}}
	not violation_matching(violations, "IV.C.2.e.ii: Packet capture is configured")
}

# ── SD-02G III.B.2.b — OT traffic over IT must be encrypted ──────────────────

test_ot_traversing_it_unencrypted_violates if {
	violations := data.tsa_pipeline.sd02_network_segmentation.violations with input as {"network_segmentation": {"ot_services_traversing_it": {"occurs": true, "encrypted_in_transit": false}}}
	violation_matching(violations, "III.B.2.b: Operational Technology system services traverse")
}

test_ot_traversing_it_encrypted_is_compliant if {
	violations := data.tsa_pipeline.sd02_network_segmentation.violations with input as {"network_segmentation": {"ot_services_traversing_it": {"occurs": true, "encrypted_in_transit": true}}}
	not violation_matching(violations, "III.B.2.b")
}

# ── SD-02G III.C.2 — MFA control-room carve-out needs compensating controls ──

test_control_room_mfa_exemption_without_compensating_controls_violates if {
	violations := data.tsa_pipeline.sd02_access_control.violations with input as {"access_control": {"multi_factor_authentication": {
		"implemented": false,
		"control_room_workstations_exempt": true,
		"compensating_controls_specified": false,
	}}}
	violation_matching(violations, "III.C.2: Multi-factor authentication is not applied to industrial control workstations")
}

test_control_room_mfa_exemption_with_compensating_controls_is_compliant if {
	violations := data.tsa_pipeline.sd02_access_control.violations with input as {"access_control": {"multi_factor_authentication": {
		"implemented": false,
		"control_room_workstations_exempt": true,
		"compensating_controls_specified": true,
	}}}
	not violation_matching(violations, "III.C.2")
}
