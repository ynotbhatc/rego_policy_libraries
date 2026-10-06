package dora.rts_tlpt

import rego.v1

# DORA level-2 technical standard — Threat-led penetration testing (TLPT).
# Commission Delegated Regulation (EU) 2025/1190, applicable 2025-07-08
#
# Entity-side obligations only; checks are attestations keyed to the
# RTS article they implement. Fail-closed: absent or non-true facts
# are violations.

default compliant := false

violation contains msg if {
	not input.resilience_testing.tlpt.scope_determination.performed == true
	msg := "DORA RTS 2025/1190 Art.2: TLPT scope determination performed against the mandatory categories and authority-designation criteria — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.organisation.control_team_lead_appointed == true
	msg := "DORA RTS 2025/1190 Art.4(1): Control team lead appointed, responsible for day-to-day TLPT management — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.organisation.secrecy_controls_established == true
	msg := "DORA RTS 2025/1190 Art.4(2): Secrecy measures established: need-to-know access, blue team unaware, confidentiality arrangements, code names — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.risk_management.live_system_risk_assessed == true
	msg := "DORA RTS 2025/1190 Art.5: Risk assessment of testing live production systems performed and reviewed throughout the test — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.risk_management.pooled_joint_assessed == true
	msg := "DORA RTS 2025/1190 Art.6: For pooled/joint TLPT: per-entity risk assessment plus cooperative joint-risk identification — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.providers.selection_evidence_collected == true
	msg := "DORA RTS 2025/1190 Art.7(1)(a)-(d): Provider selection evidence collected: CVs, certifications, indemnity insurance, minimum references (3 TI / 5 testers) — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.providers.ti_team_requirements_met == true
	msg := "DORA RTS 2025/1190 Art.7(1)(e): Threat-intelligence team requirements met (experience thresholds, prior assignments, no blue-team conflicts, tester separation) — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.providers.red_team_requirements_met == true
	msg := "DORA RTS 2025/1190 Art.7(1)(f): Red-team requirements met (manager 5+ years, 2+ testers with 2+ years, 5+ prior assignments, TI independence) — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.providers.restoration_procedures_agreed == true
	msg := "DORA RTS 2025/1190 Art.7(1)(g)-(h): Restoration and clean-up procedures agreed: credential deletion, C2 deactivation, kill switches, malware removal, secure disposal — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.providers.prohibited_activities_defined == true
	msg := "DORA RTS 2025/1190 Art.7(1)(i): Prohibited-activity boundaries contractually set (no destruction, no uncontrolled modification, no out-of-scope systems) — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.providers.compliance_documented == true
	msg := "DORA RTS 2025/1190 Art.7(2): Provider-compliance evidence documented; exceptional non-compliant providers carry documented risk mitigations — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.preparation.initiation_submitted_3_months == true
	msg := "DORA RTS 2025/1190 Art.9(2): TLPT initiation documents submitted within 3 months of authority notification (project charter, contacts, channels, code name) — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.preparation.control_team_established == true
	msg := "DORA RTS 2025/1190 Art.9(4): Control team established with defined responsibilities — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.preparation.scope_spec_approved_by_board == true
	msg := "DORA RTS 2025/1190 Art.9(6)-(7): Scope specification submitted within 6 months and approved by the management body — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.preparation.providers_contracted_before_testing == true
	msg := "DORA RTS 2025/1190 Art.9(9): Tester and TI-provider procurement completed before the testing phase starts — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.threat_intelligence.targeted_scenarios_produced == true
	msg := "DORA RTS 2025/1190 Art.10(1)-(2): Targeted threat intelligence gathered; scenarios cover each in-scope critical/important function, varied by actor and TTPs — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.threat_intelligence.min_three_scenarios_selected == true
	msg := "DORA RTS 2025/1190 Art.10(3)-(4): Minimum 3 scenarios selected (at most 1 non-threat-led); pooled/joint includes a shared-provider scenario — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.threat_intelligence.report_approved == true
	msg := "DORA RTS 2025/1190 Art.10(5)-(6): Targeted threat-intelligence report delivered and approved by the TLPT authority — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.red_team.test_plan_approved == true
	msg := "DORA RTS 2025/1190 Art.11(1)-(3): Red-team test plan prepared from scope spec and TI report, approved by control team and TLPT authority — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.red_team.active_phase_min_12_weeks == true
	msg := "DORA RTS 2025/1190 Art.11(5): Active red-team phase lasts a minimum of 12 weeks — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.red_team.weekly_reporting == true
	msg := "DORA RTS 2025/1190 Art.11(7): Testers report at least weekly to control team and test managers during the active phase — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.red_team.legup_and_suspension_procedures == true
	msg := "DORA RTS 2025/1190 Art.11(8)-(10): Leg-up, detection-continuation and suspension/limited-purple-teaming procedures defined and approved — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.closure.red_team_report_4_weeks == true
	msg := "DORA RTS 2025/1190 Art.12(2): Red-team test report submitted within 4 weeks of active-phase end — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.closure.blue_team_report_10_weeks == true
	msg := "DORA RTS 2025/1190 Art.12(4): Blue-team test report submitted within 10 weeks of active-phase end — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.closure.purple_teaming_conducted == true
	msg := "DORA RTS 2025/1190 Art.12(5)-(6): Replay / purple-teaming exercise conducted within 10 weeks of active-phase end with mutual feedback — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.closure.summary_report_8_weeks == true
	msg := "DORA RTS 2025/1190 Art.12(7): Test summary report submitted within 8 weeks of authority assessment notification — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.remediation.plan_submitted_8_weeks == true
	msg := "DORA RTS 2025/1190 Art.13: Remediation plan submitted within 8 weeks: shortcomings, prioritized measures with dates, root causes, owners, residual risks — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.attestation.obtained == true
	msg := "DORA RTS 2025/1190 Art.14: Attestation obtained from the TLPT authority (DORA Art.26(7)) — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.internal_testers.policy_established == true
	msg := "DORA RTS 2025/1190 Art.15(1): Internal-tester management policy established (suitability, conflicts, staffing minimums, 12+ months employment) without degrading defence — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.internal_testers.authority_approved_and_disclosed == true
	msg := "DORA RTS 2025/1190 Art.15(2)-(3): Internal-tester use approved by the TLPT authority and disclosed in initiation info and reports — not attested"
}

violation contains msg if {
	not input.resilience_testing.tlpt.frequency.three_year_cycle_met == true
	msg := "DORA RTS 2025/1190 / DORA Art.26(1)+(8): TLPT performed at least every 3 years with external testers at least every third test (significant credit institutions: always external) — not attested"
}

compliant if {
	count(violation) == 0
}

compliance_report := {
	"family": "Threat-led penetration testing (TLPT)",
	"regulation": "Commission Delegated Regulation (EU) 2025/1190, applicable 2025-07-08",
	"controls_evaluated": 31,
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
