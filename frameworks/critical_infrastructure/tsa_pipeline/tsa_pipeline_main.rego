package tsa_pipeline.main

import rego.v1

# =============================================================================
# TSA Pipeline Security Directives — Main Orchestrator
#
# Aggregates both currently-effective TSA pipeline cybersecurity directives:
#
#   SD Pipeline-2021-01G — "Enhancing Pipeline Cybersecurity"
#     Effective January 16, 2026 through January 15, 2027
#     Supersedes SD Pipeline-2021-01F
#       II.B  Cybersecurity Coordinator          [sd01_cybersecurity_coordinator.rego]
#       II.C  Reporting Cybersecurity Incidents  [sd01_incident_reporting.rego]
#       II.D  Cybersecurity Vulnerability Assmt  [sd01_vulnerability_assessment.rego]
#
#   SD Pipeline-2021-02G — "Pipeline Cybersecurity Mitigation Actions,
#                           Contingency Planning, and Testing"
#     Effective May 3, 2026 through May 2, 2027
#     Supersedes SD Pipeline-2021-02F
#       II.A/III.A  Scope + Critical Cyber Systems [sd02_critical_cyber_systems.rego]
#       II.B/VI     Implementation Plan + Amends   [sd02_implementation_plan.rego]
#       III.B       Network Segmentation           [sd02_network_segmentation.rego]
#       III.C       Access Control                 [sd02_access_control.rego]
#       III.D       Continuous Monitoring          [sd02_continuous_monitoring.rego]
#       III.E       Security Patches and Updates   [sd02_patch_management.rego]
#       III.F       Incident Response Plan         [sd02_incident_response_plan.rego]
#       III.G       Cybersecurity Assessment Plan  [sd02_assessment_plan.rego]
#       IV / V      Records and SSI Protection     [sd02_records.rego]
#
# Authority:  49 U.S.C. 114(d), (f), (l), and (m)
# Applies to: Owner/Operators of a hazardous liquid and natural gas pipeline or
#             a liquefied natural gas facility notified by TSA that their
#             pipeline system or facility is critical
# OPA bucket: ot  (opa_framework_map key: tsa_pipeline)
#
# --- FACT SOURCE STATUS ------------------------------------------------------
# NOTHING IN THE COMPLIANCE REPO EMITS THIS INPUT TODAY. Both directives are
# overwhelmingly plan-, attestation-, and recordkeeping-driven: "is there a
# TSA-approved Cybersecurity Implementation Plan", "was the Assessment Plan
# submitted within 12 months", "were at least one-third of measures assessed
# this year". None of that comes from Ansible host fact-gathering.
#
# On empty input this framework reports fully non-compliant across all 12
# sections. That is correct fail-closed behavior for an audit framework, but it
# is NOT a working assessment — do not demo it as one until a fact source
# (survey, attestation intake, or GRC export) is wired up on the Ansible side.
#
# OPA endpoint: POST <opa_ot_url>/v1/data/tsa_pipeline/main/compliance_report
# =============================================================================

import data.tsa_pipeline.sd01_coordinator
import data.tsa_pipeline.sd01_reporting
import data.tsa_pipeline.sd01_vulnerability_assessment
import data.tsa_pipeline.sd02_access_control
import data.tsa_pipeline.sd02_assessment_plan
import data.tsa_pipeline.sd02_continuous_monitoring
import data.tsa_pipeline.sd02_critical_cyber_systems
import data.tsa_pipeline.sd02_implementation_plan
import data.tsa_pipeline.sd02_incident_response_plan
import data.tsa_pipeline.sd02_network_segmentation
import data.tsa_pipeline.sd02_patch_management
import data.tsa_pipeline.sd02_records

# ── Violation aggregation ────────────────────────────────────────────────────
# array.concat() takes exactly 2 arrays — build the tree in pairs.

# --- SD Pipeline-2021-01G (3 sections) ---

sd01_pair_1 := array.concat(
	[v | some v in sd01_coordinator.violations],
	[v | some v in sd01_reporting.violations],
)

sd01_violations := array.concat(
	sd01_pair_1,
	[v | some v in sd01_vulnerability_assessment.violations],
)

# --- SD Pipeline-2021-02G (9 sections) ---

sd02_pair_1 := array.concat(
	[v | some v in sd02_critical_cyber_systems.violations],
	[v | some v in sd02_implementation_plan.violations],
)

sd02_pair_2 := array.concat(
	[v | some v in sd02_network_segmentation.violations],
	[v | some v in sd02_access_control.violations],
)

sd02_pair_3 := array.concat(
	[v | some v in sd02_continuous_monitoring.violations],
	[v | some v in sd02_patch_management.violations],
)

sd02_pair_4 := array.concat(
	[v | some v in sd02_incident_response_plan.violations],
	[v | some v in sd02_assessment_plan.violations],
)

sd02_quad_1 := array.concat(sd02_pair_1, sd02_pair_2)

sd02_quad_2 := array.concat(sd02_pair_3, sd02_pair_4)

sd02_violations := array.concat(
	array.concat(sd02_quad_1, sd02_quad_2),
	[v | some v in sd02_records.violations],
)

# --- Both directives ---

all_violations := array.concat(sd01_violations, sd02_violations)

# ── Top-level compliance ─────────────────────────────────────────────────────

default compliant := false

compliant if {
	count(all_violations) == 0
}

# ── Per-section compliance flags ─────────────────────────────────────────────

default sd01_coordinator_compliant := false

default sd01_reporting_compliant := false

default sd01_vulnerability_assessment_compliant := false

default sd02_critical_cyber_systems_compliant := false

default sd02_implementation_plan_compliant := false

default sd02_network_segmentation_compliant := false

default sd02_access_control_compliant := false

default sd02_continuous_monitoring_compliant := false

default sd02_patch_management_compliant := false

default sd02_incident_response_plan_compliant := false

default sd02_assessment_plan_compliant := false

default sd02_records_compliant := false

sd01_coordinator_compliant if sd01_coordinator.compliant

sd01_reporting_compliant if sd01_reporting.compliant

sd01_vulnerability_assessment_compliant if sd01_vulnerability_assessment.compliant

sd02_critical_cyber_systems_compliant if sd02_critical_cyber_systems.compliant

sd02_implementation_plan_compliant if sd02_implementation_plan.compliant

sd02_network_segmentation_compliant if sd02_network_segmentation.compliant

sd02_access_control_compliant if sd02_access_control.compliant

sd02_continuous_monitoring_compliant if sd02_continuous_monitoring.compliant

sd02_patch_management_compliant if sd02_patch_management.compliant

sd02_incident_response_plan_compliant if sd02_incident_response_plan.compliant

sd02_assessment_plan_compliant if sd02_assessment_plan.compliant

sd02_records_compliant if sd02_records.compliant

section_flags := [
	sd01_coordinator_compliant,
	sd01_reporting_compliant,
	sd01_vulnerability_assessment_compliant,
	sd02_critical_cyber_systems_compliant,
	sd02_implementation_plan_compliant,
	sd02_network_segmentation_compliant,
	sd02_access_control_compliant,
	sd02_continuous_monitoring_compliant,
	sd02_patch_management_compliant,
	sd02_incident_response_plan_compliant,
	sd02_assessment_plan_compliant,
	sd02_records_compliant,
]

total_sections := 12

passing_sections := count([f | some f in section_flags; f == true])

section_compliance_score := round((passing_sections / total_sections) * 100)

# ── Directive-level rollups ──────────────────────────────────────────────────

default sd01_compliant := false

sd01_compliant if {
	sd01_coordinator_compliant
	sd01_reporting_compliant
	sd01_vulnerability_assessment_compliant
}

default sd02_compliant := false

sd02_compliant if {
	sd02_critical_cyber_systems_compliant
	sd02_implementation_plan_compliant
	sd02_network_segmentation_compliant
	sd02_access_control_compliant
	sd02_continuous_monitoring_compliant
	sd02_patch_management_compliant
	sd02_incident_response_plan_compliant
	sd02_assessment_plan_compliant
	sd02_records_compliant
}

# ── Report metadata (defaulted — an undefined field collapses the object) ────

default entity_name := "unknown"

entity_name := input.entity_name

default assessment_date := "unknown"

assessment_date := input.assessment_date

default pipeline_type := "unknown"

pipeline_type := input.pipeline_type

# ── Complete compliance report ───────────────────────────────────────────────

compliance_report := {
	"framework": "TSA Pipeline Security Directives",
	"directives": [
		"SD Pipeline-2021-01G — Enhancing Pipeline Cybersecurity (effective 2026-01-16)",
		"SD Pipeline-2021-02G — Pipeline Cybersecurity Mitigation Actions, Contingency Planning, and Testing (effective 2026-05-03)",
	],
	"authority": "49 U.S.C. 114(d), (f), (l), and (m)",
	"entity_name": entity_name,
	"pipeline_type": pipeline_type,
	"assessed_at": assessment_date,
	"compliant": compliant,
	"sd_2021_01_compliant": sd01_compliant,
	"sd_2021_01_violation_count": count(sd01_violations),
	"sd_2021_02_compliant": sd02_compliant,
	"sd_2021_02_violation_count": count(sd02_violations),
	"total_sections": total_sections,
	"passing_sections": passing_sections,
	"section_compliance_score": section_compliance_score,
	"total_requirements_evaluated": 112,
	"violation_count": count(all_violations),
	"violations": all_violations,
	"sections": {
		"SD01_II_B_cybersecurity_coordinator": {
			"compliant": sd01_coordinator_compliant,
			"violations": sd01_coordinator.violations,
		},
		"SD01_II_C_incident_reporting": {
			"compliant": sd01_reporting_compliant,
			"violations": sd01_reporting.violations,
		},
		"SD01_II_D_vulnerability_assessment": {
			"compliant": sd01_vulnerability_assessment_compliant,
			"violations": sd01_vulnerability_assessment.violations,
		},
		"SD02_III_A_critical_cyber_systems": {
			"compliant": sd02_critical_cyber_systems_compliant,
			"violations": sd02_critical_cyber_systems.violations,
		},
		"SD02_II_B_implementation_plan": {
			"compliant": sd02_implementation_plan_compliant,
			"violations": sd02_implementation_plan.violations,
		},
		"SD02_III_B_network_segmentation": {
			"compliant": sd02_network_segmentation_compliant,
			"violations": sd02_network_segmentation.violations,
		},
		"SD02_III_C_access_control": {
			"compliant": sd02_access_control_compliant,
			"violations": sd02_access_control.violations,
		},
		"SD02_III_D_continuous_monitoring": {
			"compliant": sd02_continuous_monitoring_compliant,
			"violations": sd02_continuous_monitoring.violations,
		},
		"SD02_III_E_patch_management": {
			"compliant": sd02_patch_management_compliant,
			"violations": sd02_patch_management.violations,
		},
		"SD02_III_F_incident_response_plan": {
			"compliant": sd02_incident_response_plan_compliant,
			"violations": sd02_incident_response_plan.violations,
		},
		"SD02_III_G_assessment_plan": {
			"compliant": sd02_assessment_plan_compliant,
			"violations": sd02_assessment_plan.violations,
		},
		"SD02_IV_V_records": {
			"compliant": sd02_records_compliant,
			"violations": sd02_records.violations,
		},
	},
}
