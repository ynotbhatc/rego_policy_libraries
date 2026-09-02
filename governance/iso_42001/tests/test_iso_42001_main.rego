package iso_42001.main_test

import rego.v1

import data.iso_42001.main

# ── Contract smoke: report never collapses to {} ─────────────────────────────

test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
	report.compliant == false
	report.violation_count > 0
}

# ── Fully conformant AIMS ────────────────────────────────────────────────────

conformant_input := {
	"entity_name": "Example AI Deployer Inc",
	"organization_role": "deployer",
	"assessment_date": "2026-09-02",
	"context": {
		"internal_external_issues_determined": true,
		"interested_parties_identified": true,
		"aims_scope_documented": true,
	},
	"leadership": {
		"top_management_commitment": true,
		"ai_policy_established": true,
		"roles_responsibilities_assigned": true,
	},
	"planning": {
		"ai_risk_assessment_process": true,
		"ai_impact_assessment_process": true,
		"risk_treatment_plan": true,
		"measurable_objectives": true,
	},
	"support": {
		"resources_determined": true,
		"competence_ensured": true,
		"awareness_program": true,
		"documented_information_controlled": true,
	},
	"operation": {
		"processes_planned_controlled": true,
		"risk_assessments_at_intervals": true,
		"impact_assessments_performed": true,
	},
	"performance": {
		"monitoring_measurement": true,
		"internal_audit_program": true,
		"management_review": true,
	},
	"improvement": {"nonconformity_corrective_action": true},
	"annex_a": {
		"concern_reporting_process": true,
		"resources_documented": true,
		"lifecycle": {
			"responsible_development_objectives": true,
			"requirements_specified": true,
			"verification_validation": true,
			"deployment_plan": true,
			"operation_monitoring": true,
			"technical_documentation": true,
			"event_logging": true,
		},
		"data": {
			"management_process": true,
			"provenance_recorded": true,
			"quality_criteria": true,
		},
		"interested_parties": {
			"user_information": true,
			"incident_reporting": true,
		},
		"responsible_use": {"objectives_defined": true},
		"third_party": {
			"responsibilities_allocated": true,
			"supplier_process": true,
		},
	},
}

test_fully_conformant if {
	report := main.compliance_report with input as conformant_input
	report.compliant == true
	report.violation_count == 0
}

# ── Targeted gaps ────────────────────────────────────────────────────────────

test_missing_impact_assessment_process_violates if {
	inp := json.remove(conformant_input, ["planning/ai_impact_assessment_process"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "6.1.4")
}

test_missing_event_logging_violates if {
	inp := json.remove(conformant_input, ["annex_a/lifecycle/event_logging"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "A.6.2.8")
}

test_missing_data_provenance_violates if {
	inp := json.remove(conformant_input, ["annex_a/data/provenance_recorded"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "A.7.5")
}

test_missing_management_review_violates if {
	inp := json.remove(conformant_input, ["performance/management_review"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "9.3")
}

test_metadata_defaults_populate if {
	report := main.compliance_report with input as {}
	report.entity_name == "unknown"
	report.organization_role == "unknown"
	report.standard == "ISO/IEC 42001:2023"
}
