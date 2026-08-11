package tsa_pipeline.main_test

import rego.v1

# Contract smoke tests for the tsa_pipeline framework key.
#
# The trap these guard against: an undefined field inside an object literal
# collapses the ENTIRE object to {} at the OPA endpoint, and the calling
# playbook stores an empty result instead of failing. That silently affected
# every cis_* key until rego PR #52. These tests encode the check permanently.

# ── The framework key resolves ───────────────────────────────────────────────

test_main_report_wellformed_on_empty_input if {
	report := data.tsa_pipeline.main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
	is_number(report.violation_count)
	is_array(report.violations)
}

test_main_report_fails_closed_on_empty_input if {
	report := data.tsa_pipeline.main.compliance_report with input as {}
	report.compliant == false
	report.sd_2021_01_compliant == false
	report.sd_2021_02_compliant == false
	report.violation_count > 0
	report.passing_sections == 0
}

# ── Every section module resolves independently ──────────────────────────────
#
# Deliberately evaluated with input UNDEFINED (no `with input as {}`). A real
# OPA POST with an empty body leaves input undefined, which is stricter than
# input == {} — object.get(input, ...) is itself undefined in that case. Any
# report field not sourced through a defaulted rule collapses here.

test_every_section_report_wellformed_on_undefined_input if {
	every section_report in [
		data.tsa_pipeline.sd01_coordinator.compliance_report,
		data.tsa_pipeline.sd01_reporting.compliance_report,
		data.tsa_pipeline.sd01_vulnerability_assessment.compliance_report,
		data.tsa_pipeline.sd02_critical_cyber_systems.compliance_report,
		data.tsa_pipeline.sd02_implementation_plan.compliance_report,
		data.tsa_pipeline.sd02_network_segmentation.compliance_report,
		data.tsa_pipeline.sd02_access_control.compliance_report,
		data.tsa_pipeline.sd02_continuous_monitoring.compliance_report,
		data.tsa_pipeline.sd02_patch_management.compliance_report,
		data.tsa_pipeline.sd02_incident_response_plan.compliance_report,
		data.tsa_pipeline.sd02_assessment_plan.compliance_report,
		data.tsa_pipeline.sd02_records.compliance_report,
	] {
		is_object(section_report)
		count(section_report) > 0
		is_boolean(section_report.compliant)
		is_number(section_report.violation_count)
	}
}

test_all_twelve_sections_present_in_report if {
	report := data.tsa_pipeline.main.compliance_report with input as {}
	count(report.sections) == 12
	report.total_sections == 12
}

# ── Aggregation counts every section exactly once ────────────────────────────

test_aggregate_count_equals_sum_of_sections if {
	report := data.tsa_pipeline.main.compliance_report with input as {}
	section_sum := sum([n |
		some section in report.sections
		n := count(section.violations)
	])
	report.violation_count == section_sum
}

test_directive_counts_sum_to_total if {
	report := data.tsa_pipeline.main.compliance_report with input as {}
	report.violation_count == report.sd_2021_01_violation_count + report.sd_2021_02_violation_count
}

# ── Metadata passthrough is defaulted, not undefined ─────────────────────────

test_metadata_defaults_when_absent if {
	report := data.tsa_pipeline.main.compliance_report with input as {}
	report.entity_name == "unknown"
	report.pipeline_type == "unknown"
	report.assessed_at == "unknown"
}

test_metadata_passthrough_when_supplied if {
	report := data.tsa_pipeline.main.compliance_report with input as {
		"entity_name": "Example Pipeline Operator",
		"pipeline_type": "natural_gas_transmission",
		"assessment_date": "2026-08-11T00:00:00Z",
	}
	report.entity_name == "Example Pipeline Operator"
	report.pipeline_type == "natural_gas_transmission"
	report.assessed_at == "2026-08-11T00:00:00Z"
}
