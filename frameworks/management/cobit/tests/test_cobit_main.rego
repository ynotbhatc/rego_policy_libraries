package cobit.main_test

import rego.v1

import data.cobit.main

test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
	report.compliant == false
	report.violation_count > 0
}

compliant_input := {
	"entity_name": "Example Enterprise",
	"assessment_date": "2026-09-02",
	"edm": {
		"governance_framework_established": true,
		"benefits_delivery_overseen": true,
		"risk_optimization_overseen": true,
		"resource_optimization_overseen": true,
		"stakeholder_engagement": true,
	},
	"apo": {
		"it_strategy_documented": true,
		"enterprise_architecture_managed": true,
		"risk_management_operated": true,
		"security_management_defined": true,
		"vendor_management_operated": true,
	},
	"bai": {
		"change_management_operated": true,
		"configuration_management_operated": true,
	},
	"dss": {
		"operations_managed": true,
		"incident_management_operated": true,
		"security_services_delivered": true,
	},
	"mea": {
		"performance_monitoring_operated": true,
		"internal_control_assessed": true,
		"external_compliance_assessed": true,
	},
}

test_fully_compliant if {
	report := main.compliance_report with input as compliant_input
	report.compliant == true
	report.violation_count == 0
}

test_missing_risk_management_violates if {
	inp := json.remove(compliant_input, ["apo/risk_management_operated"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "APO12")
}

test_missing_governance_framework_violates if {
	inp := json.remove(compliant_input, ["edm/governance_framework_established"])
	report := main.compliance_report with input as inp
	some v in report.violations
	contains(v, "EDM01")
}

test_scope_note_disclaims_maturity if {
	report := main.compliance_report with input as {}
	contains(report.scope_note, "not machine-assessable")
}
