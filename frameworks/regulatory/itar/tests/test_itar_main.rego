package itar.main_test

import rego.v1

import data.itar.main

test_report_wellformed_on_empty_input if {
	report := main.compliance_report with input as {}
	is_object(report)
	count(report) > 0
	is_boolean(report.compliant)
	report.compliant == false
	report.violation_count > 0
}

compliant_input := {
	"entity_name": "Example Defense Supplier",
	"assessment_date": "2026-09-02",
	"registration": {"ddtc_current": true},
	"jurisdiction": {"technical_data_identified": true},
	"access": {
		"us_persons_only_enforced": true,
		"system_access_controls": true,
		"physical_controls": true,
	},
	"encryption": {
		"end_to_end_fips_validated": true,
		"no_decryption_in_proscribed_countries": true,
		"keys_withheld_from_foreign_persons": true,
	},
	"program": {
		"written_compliance_program": true,
		"empowered_official_designated": true,
		"training_provided": true,
		"subcontractor_flowdown": true,
		"violation_disclosure_process": true,
	},
	"records": {
		"retention_5_years": true,
		"access_logging": true,
	},
}

test_fully_compliant if {
	report := main.compliance_report with input as compliant_input
	report.compliant == true
	report.violation_count == 0
}

test_foreign_person_access_with_authorization_satisfies if {
	inp := object.union(compliant_input, {"access": {
		"us_persons_only_enforced": false,
		"foreign_person_authorization_documented": true,
		"system_access_controls": true,
		"physical_controls": true,
	}})
	report := main.compliance_report with input as inp
	report.compliant == true
}

test_foreign_person_access_without_authorization_violates if {
	inp := object.union(compliant_input, {"access": {
		"us_persons_only_enforced": false,
		"system_access_controls": true,
		"physical_controls": true,
	}})
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "deemed export")
}

test_missing_fips_encryption_violates if {
	inp := json.remove(compliant_input, ["encryption/end_to_end_fips_validated"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "120.54")
}

test_missing_access_logging_violates if {
	inp := json.remove(compliant_input, ["records/access_logging"])
	report := main.compliance_report with input as inp
	report.compliant == false
	some v in report.violations
	contains(v, "not logged")
}

test_scope_note_present if {
	report := main.compliance_report with input as {}
	contains(report.scope_note, "800-171")
}
