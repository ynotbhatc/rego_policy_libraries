package cis_windows_server_2022_test

import rego.v1

import data.cis_windows_server_2022

# Partial-input fail-closed accounting (2026-10-12): a section whose input
# keys were never collected is NOT ASSESSED and never counts as compliant.

all_keys_input := {
	"account_policies": {}, "local_policies": {}, "event_log": {}, "services": {},
	"registry": {}, "security_options": {}, "audit_policy": {}, "windows_defender": {}, "bitlocker": {},
}

test_empty_input_nothing_assessed if {
	count(cis_windows_server_2022.not_assessed_sections) == 9 with input as {}
	cis_windows_server_2022.assessment_coverage_percentage == 0 with input as {}
	not cis_windows_server_2022.compliant with input as {}
}

test_one_section_is_not_compliance if {
	inp := {"bitlocker": {}}
	cis_windows_server_2022.assessed_sections == 1 with input as inp
	count(cis_windows_server_2022.not_assessed_sections) == 8 with input as inp
	not cis_windows_server_2022.compliant with input as inp
	r := cis_windows_server_2022.main.compliance_report with input as inp
	count(r.sections_not_assessed) == 8
	some v in r.violations
	startswith(v, "NOT ASSESSED: section_1_account_policies")
}

test_all_sections_present_nothing_unassessed if {
	count(cis_windows_server_2022.not_assessed_sections) == 0 with input as all_keys_input
	cis_windows_server_2022.assessment_coverage_percentage == 100 with input as all_keys_input
	r := cis_windows_server_2022.main.compliance_report with input as all_keys_input
	r.assessment_coverage_percentage == 100
	count(r.sections_not_assessed) == 0
}
