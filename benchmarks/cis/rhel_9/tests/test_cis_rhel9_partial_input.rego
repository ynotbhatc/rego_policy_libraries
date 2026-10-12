package cis_rhel9_test

import rego.v1

import data.cis_rhel9

# Partial-input fail-closed accounting (2026-10-12).
# A section whose input keys were never collected must be reported as NOT
# ASSESSED and must never count as compliant.

thin_input := {"ansible_facts": {"ansible_distribution": "RedHat", "ansible_distribution_major_version": "9"}}

all_keys_input := {
	"mount_options": {}, "initial_setup": {}, "boot_security": {}, "selinux": {},
	"unnecessary_services": {}, "sysctl_parameters": {}, "auditd": {}, "rsyslog": {},
	"cron": {}, "ssh": {}, "sudo": {}, "pam": {}, "suid_files": [], "user_group": {},
}

test_empty_input_nothing_assessed if {
	count(cis_rhel9.not_assessed_sections) == 14 with input as {}
	cis_rhel9.assessed_sections == 0 with input as {}
	cis_rhel9.assessment_coverage_percentage == 0 with input as {}
	not cis_rhel9.compliant with input as {}
}

test_ansible_facts_only_is_not_an_assessment if {
	count(cis_rhel9.not_assessed_sections) == 14 with input as thin_input
	cis_rhel9.compliant_sections == 0 with input as thin_input
	cis_rhel9.compliance_percentage == 0 with input as thin_input
	not cis_rhel9.compliant with input as thin_input
}

test_bridge_reports_unassessed_sections_as_failed if {
	r := cis_rhel9.main.compliance_report with input as thin_input
	count(r.sections_not_assessed) == 14
	r.assessment_coverage_percentage == 0
	r.failed_controls == r.total_controls
	r.passed_controls == 0
	r.compliance_percentage == 0
	not r.compliant
	some v in r.violations
	startswith(v, "NOT ASSESSED: section_5_4_5_5_pam")
}

test_one_section_present_counts_one_assessed if {
	inp := {"pam": {"pwquality_installed": true, "pwquality_conf_raw": "", "system_auth": ""}}
	cis_rhel9.assessed_sections == 1 with input as inp
	count(cis_rhel9.not_assessed_sections) == 13 with input as inp
	not cis_rhel9.compliant with input as inp
	r := cis_rhel9.main.compliance_report with input as inp
	count(r.sections_not_assessed) == 13
	r.assessment_coverage_percentage == 7
}

test_all_sections_present_nothing_unassessed if {
	count(cis_rhel9.not_assessed_sections) == 0 with input as all_keys_input
	cis_rhel9.assessed_sections == 14 with input as all_keys_input
	cis_rhel9.assessment_coverage_percentage == 100 with input as all_keys_input
	r := cis_rhel9.main.compliance_report with input as all_keys_input
	count(r.sections_not_assessed) == 0
	r.assessment_coverage_percentage == 100
	not [v | some v in r.violations; startswith(v, "NOT ASSESSED")][0]
}

test_missing_inputs_named_per_section if {
	m := cis_rhel9.missing_inputs with input as {"pam": {}}
	m.section_5_4_5_5_pam == []
	m.section_5_2_ssh == ["ssh"]
}
