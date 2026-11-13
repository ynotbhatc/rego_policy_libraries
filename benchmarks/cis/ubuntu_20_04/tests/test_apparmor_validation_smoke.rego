package cis_ubuntu_20_04.apparmor_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_20_04/apparmor_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_apparmor_validation_loads_on_empty_input if {
	m := data.cis_ubuntu_20_04.apparmor with input as {}
	is_object(m)
}

test_apparmor_validation_report_wellformed_on_empty_input if {
	report := data.cis_ubuntu_20_04.apparmor.report with input as {}
	is_object(report)
	count(report) > 0
}

test_apparmor_validation_fail_closed_on_empty_input if {
	report := data.cis_ubuntu_20_04.apparmor.report with input as {}
	not object.get(report, "compliant", false) == true
}

test_apparmor_validation_violations_on_empty_input if {
	v := data.cis_ubuntu_20_04.apparmor.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: missing profile facts must not pass 1.6.1.3 / 1.6.1.4.
test_missing_profile_facts_flagged if {
	v := data.cis_ubuntu_20_04.apparmor.profile_violations with input as {}
	"CIS 1.6.1.3: evidence missing - apparmor.unloaded_profiles (or apparmor.profiles) not collected" in v
	"CIS 1.6.1.4: evidence missing - apparmor.complain_profiles (or apparmor.profiles) not collected" in v
}

test_present_profile_counts_not_flagged_missing if {
	v := data.cis_ubuntu_20_04.apparmor.profile_violations with input as {"apparmor": {"unloaded_profiles": 0, "complain_profiles": 0}}
	count(v) == 0
}
