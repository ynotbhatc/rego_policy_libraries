package stig.oracle_linux_9.software_integrity_test

import rego.v1

# Generated smoke test for benchmarks/stig/oracle_linux_9/software_integrity.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_software_integrity_loads_on_empty_input if {
	m := data.stig.oracle_linux_9.software_integrity with input as {}
	is_object(m)
}

test_software_integrity_report_wellformed_on_empty_input if {
	report := data.stig.oracle_linux_9.software_integrity.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_software_integrity_fail_closed_on_empty_input if {
	report := data.stig.oracle_linux_9.software_integrity.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_software_integrity_violations_on_empty_input if {
	v := data.stig.oracle_linux_9.software_integrity.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: each STIG id checks the setting its DISA title names.

test_profiling_perf_event_paranoid_passes if {
	data.stig.oracle_linux_9.software_integrity.status_ol09_00_002407 == "Not_a_Finding" with input as {"kernel_params": {"kernel.perf_event_paranoid": "3"}}
}

test_profiling_kexec_does_not_cover if {
	data.stig.oracle_linux_9.software_integrity.status_ol09_00_002407 == "Open" with input as {"kernel_params": {"kernel.kexec_load_disabled": "1", "kernel.perf_event_paranoid": "1"}}
}

# Semantic review 2026-11-13: missing evidence must not pass.

test_repo_without_gpgcheck_key_open if {
	data.stig.oracle_linux_9.software_integrity.status_ol09_00_000498 == "Open" with input as {"yum_repos": [{"name": "a"}]}
}

test_repo_gpgcheck_true_pass if {
	data.stig.oracle_linux_9.software_integrity.status_ol09_00_000498 == "Not_a_Finding" with input as {"yum_repos": [{"name": "a", "gpgcheck": true}]}
}
