package stig.oracle_linux_9.configuration_management_test

import rego.v1

# Generated smoke test for benchmarks/stig/oracle_linux_9/configuration_management.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_configuration_management_loads_on_empty_input if {
	m := data.stig.oracle_linux_9.configuration_management with input as {}
	is_object(m)
}

test_configuration_management_report_wellformed_on_empty_input if {
	report := data.stig.oracle_linux_9.configuration_management.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_configuration_management_fail_closed_on_empty_input if {
	report := data.stig.oracle_linux_9.configuration_management.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_configuration_management_violations_on_empty_input if {
	v := data.stig.oracle_linux_9.configuration_management.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: each STIG id checks the setting its DISA title names.

test_lsm_selinux_enforcing_passes if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_000060 == "Not_a_Finding" with input as {"selinux": {"status": "enforcing"}}
}

test_lsm_fips_policy_alone_open if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_000060 == "Open" with input as {"crypto_policy": "FIPS", "selinux": {"status": "disabled"}}
}

test_ptrace_scope_passes if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002410 == "Not_a_Finding" with input as {"kernel_params": {"kernel.yama.ptrace_scope": "1"}}
}

test_ptrace_ignores_perf_event if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002410 == "Open" with input as {"kernel_params": {"kernel.perf_event_paranoid": "3"}}
}

test_kexec_passes if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002428 == "Not_a_Finding" with input as {"kernel_params": {"kernel.kexec_load_disabled": "1"}}
}

test_kexec_ignores_bpf if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002428 == "Open" with input as {"kernel_params": {"kernel.unprivileged_bpf_disabled": "1", "kernel.kexec_load_disabled": "0"}}
}

test_home_nosuid_passes if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002071 == "Not_a_Finding" with input as {"filesystem_mounts": [{"mount": "/home", "device": "/dev/sda3", "options": ["nosuid"]}]}
}

test_tmp_nosuid_does_not_cover_home if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002071 == "Open" with input as {"filesystem_mounts": [{"mount": "/tmp", "device": "/dev/sda2", "options": ["nosuid"]}]}
}

test_tmp_noexec_does_not_cover_home if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002072 == "Open" with input as {"filesystem_mounts": [{"mount": "/tmp", "device": "/dev/sda2", "options": ["noexec"]}]}
}

test_graphical_ctrl_alt_del_missing_packages_open if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002107 == "Open" with input as {"os": 1}
}

test_graphical_ctrl_alt_del_no_gnome_passes if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002107 == "Not_a_Finding" with input as {"packages": {"bash": true}}
}

test_home_nodev_passes if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002070 == "Not_a_Finding" with input as {"filesystem_mounts": [{"mount": "/home", "device": "/dev/sda3", "options": ["nodev"]}]}
}

test_tmp_nodev_does_not_cover_home if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_002070 == "Open" with input as {"filesystem_mounts": [{"mount": "/tmp", "device": "/dev/sda2", "options": ["nodev"]}]}
}

test_aide_installed_without_fips_hashes_open if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_000302 == "Open" with input as {"packages": {"aide": true}}
}

test_aide_sha512_passes if {
	data.stig.oracle_linux_9.configuration_management.status_ol09_00_000302 == "Not_a_Finding" with input as {"aide_config": {"hash_algorithms": ["sha512"]}}
}
