package cis_ubuntu_2204.l2_test

import rego.v1

# Generated smoke test for benchmarks/cis/ubuntu_22_04/l2_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_l2_validation_loads_on_empty_input if {
	m := data.cis_ubuntu_2204.l2 with input as {}
	is_object(m)
}

test_l2_validation_report_wellformed_on_empty_input if {
	report := data.cis_ubuntu_2204.l2.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_l2_validation_fail_closed_on_empty_input if {
	report := data.cis_ubuntu_2204.l2.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_l2_validation_violations_on_empty_input if {
	v := data.cis_ubuntu_2204.l2.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: missing L2 evidence must not pass; sshd defaults apply.
test_missing_l2_evidence_flagged if {
	v := data.cis_ubuntu_2204.l2.violations with input as {}
	"CIS L2 1.5.4: evidence missing - kernel.suid_dumpable not collected" in v
	"CIS L2 3.3.1: evidence missing - sysctl net.ipv6.conf.all.accept_ra not collected" in v
	"CIS L2 3.3.1: evidence missing - sysctl net.ipv6.conf.default.accept_ra not collected" in v
	"CIS L2 3.3.2: evidence missing - sysctl net.ipv6.conf.all.accept_redirects not collected" in v
	"CIS L2 6.1.11: evidence missing - file_system.unowned_files not collected" in v
	"CIS L2 6.1.14: evidence missing - file_system.unexpected_sgid_files not collected" in v
}

test_present_l2_evidence_not_flagged_missing if {
	v := data.cis_ubuntu_2204.l2.violations with input as {"kernel": {"suid_dumpable": 0}, "sysctl": {"net.ipv6.conf.all.accept_ra": 0, "net.ipv6.conf.default.accept_ra": 0, "net.ipv6.conf.all.accept_redirects": 0}, "file_system": {"unowned_files": [], "ungrouped_files": [], "unexpected_suid_files": [], "unexpected_sgid_files": []}}
	every x in v {
		not contains(x, "evidence missing")
	}
}

test_allowtcpforwarding_absent_defaults_to_yes if {
	v := data.cis_ubuntu_2204.l2.violations with input as {"ssh": {"sshd_config_raw": "port 22\n"}}
	"CIS L2 5.2.7: AllowTcpForwarding not set to 'no'" in v
}

test_logingracetime_zero_flagged if {
	v := data.cis_ubuntu_2204.l2.violations with input as {"ssh": {"sshd_config_raw": "logingracetime 0\n"}}
	"CIS L2 5.2.8: LoginGraceTime is 0 (no limit)" in v
}
