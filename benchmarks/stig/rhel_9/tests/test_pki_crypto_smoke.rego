package stig.rhel_9.pki_crypto_test

import rego.v1

# Generated smoke test for benchmarks/stig/rhel_9/pki_crypto.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_pki_crypto_loads_on_empty_input if {
	m := data.stig.rhel_9.pki_crypto with input as {}
	is_object(m)
}

test_pki_crypto_report_wellformed_on_empty_input if {
	report := data.stig.rhel_9.pki_crypto.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_pki_crypto_fail_closed_on_empty_input if {
	report := data.stig.rhel_9.pki_crypto.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_pki_crypto_violations_on_empty_input if {
	v := data.stig.rhel_9.pki_crypto.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: missing evidence must not pass.

test_missing_evidence_open_status_rhel_09_672020 if {
	data.stig.rhel_9.pki_crypto.status_rhel_09_672020 == "Open" with input as {"x": 1}
}

test_missing_evidence_open_status_rhel_09_672055 if {
	data.stig.rhel_9.pki_crypto.status_rhel_09_672055 == "Open" with input as {"x": 1}
}

# Semantic review 2026-11-13: missing evidence must not pass.

test_empty_overrides_pass if {
	data.stig.rhel_9.pki_crypto.status_rhel_09_672020 == "Not_a_Finding" with input as {"crypto_policy_overrides": []}
}

test_legacy_override_false_passes if {
	data.stig.rhel_9.pki_crypto.status_rhel_09_672055 == "Not_a_Finding" with input as {"openssl_config": {"legacy_override": false}}
}
