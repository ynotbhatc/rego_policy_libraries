package iec_62443_main_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/iec_62443/iec_62443_main.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_iec_62443_main_loads_on_empty_input if {
	m := data.iec_62443_main with input as {}
	is_object(m)
}

# Semantic review 2026-11-13: near-empty input must not score SRs as passing (was 32 of 51).
test_empty_input_passes_no_srs if {
	data.iec_62443_main.passing_srs == 0 with input as {}
}

test_target_sl_only_input_not_inflated if {
	data.iec_62443_main.passing_srs == 0 with input as {"target_sl": 1}
}

test_evidence_missing_finding_names_requirement if {
	v := data.iec_62443.fr7.violations with input as {}
	some m in v
	contains(m, "SR 7.7")
	contains(m, "evidence missing")
}
