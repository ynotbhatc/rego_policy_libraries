package cmmc.numeric_guards_test

import rego.v1

# Issue #300: "3" sorts above every number in Rego, so a string cmmc_level used to switch the Level 2
# practices on, and null switched them off silently. A non-number is now evidence missing.

_ac_msg := "CMMC AC input contract: FAIL-CLOSED - input.cmmc_level was not supplied or is not a number (evidence missing); the Level 2 access-control practices were not evaluated and the domain is reported non-compliant"

test_ac_string_level_is_evidence_missing if {
	_ac_msg in data.cmmc.access_control.violations with input as {"cmmc_level": "3"}
}

test_ac_null_level_is_evidence_missing if {
	_ac_msg in data.cmmc.access_control.violations with input as {"cmmc_level": null}
}

test_ac_word_level_is_evidence_missing if {
	_ac_msg in data.cmmc.access_control.violations with input as {"cmmc_level": "x"}
}

test_ac_string_level_does_not_evaluate_level_2 if {
	vs := data.cmmc.access_control.violations with input as {"cmmc_level": "3"}
	every v in vs {
		not startswith(v, "CMMC AC.L2-3.1.3:")
	}
}

test_ac_numeric_level_still_evaluates_level_2 if {
	vs := data.cmmc.access_control.violations with input as {"cmmc_level": 2}
	not _ac_msg in vs
	some v in vs
	startswith(v, "CMMC AC.L2-3.1.3:")
}

test_main_string_level_not_level_2_compliant if {
	not data.cmmc.cmmc_level_2_compliant with input as {"cmmc_level": "2"}
}
