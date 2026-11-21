package iec_62443.numeric_guards_test

import rego.v1

# Issue #300: "1" sorts above every number and null below every number in Rego, so an
# unguarded comparison mis-decides. A non-number must be reported as evidence missing.

_fr2_sl_msg := "IEC 62443 FR 2 (UC): evidence missing - input.target_sl not provided; Security Level dependent requirements cannot be evaluated"

test_fr2_string_target_sl_is_evidence_missing if {
	_fr2_sl_msg in data.iec_62443.fr2.violations with input as {"target_sl": "3"}
}

test_fr2_null_target_sl_is_evidence_missing if {
	_fr2_sl_msg in data.iec_62443.fr2.violations with input as {"target_sl": null}
}

test_fr2_word_target_sl_is_evidence_missing if {
	_fr2_sl_msg in data.iec_62443.fr2.violations with input as {"target_sl": "x"}
}

test_fr2_string_target_sl_not_compliant if {
	not data.iec_62443.fr2.compliant with input as {"target_sl": "3"}
}

test_fr2_numeric_target_sl_still_evaluates if {
	vs := data.iec_62443.fr2.violations with input as {"target_sl": 2}
	not _fr2_sl_msg in vs
	some v in vs
	startswith(v, "IEC 62443 SR 2.1 RE 1 SL2 (UC):")
}

_ra_msg := "IEC 62443-2-1 (CSMS): evidence missing - input.risk_assessment.review_frequency_months is not a number"

test_part2_1_string_review_frequency_is_evidence_missing if {
	_ra_msg in data.iec_62443.part2_1.violations with input as {"risk_assessment": {"conducted": true, "review_frequency_months": "1"}}
}

test_part2_1_null_review_frequency_is_evidence_missing if {
	_ra_msg in data.iec_62443.part2_1.violations with input as {"risk_assessment": {"conducted": true, "review_frequency_months": null}}
}

test_part2_1_word_review_frequency_is_evidence_missing if {
	_ra_msg in data.iec_62443.part2_1.violations with input as {"risk_assessment": {"conducted": true, "review_frequency_months": "x"}}
}

test_part2_1_numeric_review_frequency_unchanged if {
	vs := data.iec_62443.part2_1.violations with input as {"risk_assessment": {"conducted": true, "review_frequency_months": 36}}
	not _ra_msg in vs
	some v in vs
	contains(v, "reviewed every 36 months")
}

test_part2_1_numeric_review_frequency_within_limit if {
	vs := data.iec_62443.part2_1.violations with input as {"risk_assessment": {"conducted": true, "review_frequency_months": 12}}
	not _ra_msg in vs
	every v in vs {
		not contains(v, "risk assessment is reviewed every")
	}
}
