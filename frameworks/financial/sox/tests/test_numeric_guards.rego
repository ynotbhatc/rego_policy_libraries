package sox.numeric_guards_test

import rego.v1

# The SOX score is computed internally; a non-number must give no compliance level.
test_string_score_has_no_level if {
	not data.sox.simplified.sox_compliance_level with data.sox.simplified.sox_compliance_score as "1"
	not data.sox.main.sox_compliance_level with data.sox.main.sox_compliance_score as "1"
}

test_null_score_has_no_level if {
	not data.sox.simplified.sox_compliance_level with data.sox.simplified.sox_compliance_score as null
	not data.sox.main.sox_compliance_level with data.sox.main.sox_compliance_score as null
}

test_text_score_has_no_level if {
	not data.sox.simplified.sox_compliance_level with data.sox.simplified.sox_compliance_score as "x"
	not data.sox.main.sox_compliance_level with data.sox.main.sox_compliance_score as "x"
}

test_numeric_score_unchanged if {
	# Before 2026-11-24 this ran with no input document, where sox.simplified.sox_compliant was true because the
	# check list was undefined. No input is now 20 failed checks, so the all-pass input is supplied.
	data.sox.simplified.sox_compliance_level == "FULLY_COMPLIANT" with data.sox.simplified.sox_compliance_score as 0.99
		with input as data.sox.simplified_test.full
	data.sox.main.sox_compliance_level == "NON_COMPLIANT" with data.sox.main.sox_compliance_score as 10
}
