package sox.application_controls.numeric_guards_test

import rego.v1

# The score is computed internally; a non-number (if one ever reached it) must give no risk level, never "LOW".
test_string_score_has_no_risk_level if {
	not data.sox.application_controls.application_controls_risk_level with data.sox.application_controls.application_controls_score as "1"
}

test_null_score_has_no_risk_level if {
	not data.sox.application_controls.application_controls_risk_level with data.sox.application_controls.application_controls_score as null
}

test_text_score_has_no_risk_level if {
	not data.sox.application_controls.application_controls_risk_level with data.sox.application_controls.application_controls_score as "x"
}

test_numeric_score_unchanged if {
	data.sox.application_controls.application_controls_risk_level == "LOW" with data.sox.application_controls.application_controls_score as 95
	data.sox.application_controls.application_controls_risk_level == "CRITICAL" with data.sox.application_controls.application_controls_score as 10
}
