package nist_ssdf.main_numeric_guards_test

import rego.v1

# total_controls is computed internally; a non-number in its place falls back to the 0 default.
test_non_number_total_controls_falls_back_to_zero if {
	every v in ["1", null, "x"] {
		data.nist_ssdf.main.compliance_percentage == 0 with input as {} with data.nist_ssdf.main.total_controls as v
	}
}

test_numeric_total_controls_unchanged if {
	data.nist_ssdf.main.compliance_percentage == 0 with input as {}
}
