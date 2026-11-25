package fisma.main_missing_row_fields_test

import rego.v1

# `not row.field != ""` and `not row.field in [...]` are undefined when the field is missing, so a row without the
# field dropped out of the violation list and the check passed.

fm := data.fisma.main

_cc := {
	"provider_organization": "GSA",
	"authorization_status": "authorized",
	"inheritance_documented": true,
}

_it := {
	"type_name": "PII",
	"confidentiality_impact": "moderate",
	"integrity_impact": "moderate",
	"availability_impact": "low",
	"rationale": "NIST SP 800-60",
}

_cc_in(c) := {"fisma": {"prepare": {"common_controls": [c]}}}

_it_in(i) := {"fisma": {"categorize": {"information_types": [i]}}}

test_complete_common_control_passes if fm.common_controls_identified with input as _cc_in(_cc)

test_complete_information_type_passes if fm.information_types_identified with input as _it_in(_it)

test_common_control_missing_a_field_does_not_pass if {
	every f in ["provider_organization", "authorization_status", "inheritance_documented"] {
		not fm.common_controls_identified with input as _cc_in(object.remove(_cc, [f]))
	}
}

test_information_type_missing_a_field_does_not_pass if {
	every f in ["type_name", "confidentiality_impact", "integrity_impact", "availability_impact", "rationale"] {
		not fm.information_types_identified with input as _it_in(object.remove(_it, [f]))
	}
}
