package governance.geisa.api_numeric_guards_test

import rego.v1

# "0" sorts above every number, so a string major version would pass `major < 1`; it is a finding.
test_string_major_version_is_a_finding if {
	vs := data.governance.geisa.api.violations with input as {"discovery_response": {"status_code": 1, "geisa_version": {"major": "0"}}}
	some v in vs
	contains(v, "major must be a number")
}

test_numeric_major_version_no_type_finding if {
	vs := data.governance.geisa.api.violations with input as {"discovery_response": {"status_code": 1, "geisa_version": {"major": 1}}}
	every v in vs {
		not contains(v, "major must be a number")
	}
}

test_null_major_version_is_a_finding if {
	vs := data.governance.geisa.api.violations with input as {"discovery_response": {"status_code": 1, "geisa_version": {"major": null}}}
	some v in vs
	contains(v, "major must be a number")
	not "API: GEISA version must be >= 1.0" in vs
}

test_text_major_version_is_a_finding if {
	vs := data.governance.geisa.api.violations with input as {"discovery_response": {"status_code": 1, "geisa_version": {"major": "x"}}}
	some v in vs
	contains(v, "major must be a number")
}

test_numeric_major_zero_unchanged if {
	vs := data.governance.geisa.api.violations with input as {"discovery_response": {"status_code": 1, "geisa_version": {"major": 0}}}
	"API: GEISA version must be >= 1.0" in vs
}
