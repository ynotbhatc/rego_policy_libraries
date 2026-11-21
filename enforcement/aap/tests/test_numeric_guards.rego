package aac.aap.policy_numeric_guards_test

import rego.v1

# "80" sorts above every number, so a string max_length silently disabled the length check.
test_string_max_length_is_a_finding if {
	r := data.aac.aap.policy.naming_standard with input as {"job_template": {"name": "abcdef"}}
		with data.aac.aap.config as {"naming": {"max_length": "1"}}
	not r.allowed
	some v in r.violations
	contains(v, "evidence missing")
}

test_null_max_length_is_a_finding if {
	r := data.aac.aap.policy.naming_standard with input as {"job_template": {"name": "abcdef"}}
		with data.aac.aap.config as {"naming": {"max_length": null}}
	not r.allowed
}

test_text_max_length_is_a_finding if {
	r := data.aac.aap.policy.naming_standard with input as {"job_template": {"name": "abcdef"}}
		with data.aac.aap.config as {"naming": {"max_length": "x"}}
	not r.allowed
}

test_numeric_max_length_unchanged if {
	r := data.aac.aap.policy.naming_standard with input as {"job_template": {"name": "abcdef"}}
		with data.aac.aap.config as {"naming": {"max_length": 3}}
	r.violations == ["Job template name is 6 characters; the maximum is 3."]
}
