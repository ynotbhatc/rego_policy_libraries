# A row that lacks the field a rule selects on must produce a finding, not drop out of the check.
package cis_aws.missing_row_fields_test

import rego.v1

import data.cis_aws as b

green := data.cis_aws.v7_controls_test.green

_has_id(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

# 2.11: a credential-report row with no user name is still checked (it used to be skipped)
test_credential_row_without_user_is_checked if {
	inp := json.patch(green, [
		{"op": "remove", "path": "/credential_report/1/user"},
		{"op": "add", "path": "/credential_report/1/password_last_used", "value": "2020-01-01T00:00:00+00:00"},
	])
	vs := b.violations with input as inp
	_has_id(vs, "2.11")
}

# 7.2.4: a guardrail filter without a type cannot be matched to the harmful categories
test_guardrail_filter_without_type_is_a_finding if {
	inp := json.patch(green, [{"op": "remove", "path": "/bedrock_guardrails/0/contentPolicy/filters/0/type"}])
	vs := b.violations with input as inp
	_has_id(vs, "7.2.4")
}
