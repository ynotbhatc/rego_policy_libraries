package ami.headend.security_numeric_guards_test

import rego.v1

# "1" sorts above every number in Rego and null below: a non-number expiry must not pass.
test_string_jwt_expiry_not_managed if {
	not data.ami.headend.security.api_gateway_session_management with input as {"mdms": {"api_gateway": {"authentication": {
		"oauth2_enabled": true,
		"jwt_expiry_minutes": "1",
		"refresh_token_rotation": true,
	}}}}
}

test_null_jwt_expiry_not_managed if {
	not data.ami.headend.security.api_gateway_session_management with input as {"mdms": {"api_gateway": {"authentication": {
		"oauth2_enabled": true,
		"jwt_expiry_minutes": null,
		"refresh_token_rotation": true,
	}}}}
}

test_text_jwt_expiry_not_managed if {
	not data.ami.headend.security.api_gateway_session_management with input as {"mdms": {"api_gateway": {"authentication": {
		"oauth2_enabled": true,
		"jwt_expiry_minutes": "x",
		"refresh_token_rotation": true,
	}}}}
}

test_numeric_jwt_expiry_still_managed if {
	data.ami.headend.security.api_gateway_session_management with input as {"mdms": {"api_gateway": {"authentication": {
		"oauth2_enabled": true,
		"jwt_expiry_minutes": 60,
		"refresh_token_rotation": true,
	}}}}
}

test_string_retention_not_sufficient if {
	not data.ami.headend.security.audit_log_retention with input as {"mdms": {"audit_logging": {"retention_days": "1"}}}
}

test_numeric_retention_still_sufficient if {
	data.ami.headend.security.audit_log_retention with input as {"mdms": {"audit_logging": {"retention_days": 365}}}
}
