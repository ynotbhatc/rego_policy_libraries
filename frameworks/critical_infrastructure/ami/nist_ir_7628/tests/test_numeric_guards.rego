package ami.nist_ir7628.audit_numeric_guards_test

import rego.v1

# "1" sorts above every number in Rego and null below: a non-number retention must not pass.
test_string_retention_not_sufficient if {
	not data.ami.nist_ir7628.audit.log_retention_sufficient with input as {"audit": {"storage": {"retention_days": "1"}}}
}

test_null_retention_not_sufficient if {
	not data.ami.nist_ir7628.audit.log_retention_sufficient with input as {"audit": {"storage": {"retention_days": null}}}
}

test_text_retention_not_sufficient if {
	not data.ami.nist_ir7628.audit.log_retention_sufficient with input as {"audit": {"storage": {"retention_days": "x"}}}
}

test_numeric_retention_still_sufficient if {
	data.ami.nist_ir7628.audit.log_retention_sufficient with input as {"audit": {"storage": {"retention_days": 365}}}
}

test_numeric_retention_too_short_still_fails if {
	not data.ami.nist_ir7628.audit.log_retention_sufficient with input as {"audit": {"storage": {"retention_days": 30}}}
}
