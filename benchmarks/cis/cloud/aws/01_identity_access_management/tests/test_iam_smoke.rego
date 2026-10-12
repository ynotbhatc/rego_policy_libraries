package cis.aws.iam_test

import rego.v1

# Generated smoke test for benchmarks/cis/cloud/aws/01_identity_access_management/iam.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_iam_loads_on_empty_input if {
	m := data.cis.aws.iam with input as {}
	is_object(m)
}
