package cis_nginx_1_20_test

import rego.v1

# Generated smoke test for benchmarks/cis/nginx/cis_nginx_1_20.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_cis_nginx_1_20_loads_on_empty_input if {
	m := data.cis_nginx_1_20 with input as {}
	is_object(m)
}

