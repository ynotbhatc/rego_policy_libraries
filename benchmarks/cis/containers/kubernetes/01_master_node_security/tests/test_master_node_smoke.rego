package cis.kubernetes.master_test

import rego.v1

# Generated smoke test for benchmarks/cis/containers/kubernetes/01_master_node_security/master_node.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_master_node_loads_on_empty_input if {
	m := data.cis.kubernetes.master with input as {}
	is_object(m)
}
