package ami.nist_ir7628.complete_test

import rego.v1

# Generated smoke test for frameworks/critical_infrastructure/ami/nist_ir_7628/nist_ir7628_complete.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_nist_ir7628_complete_loads_on_empty_input if {
	m := data.ami.nist_ir7628.complete with input as {}
	is_object(m)
}
