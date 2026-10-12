package soc2.processing_integrity.data_processing_test

import rego.v1

# Generated smoke test for frameworks/management/soc2/processing_integrity/data_processing.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_data_processing_loads_on_empty_input if {
	m := data.soc2.processing_integrity.data_processing with input as {}
	is_object(m)
}
