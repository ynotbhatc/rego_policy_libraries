package governance.geisa.manifest_validation_test

import rego.v1

# Generated smoke test for governance/geisa/geisa_manifest_validation.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_geisa_manifest_validation_loads_on_empty_input if {
	m := data.governance.geisa.manifest_validation with input as {}
	is_object(m)
}

test_geisa_manifest_validation_violations_on_empty_input if {
	v := data.governance.geisa.manifest_validation.violations with input as {}
	count(v) > 0
}
