package soc2.infrastructure.applications_services_test

import rego.v1

# Generated smoke test for frameworks/management/soc2/infrastructure/applications_services/applications_services.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_applications_services_loads_on_empty_input if {
	m := data.soc2.infrastructure.applications_services with input as {}
	is_object(m)
}
