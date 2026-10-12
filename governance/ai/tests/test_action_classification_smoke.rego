package ai_governance.classification_test

import rego.v1

# Generated smoke test for governance/ai/action_classification.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_action_classification_loads_on_empty_input if {
	m := data.ai_governance.classification with input as {}
	is_object(m)
}
