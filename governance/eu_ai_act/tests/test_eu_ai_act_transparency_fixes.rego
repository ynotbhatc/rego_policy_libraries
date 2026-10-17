package eu_ai_act.transparency_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

test_transparency_empty_input_is_not_compliant if {
	not data.eu_ai_act.transparency.compliant with input as {}
	"Article 50: evidence missing — eu_ai_act.transparency assessment not provided" in data.eu_ai_act.transparency.violations with input as {}
}

test_transparency_empty_assessment_is_not_compliant if {
	not data.eu_ai_act.transparency.compliant with input as {"eu_ai_act": {"transparency": {}}}
}

test_transparency_assessment_with_nothing_applicable_is_compliant if {
	i := {"eu_ai_act": {"transparency": {"chatbot": {"interacts_with_natural_persons": false}}}}
	data.eu_ai_act.transparency.compliant with input as i
}

test_transparency_chatbot_disclosed_at_start_is_compliant if {
	i := {"eu_ai_act": {"transparency": {"chatbot": {"interacts_with_natural_persons": true, "disclosure_at_interaction_start": true}}}}
	data.eu_ai_act.transparency.compliant with input as i
}

test_transparency_chatbot_users_informed_is_compliant if {
	i := {"eu_ai_act": {"transparency": {"chatbot": {"interacts_with_natural_persons": true, "users_informed_of_ai_nature": true, "disclosure_at_interaction_start": true}}}}
	data.eu_ai_act.transparency.compliant with input as i
}

test_transparency_chatbot_without_any_disclosure_still_fails if {
	i := {"eu_ai_act": {"transparency": {"chatbot": {"interacts_with_natural_persons": true}}}}
	not data.eu_ai_act.transparency.compliant with input as i
	v := data.eu_ai_act.transparency.violations with input as i
	count(v) == 2
}

test_transparency_registration_violation_cites_article_49 if {
	i := {"eu_ai_act": {"transparency": {"deployment": {"high_risk_system": true}}}}
	v := data.eu_ai_act.transparency.violations with input as i
	some m in v
	startswith(m, "Article 49:")
}
