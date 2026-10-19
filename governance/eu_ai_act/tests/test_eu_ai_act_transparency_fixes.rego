package eu_ai_act.transparency_test

import rego.v1

# Regression tests for validation 2026-10-17 fixes.

# decisions 2026-10-19: every Art. 50 section must be declared; explicit false flags mark N/A.
na_chatbot := {"interacts_with_natural_persons": false}

na_rest := {
	"emotion_recognition": {"system_deployed": false},
	"biometric_categorization": {"system_deployed": false},
	"deep_fake": {"generates_synthetic_image": false},
	"public_interest_text": {"generates_text_on_public_interest": false},
	"deployment": {"high_risk_system": false},
}

all_na := {"eu_ai_act": {"transparency": object.union({"chatbot": na_chatbot}, na_rest)}}

with_chatbot(c) := {"eu_ai_act": {"transparency": object.union({"chatbot": c}, na_rest)}}

test_transparency_empty_input_is_not_compliant if {
	not data.eu_ai_act.transparency.compliant with input as {}
	"Article 50: evidence missing — eu_ai_act.transparency assessment not provided" in data.eu_ai_act.transparency.violations with input as {}
}

test_transparency_empty_assessment_is_not_compliant if {
	not data.eu_ai_act.transparency.compliant with input as {"eu_ai_act": {"transparency": {}}}
}

test_transparency_assessment_with_nothing_applicable_is_compliant if {
	data.eu_ai_act.transparency.compliant with input as all_na
}

test_transparency_chatbot_disclosed_at_start_is_compliant if {
	i := with_chatbot({"interacts_with_natural_persons": true, "disclosure_at_interaction_start": true})
	data.eu_ai_act.transparency.compliant with input as i
}

test_transparency_chatbot_users_informed_is_compliant if {
	i := with_chatbot({"interacts_with_natural_persons": true, "users_informed_of_ai_nature": true, "disclosure_at_interaction_start": true})
	data.eu_ai_act.transparency.compliant with input as i
}

test_transparency_chatbot_without_any_disclosure_still_fails if {
	i := with_chatbot({"interacts_with_natural_persons": true})
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

# decisions 2026-10-19: silence on an Art. 50 section is not read as "not applicable".
test_transparency_undeclared_section_not_compliant if {
	i := json.remove(all_na, ["eu_ai_act/transparency/deep_fake"])
	not data.eu_ai_act.transparency.compliant with input as i
	v := data.eu_ai_act.transparency.violations with input as i
	count(v) == 1
	some m in v
	contains(m, "Article 50.3: applicability not determined — transparency.deep_fake")
}

test_transparency_only_chatbot_declared_flags_every_other_section if {
	i := {"eu_ai_act": {"transparency": {"chatbot": na_chatbot}}}
	v := data.eu_ai_act.transparency.violations with input as i
	count(v) == 5
}

test_transparency_all_sections_explicit_false_is_compliant if {
	data.eu_ai_act.transparency.compliant with input as all_na
}
