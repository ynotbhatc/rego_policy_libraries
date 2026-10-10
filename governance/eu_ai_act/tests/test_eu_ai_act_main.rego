# Tests for eu_ai_act.main — the fail-closed gate (rego_policy_libraries#186).
#
# Contract: an assessment with no facts, or with facts but no classification,
# is non-compliant with an explicit violation; a classified system with no
# module violations still passes.

package eu_ai_act.main_test

import rego.v1

import data.eu_ai_act.main as pkg

# A minimal-risk system that declares the prohibited facts false.
clean_minimal := {"eu_ai_act": {
	"system_classification": {"risk_tier": "minimal_risk"},
	"prohibited": {"subliminal_manipulation": {"uses_subliminal_techniques": false}},
}}

test_empty_input_is_non_compliant if {
	r := pkg.compliance_report with input as {}
	r.compliant == false
	r.overall_compliant == false
	r.facts_supplied == false
	r.classified == false
	r.risk_tier == "prohibited"
}

test_empty_input_names_the_gate if {
	r := pkg.compliance_report with input as {}
	count([m | some m in r.violations; startswith(m, "FAIL-CLOSED: no eu_ai_act facts")]) == 1
	r.violation_count == count(r.violations)
	r.total_violations == count(r.violations)
}

test_report_carries_a_compliant_key_like_every_other_framework if {
	r := pkg.compliance_report with input as {}
	"compliant" in object.keys(r)
}

test_facts_without_classification_are_non_compliant if {
	inp := {"eu_ai_act": {"prohibited": {"subliminal_manipulation": {"uses_subliminal_techniques": false}}}}
	r := pkg.compliance_report with input as inp
	r.compliant == false
	r.facts_supplied == true
	r.classified == false
	count([m | some m in r.violations; contains(m, "risk_tier is missing")]) == 1
}

test_unknown_tier_is_treated_as_unclassified if {
	inp := {"eu_ai_act": {"system_classification": {"risk_tier": "low"}}}
	r := pkg.compliance_report with input as inp
	r.compliant == false
	r.classified == false
}

test_classified_clean_system_passes if {
	r := pkg.compliance_report with input as clean_minimal
	r.compliant == true
	r.overall_compliant == true
	r.risk_tier == "minimal_risk"
	count(r.violations) == 0
}

test_classified_system_with_a_prohibited_violation_fails_on_the_article_not_the_gate if {
	inp := {"eu_ai_act": {
		"system_classification": {"risk_tier": "minimal_risk"},
		"prohibited": {"subliminal_manipulation": {"uses_subliminal_techniques": true}},
	}}
	r := pkg.compliance_report with input as inp
	r.compliant == false
	count([m | some m in r.violations; startswith(m, "FAIL-CLOSED")]) == 0
	count([m | some m in r.violations; contains(m, "Article 5.1(a)")]) >= 1
}

test_high_risk_tier_requires_every_applicable_module if {
	inp := {"eu_ai_act": {"system_classification": {"risk_tier": "high_risk"}}}
	r := pkg.compliance_report with input as inp
	r.classified == true
	count(r.applicable_modules) == 4

	# high_risk / transparency / governance have requirements that are not met by silence
	r.compliant == false
}
