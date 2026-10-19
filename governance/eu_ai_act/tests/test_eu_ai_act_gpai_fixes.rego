package eu_ai_act.gpai_test

import rego.v1

msgs(i) := {m | some m in data.eu_ai_act.gpai.violations with input as i}

has_msg(i, needle) if {
	some m in msgs(i)
	contains(m, needle)
}

test_flops_above_threshold_triggers_art55_even_when_flags_false if {
	i := {"eu_ai_act": {"gpai": {
		"article_54": {"provider_established_outside_eu": false},
		"article_55": {"training_flops": 3e25, "training_flops_exceeds_threshold": false, "systemic_risk_model": false},
	}}}
	has_msg(i, "Article 55.1: GPAI model with training computation exceeding")
	has_msg(i, "Article 55.1(a): Model evaluation")
	has_msg(i, "classification is presumed under Art. 51(2)")
}

test_flops_below_threshold_no_art55_obligations if {
	i := {"eu_ai_act": {"gpai": {
		"article_54": {"provider_established_outside_eu": false},
		"article_55": {"training_flops": 1e24, "training_flops_exceeds_threshold": false, "systemic_risk_model": false},
	}}}
	not has_msg(i, "Article 55")
	not has_msg(i, "Article 51")
}

test_numeric_string_flops_is_read if {
	i := {"eu_ai_act": {"gpai": {"article_55": {"training_flops": "2e25"}}}}
	has_msg(i, "Article 55.1: GPAI model with training computation exceeding")
}

test_no_classification_evidence_is_a_violation if {
	has_msg({}, "systemic-risk classification cannot be established")
}

test_declared_flag_alone_is_enough_evidence if {
	i := {"eu_ai_act": {"gpai": {"article_55": {"training_flops_exceeds_threshold": false}}}}
	not has_msg(i, "systemic-risk classification cannot be established")
}

test_missing_art54_flag_is_a_violation if {
	has_msg({}, "provider_established_outside_eu not declared")
}

test_explicit_eu_provider_has_no_art54_violation if {
	i := {"eu_ai_act": {"gpai": {"article_54": {"provider_established_outside_eu": false}}}}
	not has_msg(i, "Article 54")
}

test_non_eu_provider_without_representative_violates if {
	i := {"eu_ai_act": {"gpai": {"article_54": {"provider_established_outside_eu": true}}}}
	has_msg(i, "has not designated an authorized representative")
}

# decisions 2026-10-19: Commission designation (Art. 51(1)(b)) triggers Art. 55 obligations.
test_commission_designation_triggers_art55_below_flops_threshold if {
	i := {"eu_ai_act": {"gpai": {
		"article_54": {"provider_established_outside_eu": false},
		"article_55": {"training_flops": 1e24, "systemic_risk_model": false, "commission_designated": true},
	}}}
	has_msg(i, "Article 55.1(a): Model evaluation")
	has_msg(i, "Article 51(1)(b)")
}

test_commission_designation_counts_as_classification_evidence if {
	i := {"eu_ai_act": {"gpai": {"article_55": {"commission_designated": true}}}}
	not has_msg(i, "evidence missing — article_55.training_flops")
}

test_no_designation_flag_leaves_classification_unchanged if {
	i := {"eu_ai_act": {"gpai": {
		"article_54": {"provider_established_outside_eu": false},
		"article_55": {"training_flops": 1e24, "systemic_risk_model": false},
	}}}
	not has_msg(i, "Article 55")
}
