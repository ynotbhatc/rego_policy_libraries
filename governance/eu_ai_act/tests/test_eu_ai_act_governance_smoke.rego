package eu_ai_act.governance_test

import rego.v1

# Generated smoke test for governance/eu_ai_act/eu_ai_act_governance.rego (scripts/gen_tests.py). Each rule states one thing the module was proven
# to do on empty input; a missing rule means the module does not do that, see docs/TEST_GENERATION.md.

test_eu_ai_act_governance_loads_on_empty_input if {
	m := data.eu_ai_act.governance with input as {}
	is_object(m)
}

test_eu_ai_act_governance_report_wellformed_on_empty_input if {
	report := data.eu_ai_act.governance.compliance_report with input as {}
	is_object(report)
	count(report) > 0
}

test_eu_ai_act_governance_fail_closed_on_empty_input if {
	report := data.eu_ai_act.governance.compliance_report with input as {}
	not object.get(report, "compliant", false) == true
}

test_eu_ai_act_governance_violations_on_empty_input if {
	v := data.eu_ai_act.governance.violations with input as {}
	count(v) > 0
}

# Semantic review 2026-11-13: omitting the applicability flags must not silently skip FRIA / registration.
test_missing_applicability_flags_fail_closed if {
	inp := {"eu_ai_act": {"governance": {"deployer": {}, "fria": {}}}}
	v := data.eu_ai_act.governance.violations with input as inp
	"Article 27: evidence missing — fria.assessment_required not collected; FRIA applicability undetermined" in v
	"Article 26.8: evidence missing — deployer.annex_iii_use_case not collected; EU database registration applicability undetermined" in v
}

test_explicit_not_applicable_flags_do_not_raise_scope_finding if {
	inp := {"eu_ai_act": {"governance": {"deployer": {"high_risk_public_or_private_sector": false, "annex_iii_use_case": false}, "fria": {"assessment_required": false}}}}
	v := data.eu_ai_act.governance.violations with input as inp
	not "Article 27: evidence missing — fria.assessment_required not collected; FRIA applicability undetermined" in v
}
