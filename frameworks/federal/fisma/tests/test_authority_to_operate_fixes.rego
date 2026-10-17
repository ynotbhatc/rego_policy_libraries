package fisma.ato_fixes_test

import rego.v1

ato := data.fisma.ato

inp(risk, resolved, items) := {"ato": {
	"risk_assessment": {"residual_risk": {"overall_risk_level": risk}},
	"controls": {"deficiencies": {"critical_deficiencies_resolved": resolved}},
	"authorization_package": {"poam": {"action_items": items}},
	"poam": {"timeline": {"critical_items_timeline": 30}},
}}

# Moderate risk, complete package, resolved criticals, 3 POA&M items: used to make
# AUTHORIZE and AUTHORIZE_WITH_CONDITIONS both fire (eval_conflict_error).
test_moderate_with_poam_items_single_decision if {
	r := ato.ato_decision_recommendation with input as inp("moderate", true, [1, 2, 3])
		with data.fisma.ato.authorization_package_complete as true
		with data.fisma.ato.security_controls_effective as true
		with data.fisma.ato.ato_ready as true
	r == "AUTHORIZE_WITH_CONDITIONS"
}

test_low_risk_ready_authorizes if {
	r := ato.ato_decision_recommendation with input as inp("low", true, [])
		with data.fisma.ato.authorization_package_complete as true
		with data.fisma.ato.ato_ready as true
	r == "AUTHORIZE"
}

test_low_risk_unresolved_criticals_defined_and_denied if {
	r := ato.ato_decision_recommendation with input as inp("low", false, [])
		with data.fisma.ato.authorization_package_complete as true
		with data.fisma.ato.ato_ready as true
	r == "DENY"
}

test_moderate_unresolved_criticals_interim if {
	r := ato.ato_decision_recommendation with input as inp("moderate", false, [1])
		with data.fisma.ato.authorization_package_complete as true
		with data.fisma.ato.security_controls_effective as true
	r == "INTERIM_AUTHORIZE"
}

test_high_risk_denied if {
	r := ato.ato_decision_recommendation with input as inp("high", true, [])
		with data.fisma.ato.authorization_package_complete as true
		with data.fisma.ato.ato_ready as true
	r == "DENY"
}

test_incomplete_package_denied if {
	ato.ato_decision_recommendation == "DENY" with input as inp("low", true, [])
}

# Undefined-in-literal trap: a failing assessment must still produce the report.
test_assessment_defined_on_empty_input if {
	a := ato.ato_assessment with input as {}
	a.ato_ready == false
	a.readiness_score == 0
	a.decision_recommendation == "DENY"
	count(a.assessment_areas) == 6
}

test_readiness_score_counts_passing_areas_despite_failures if {
	s := ato.ato_readiness_score with input as {}
		with data.fisma.ato.authorization_package_complete as true
		with data.fisma.ato.risk_assessment_acceptable as true
	s == 100 / 3
}
