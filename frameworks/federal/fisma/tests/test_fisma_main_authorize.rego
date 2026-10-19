package fisma.main_test

import rego.v1

# Decisions 2026-10-19: a documented "deny" decision completes the paperwork
# but does not make RMF step 6 (Authorize) compliant.

authorize_input(decision) := {"fisma": {"authorize": {
	"package": {
		"system_security_plan_current": true,
		"security_assessment_report_current": true,
		"plan_of_action_milestones_current": true,
		"risk_assessment_current": true,
	},
	"risk_assessment": {
		"methodology_documented": true,
		"threat_analysis_completed": true,
		"vulnerability_analysis_completed": true,
		"risk_determination_documented": true,
		"residual_risk_acceptable": true,
	},
	"decision": {
		"authorizing_official_decision": decision,
		"decision_rationale_documented": true,
		"authorization_letter_issued": true,
	},
	"terms_conditions": {
		"authorization_boundary_defined": true,
		"authorization_period_defined": true,
		"conditions_compliance_required": true,
		"reporting_requirements_defined": true,
	},
}}}

test_authorize_decision_completes_step_6 if {
	data.fisma.main.rmf_step_6_authorize_compliant with input as authorize_input("authorize")
}

test_interim_authorize_decision_completes_step_6 if {
	data.fisma.main.rmf_step_6_authorize_compliant with input as authorize_input("interim_authorize")
}

test_deny_decision_is_documented_but_step_6_not_compliant if {
	i := authorize_input("deny")
	data.fisma.main.authorization_decision_documented with input as i
	not data.fisma.main.authorization_granted with input as i
	not data.fisma.main.rmf_step_6_authorize_compliant with input as i
}
