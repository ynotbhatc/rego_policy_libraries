package governance.oidc_test

import rego.v1

# Behavioural tests for the role/framework decisions (replaces reliance on the
# load-only smoke test). Token-claim checks (iss/aud/exp/signature) are NOT
# covered by the base tok() helper, which builds a fully valid token; claim
# checks are in test_oidc_token_validation_claims.rego.

tok(roles) := {
	"issuer": "https://sso.example.com/realms/aac",
	"client_id": "aac-portal",
	"claims": {
		"sub": "u1", "preferred_username": "u1",
		"iss": "https://sso.example.com/realms/aac", "aud": "aac-portal",
		"exp": 4102444800,
		"realm_access": {"roles": roles},
	},
}

test_viewer_can_read_results if {
	data.governance.oidc.authorized with input as {"token": tok(["viewer"]), "resource": {"type": "results", "framework": "cis_rhel9"}}
}

test_viewer_cannot_launch_assessment if {
	not data.governance.oidc.authorized with input as {"token": tok(["viewer"]), "resource": {"type": "assessment_launch", "framework": "cis_rhel9"}}
}

test_admin_can_launch_assessment if {
	data.governance.oidc.authorized with input as {"token": tok(["admin"]), "resource": {"type": "assessment_launch", "framework": "cis_rhel9"}}
}

test_analyst_cannot_read_ot_framework if {
	not data.governance.oidc.authorized with input as {"token": tok(["analyst"]), "resource": {"type": "report", "framework": "nerc_cip"}}
}

test_auditor_can_read_ot_framework_report if {
	data.governance.oidc.authorized with input as {"token": tok(["auditor"]), "resource": {"type": "report", "framework": "nerc_cip"}}
}

test_no_roles_denied_with_reason if {
	i := {"token": {"claims": {"sub": "u1"}}, "resource": {"type": "results"}}
	not data.governance.oidc.authorized with input as i
	r := data.governance.oidc.deny_reasons with input as i
	"Invalid or missing OIDC token" in r
}

test_summary_default_denies_without_token if {
	s := data.governance.oidc.summary with input as {}
	s.authorized == false
}
