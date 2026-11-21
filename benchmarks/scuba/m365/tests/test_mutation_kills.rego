package scuba_m365.mutation_kill_test

# Tests that kill the mutants scripts/mutation_test.py found surviving in this directory (#306): boundary values
# on the numeric limits, the conditional MS.AAD.3.3 clause, and the baseline accounting check. Each test reads a
# single policy's finding, so the other facts in the input do not matter.

import rego.v1

_has(vs, id) if {
	some v in vs
	startswith(v, concat("", ["SCuBA ", id, "v"]))
}

# MS.AAD.3.3: the login-context clause applies only when Authenticator is evidenced as enabled; context shown
# without that evidence is not a pass.
test_aad_3_3_enabled_with_login_context_passes if {
	vs := data.scuba_m365.aad.violations with input as {"scuba": {"aad": {"auth": {"authenticator": {"enabled": true, "login_context_shown": true}}}}}
	not _has(vs, "MS.AAD.3.3")
}

test_aad_3_3_login_context_without_enabled_evidence_fails if {
	vs := data.scuba_m365.aad.violations with input as {"scuba": {"aad": {"auth": {"authenticator": {"login_context_shown": true}}}}}
	_has(vs, "MS.AAD.3.3")
}

# MS.AAD.5.6: 180 days or less
test_aad_5_6_180_days_passes if {
	vs := data.scuba_m365.aad.violations with input as {"scuba": {"aad": {"apps": {"password_lifetime_days": 180}}}}
	not _has(vs, "MS.AAD.5.6")
}

test_aad_5_6_181_days_fails if {
	vs := data.scuba_m365.aad.violations with input as {"scuba": {"aad": {"apps": {"password_lifetime_days": 181}}}}
	_has(vs, "MS.AAD.5.6")
}

# MS.AAD.7.1: a minimum of two and a maximum of eight Global Administrators, both ends included
test_aad_7_1_two_admins_passes if {
	vs := data.scuba_m365.aad.violations with input as {"scuba": {"aad": {"privileged": {"global_admin_count": 2}}}}
	not _has(vs, "MS.AAD.7.1")
}

test_aad_7_1_eight_admins_passes if {
	vs := data.scuba_m365.aad.violations with input as {"scuba": {"aad": {"privileged": {"global_admin_count": 8}}}}
	not _has(vs, "MS.AAD.7.1")
}

test_aad_7_1_one_admin_fails if {
	vs := data.scuba_m365.aad.violations with input as {"scuba": {"aad": {"privileged": {"global_admin_count": 1}}}}
	_has(vs, "MS.AAD.7.1")
}

test_aad_7_1_nine_admins_fails if {
	vs := data.scuba_m365.aad.violations with input as {"scuba": {"aad": {"privileged": {"global_admin_count": 9}}}}
	_has(vs, "MS.AAD.7.1")
}

# MS.SHAREPOINT.3.1 / 3.3: between 1 and 30 days; 0 (never expires / no re-authentication) is a finding
test_sharepoint_3_1_one_day_passes if {
	vs := data.scuba_m365.sharepoint.violations with input as {"scuba": {"sharepoint": {"anyone_links": {"expiration_days": 1}}}}
	not _has(vs, "MS.SHAREPOINT.3.1")
}

test_sharepoint_3_1_zero_days_fails if {
	vs := data.scuba_m365.sharepoint.violations with input as {"scuba": {"sharepoint": {"anyone_links": {"expiration_days": 0}}}}
	_has(vs, "MS.SHAREPOINT.3.1")
}

test_sharepoint_3_3_one_day_passes if {
	vs := data.scuba_m365.sharepoint.violations with input as {"scuba": {"sharepoint": {"verification_code_reauth_days": 1}}}
	not _has(vs, "MS.SHAREPOINT.3.3")
}

test_sharepoint_3_3_zero_days_fails if {
	vs := data.scuba_m365.sharepoint.violations with input as {"scuba": {"sharepoint": {"verification_code_reauth_days": 0}}}
	_has(vs, "MS.SHAREPOINT.3.3")
}

# The accounting check must notice a product module that stops counting one of its policies.
test_accounting_unbalanced_when_a_policy_is_not_counted if {
	not data.scuba_m365.main.accounting_balanced with data.scuba_m365.main.policies_evaluated as 103
}
