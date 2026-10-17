package cis.azure.iam_test

import rego.v1

# Validation fix 2026-10-17: missing MFA field / absent user list passed; role "*" passed; no defaults.

test_priv_mfa_field_missing_fails if {
	not data.cis.azure.iam.mfa_enabled_privileged_users with input as {"privileged_users": [{"name": "a"}]}
}

test_priv_mfa_absent_list_fails if {
	not data.cis.azure.iam.mfa_enabled_privileged_users with input as {}
}

test_priv_mfa_ok if {
	data.cis.azure.iam.mfa_enabled_privileged_users with input as {"privileged_users": [{"name": "a", "mfa_enabled": true}]}
}

test_nonpriv_mfa_field_missing_fails if {
	not data.cis.azure.iam.mfa_enabled_non_privileged_users with input as {"non_privileged_users": [{"name": "b"}]}
}

test_nonpriv_mfa_ok if {
	data.cis.azure.iam.mfa_enabled_non_privileged_users with input as {"non_privileged_users": [{"name": "b", "mfa_enabled": true}]}
}

test_custom_role_star_string_fails if {
	not data.cis.azure.iam.no_custom_subscription_owner_roles with input as {"custom_roles": [{"permissions": "*"}]}
}

test_custom_role_star_array_fails if {
	not data.cis.azure.iam.no_custom_subscription_owner_roles with input as {"custom_roles": [{"permissions": ["Microsoft.Compute/read", "*"]}]}
}

test_custom_role_write_wildcard_fails if {
	not data.cis.azure.iam.no_custom_subscription_owner_roles with input as {"custom_roles": [{"permissions": "Microsoft.Compute/*/write"}]}
}

test_custom_role_benign_passes if {
	data.cis.azure.iam.no_custom_subscription_owner_roles with input as {"custom_roles": [{"permissions": ["Microsoft.Compute/virtualMachines/read"]}]}
}

test_report_populated_on_empty_input if {
	r := data.cis.azure.iam.azure_iam_compliance with input as {}
	r.overall_compliant == false
	r.mfa_enabled_privileged_users == false
}
