package cis.aws.iam_test

import rego.v1

# Validation fix 2026-10-17: MFA / stale-credential comprehensions bound the user
# value and indexed by it (always empty -> always pass); controls lacked defaults.

test_mfa_missing_fails if {
	not data.cis.aws.iam.mfa_enabled_for_console_users with input as {"iam_users": {"alice": {"console_access": true, "mfa_enabled": false}}}
}

test_mfa_present_passes if {
	data.cis.aws.iam.mfa_enabled_for_console_users with input as {"iam_users": {"alice": {"console_access": true, "mfa_enabled": true}, "bot": {"console_access": false}}}
}

test_mfa_no_iam_users_evidence_fails if {
	not data.cis.aws.iam.mfa_enabled_for_console_users with input as {}
}

test_old_credentials_fail if {
	not data.cis.aws.iam.old_credentials_disabled with input as {"iam_users": {"alice": {"last_used": "2020-01-01T00:00:00Z"}}}
}

test_recent_credentials_pass if {
	data.cis.aws.iam.old_credentials_disabled with input as {"iam_users": {"alice": {"last_used": "2999-01-01T00:00:00Z"}}}
}

test_report_populated_when_control_fails if {
	r := data.cis.aws.iam.aws_iam_compliance with input as {"iam_password_policy": {"minimum_password_length": 8}}
	r.password_policy_min_length == false
	r.overall_compliant == false
	count(r) == 15
}
