package cis.aws.iam

import rego.v1

# CIS Amazon Web Services Foundations Benchmark
# Section 1: Identity and Access Management

# CIS 1.1 - Ensure IAM policies are attached only to groups or roles
iam_policies_not_attached_to_users if {
    count(input.iam_user_attached_policies) == 0
}

# CIS 1.2 - Ensure MFA is enabled for all IAM users that have a console password
mfa_enabled_for_console_users if {
    count([user | user := input.iam_users[_]; input.iam_users[user].console_access == true; input.iam_users[user].mfa_enabled == true]) == count([user | user := input.iam_users[_]; input.iam_users[user].console_access == true])
}

# CIS 1.3 - Ensure credentials unused for 90 days or greater are disabled
old_credentials_disabled if {
    count([user | user := input.iam_users[_]; input.iam_users[user].last_used; days_since_last_used(input.iam_users[user].last_used) >= 90]) == 0
}

days_since_last_used(last_used) := days if {
    now := time.now_ns()
    last_used_ns := time.parse_rfc3339_ns(last_used)
    days := (now - last_used_ns) / (24 * 60 * 60 * 1000000000)
}

# CIS 1.4 - Ensure access keys are rotated every 90 days or less
access_keys_rotated if {
    count([key | key := input.iam_access_keys[_]; days_since_created(key.created_date) >= 90]) == 0
}

days_since_created(created_date) := days if {
    now := time.now_ns()
    created_ns := time.parse_rfc3339_ns(created_date)
    days := (now - created_ns) / (24 * 60 * 60 * 1000000000)
}

# CIS 1.5 - Ensure IAM password policy requires minimum length of 14 or greater
password_policy_min_length if {
    input.iam_password_policy.minimum_password_length >= 14
}

# CIS 1.6 - Ensure IAM password policy prevents password reuse
password_policy_prevents_reuse if {
    input.iam_password_policy.password_reuse_prevention >= 24
}

# CIS 1.7 - Ensure IAM password policy requires at least one uppercase letter
password_policy_uppercase if {
    input.iam_password_policy.require_uppercase_characters == true
}

# CIS 1.8 - Ensure IAM password policy requires at least one lowercase letter
password_policy_lowercase if {
    input.iam_password_policy.require_lowercase_characters == true
}

# CIS 1.9 - Ensure IAM password policy requires at least one symbol
password_policy_symbols if {
    input.iam_password_policy.require_symbols == true
}

# CIS 1.10 - Ensure IAM password policy requires at least one number
password_policy_numbers if {
    input.iam_password_policy.require_numbers == true
}

# CIS 1.11 - Ensure IAM password policy expires passwords within 90 days or less
password_policy_max_age if {
    input.iam_password_policy.max_password_age <= 90
}

# CIS 1.12 - Ensure no root account access key exists
no_root_access_keys if {
    count(input.root_access_keys) == 0
}

# CIS 1.13 - Ensure MFA is enabled for the root account
root_mfa_enabled if {
    input.root_account.mfa_enabled == true
}

# CIS 1.14 - Ensure hardware MFA is enabled for the root account
root_hardware_mfa_enabled if {
    input.root_account.hardware_mfa_enabled == true
}

# Aggregate AWS IAM compliance
aws_iam_compliant if {
    iam_policies_not_attached_to_users
    mfa_enabled_for_console_users
    old_credentials_disabled
    access_keys_rotated
    password_policy_min_length
    password_policy_prevents_reuse
    password_policy_uppercase
    password_policy_lowercase
    password_policy_symbols
    password_policy_numbers
    password_policy_max_age
    no_root_access_keys
    root_mfa_enabled
    root_hardware_mfa_enabled
}

# Detailed AWS IAM compliance report
aws_iam_compliance := {
    "iam_policies_not_attached_to_users": iam_policies_not_attached_to_users,
    "mfa_enabled_for_console_users": mfa_enabled_for_console_users,
    "old_credentials_disabled": old_credentials_disabled,
    "access_keys_rotated": access_keys_rotated,
    "password_policy_min_length": password_policy_min_length,
    "password_policy_prevents_reuse": password_policy_prevents_reuse,
    "password_policy_uppercase": password_policy_uppercase,
    "password_policy_lowercase": password_policy_lowercase,
    "password_policy_symbols": password_policy_symbols,
    "password_policy_numbers": password_policy_numbers,
    "password_policy_max_age": password_policy_max_age,
    "no_root_access_keys": no_root_access_keys,
    "root_mfa_enabled": root_mfa_enabled,
    "root_hardware_mfa_enabled": root_hardware_mfa_enabled,
    "overall_compliant": aws_iam_compliant
}