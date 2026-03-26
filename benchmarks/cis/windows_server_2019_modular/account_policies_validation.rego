package cis_windows_server_2019.account_policies

# CIS Windows Server 2019 Benchmark v3.0.0 - Section 1: Account Policies

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	[v | some v in password_policy_violations],
	[v | some v in lockout_policy_violations],
)

# CIS 1.1.1: Enforce password history >= 24
password_policy_violations contains msg if {
	input.account_policies.password_history_size < 24
	msg := sprintf("CIS 1.1.1: Password history is %d, should be 24 or more", [input.account_policies.password_history_size])
}

# CIS 1.1.2: Maximum password age <= 365 and not 0
password_policy_violations contains msg if {
	input.account_policies.maximum_password_age > 365
	msg := sprintf("CIS 1.1.2: Maximum password age is %d days, should be 365 or less", [input.account_policies.maximum_password_age])
}

password_policy_violations contains msg if {
	input.account_policies.maximum_password_age == 0
	msg := "CIS 1.1.2: Maximum password age is 0 (never expires) - should be 365 or less"
}

# CIS 1.1.3: Minimum password age >= 1
password_policy_violations contains msg if {
	input.account_policies.minimum_password_age < 1
	msg := sprintf("CIS 1.1.3: Minimum password age is %d days, should be 1 or more", [input.account_policies.minimum_password_age])
}

# CIS 1.1.4: Minimum password length >= 14
password_policy_violations contains msg if {
	input.account_policies.minimum_password_length < 14
	msg := sprintf("CIS 1.1.4: Minimum password length is %d, should be 14 or more", [input.account_policies.minimum_password_length])
}

# CIS 1.1.5: Password complexity = Enabled
password_policy_violations contains msg if {
	not input.account_policies.password_complexity_enabled
	msg := "CIS 1.1.5: Password complexity requirements are not enabled"
}

# CIS 1.1.6: Relax minimum password length limits = Enabled
password_policy_violations contains msg if {
	not input.account_policies.relax_minimum_password_length
	msg := "CIS 1.1.6: Relax minimum password length limits is not enabled"
}

# CIS 1.1.7: Store passwords using reversible encryption = Disabled
password_policy_violations contains msg if {
	input.account_policies.store_plaintext_passwords
	msg := "CIS 1.1.7: Store passwords using reversible encryption is enabled (must be disabled)"
}

# CIS 1.2.1: Account lockout duration >= 15 minutes
lockout_policy_violations contains msg if {
	input.account_policies.lockout_duration > 0
	input.account_policies.lockout_duration < 15
	msg := sprintf("CIS 1.2.1: Account lockout duration is %d minutes, should be 15 or more", [input.account_policies.lockout_duration])
}

# CIS 1.2.2: Account lockout threshold 1-10
lockout_policy_violations contains msg if {
	input.account_policies.lockout_threshold == 0
	msg := "CIS 1.2.2: Account lockout threshold is 0 (disabled) - should be 5 or less"
}

lockout_policy_violations contains msg if {
	input.account_policies.lockout_threshold > 10
	msg := sprintf("CIS 1.2.2: Account lockout threshold is %d, should be 10 or less", [input.account_policies.lockout_threshold])
}

# CIS 1.2.3: Allow Administrator account lockout = Enabled
lockout_policy_violations contains msg if {
	not input.account_policies.admin_lockout_enabled
	msg := "CIS 1.2.3: Administrator account lockout is not enabled"
}

# CIS 1.2.4: Reset account lockout counter >= 15 minutes
lockout_policy_violations contains msg if {
	input.account_policies.lockout_observation_window < 15
	msg := sprintf("CIS 1.2.4: Account lockout observation window is %d minutes, should be 15 or more", [input.account_policies.lockout_observation_window])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"password_policy_violations": count(password_policy_violations),
	"lockout_policy_violations": count(lockout_policy_violations),
	"controls_checked": 11,
	"section": "1 Account Policies",
	"benchmark": "CIS Windows Server 2019 v3.0.0",
}
