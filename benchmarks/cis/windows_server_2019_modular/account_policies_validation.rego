# METADATA
# title: "CIS Windows Server 2019 Benchmark v4.0.0 - Section 1: Account Policies"
# custom:
#   class: security
#   framework: cis_windows_server_2019_modular
#   source: cis
#   domains: [windows]
#   coverage:
#     checks: 15
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_windows_server_2019.account_policies

# CIS Windows Server 2019 Benchmark v4.0.0 - Section 1: Account Policies

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	[v | some v in password_policy_violations],
	[v | some v in lockout_policy_violations],
)

# Numeric policy value; accepts numbers or numeric strings. Undefined when absent or not numeric.
policy_number(key) := to_number(input.account_policies[key])

# A missing numeric policy is missing evidence, not a pass.
password_policy_violations contains msg if {
	some key in ["password_history_size", "maximum_password_age", "minimum_password_age", "minimum_password_length"]
	not policy_number(key)
	msg := sprintf("CIS 1.1.x: evidence missing - account_policies.%s not collected", [key])
}

lockout_policy_violations contains msg if {
	some key in ["lockout_duration", "lockout_threshold", "lockout_observation_window"]
	not policy_number(key)
	msg := sprintf("CIS 1.2.x: evidence missing - account_policies.%s not collected", [key])
}

# CIS 1.1.1: Enforce password history >= 24
password_policy_violations contains msg if {
	policy_number("password_history_size") < 24
	msg := sprintf("CIS 1.1.1: Password history is %d, should be 24 or more", [policy_number("password_history_size")])
}

# CIS 1.1.2: Maximum password age <= 365 and not 0
password_policy_violations contains msg if {
	policy_number("maximum_password_age") > 365
	msg := sprintf("CIS 1.1.2: Maximum password age is %d days, should be 365 or less", [policy_number("maximum_password_age")])
}

password_policy_violations contains msg if {
	policy_number("maximum_password_age") == 0
	msg := "CIS 1.1.2: Maximum password age is 0 (never expires) - should be 365 or less"
}

# CIS 1.1.3: Minimum password age >= 1
password_policy_violations contains msg if {
	policy_number("minimum_password_age") < 1
	msg := sprintf("CIS 1.1.3: Minimum password age is %d days, should be 1 or more", [policy_number("minimum_password_age")])
}

# CIS 1.1.4: Minimum password length >= 14
password_policy_violations contains msg if {
	policy_number("minimum_password_length") < 14
	msg := sprintf("CIS 1.1.4: Minimum password length is %d, should be 14 or more", [policy_number("minimum_password_length")])
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
	policy_number("lockout_duration") > 0
	policy_number("lockout_duration") < 15
	msg := sprintf("CIS 1.2.1: Account lockout duration is %d minutes, should be 15 or more", [policy_number("lockout_duration")])
}

# CIS 1.2.2: Account lockout threshold 1-5
lockout_policy_violations contains msg if {
	policy_number("lockout_threshold") == 0
	msg := "CIS 1.2.2: Account lockout threshold is 0 (disabled) - should be 5 or less"
}

lockout_policy_violations contains msg if {
	policy_number("lockout_threshold") > 5
	msg := sprintf("CIS 1.2.2: Account lockout threshold is %d, should be 5 or fewer", [policy_number("lockout_threshold")])
}

# CIS 1.2.3: Allow Administrator account lockout = Enabled
lockout_policy_violations contains msg if {
	not input.account_policies.admin_lockout_enabled
	msg := "CIS 1.2.3: Administrator account lockout is not enabled"
}

# CIS 1.2.4: Reset account lockout counter >= 15 minutes
lockout_policy_violations contains msg if {
	policy_number("lockout_observation_window") < 15
	msg := sprintf("CIS 1.2.4: Account lockout observation window is %d minutes, should be 15 or more", [policy_number("lockout_observation_window")])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"password_policy_violations": count(password_policy_violations),
	"lockout_policy_violations": count(lockout_policy_violations),
	"controls_checked": 11,
	"section": "1 Account Policies",
	"benchmark": "CIS Windows Server 2019 v4.0.0",
}
