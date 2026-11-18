# METADATA
# title: "CMMC 2.0 — Domain 3.5: Identification & Authentication"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 53
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cmmc.identification_authentication

import rego.v1

# Organisation-defined parameters. Where NIST SP 800-171 R2 leaves a period,
# frequency or count to the organisation ("a defined period", "periodically",
# "a specified number"; NIST SP 800-171A objectives "... is defined"), the
# organisation's value is read from input.org_defined.<name> and the observed
# value is compared with it. Either one missing, or not a number, is a finding.
# is_number guards every comparison: OPA orders null below numbers and strings
# above them.
_odp(name) := v if {
	v := input.org_defined[name]
	is_number(v)
}

_actual(path) := v if {
	v := object.get(input, path, null)
	is_number(v)
}

_at_most(path, name) if _actual(path) <= _odp(name)

_at_least(path, name) if _actual(path) >= _odp(name)

# 32 CFR 170.14(d): "periodically" means an organisation-defined interval of no
# more than one year.
_periodic_ok(name) if _odp(name) <= 365

# =============================================================================
# CMMC 2.0 — Domain 3.5: Identification & Authentication
# NIST SP 800-171 Rev 2 — 11 Practices
# =============================================================================

# 3.5.1 — Identify system users, processes, and devices. (L1)
default compliant_3_5_1 := false

compliant_3_5_1 if {
	input.identity.unique_user_accounts == true
	input.identity.shared_accounts_documented == true
	input.identity.service_accounts_identified == true
}

violation_3_5_1 contains msg if {
	not input.identity.unique_user_accounts
	msg := "3.5.1: System users do not have unique identifiers"
}

violation_3_5_1 contains msg if {
	not input.identity.service_accounts_identified
	msg := "3.5.1: System processes and service accounts are not identified"
}

# 3.5.2 — Authenticate the identities of users, processes, or devices before
#          allowing access. (L1)
default compliant_3_5_2 := false

compliant_3_5_2 if {
	input.identity.authentication_required == true
}

violation_3_5_2 contains msg if {
	not input.identity.authentication_required
	msg := "3.5.2: Authentication is not required before granting system access"
}

# 3.5.3 — Use multifactor authentication for local and network access to
#          privileged accounts. (L2)
default compliant_3_5_3 := false

compliant_3_5_3 if {
	input.identity.mfa_privileged_accounts == true
	input.identity.mfa_network_access == true
}

violation_3_5_3 contains msg if {
	not input.identity.mfa_privileged_accounts
	msg := "3.5.3: MFA is not enforced for privileged account access"
}

violation_3_5_3 contains msg if {
	not input.identity.mfa_network_access
	msg := "3.5.3: MFA is not enforced for network access to privileged accounts"
}

# 3.5.4 — Employ replay-resistant authentication mechanisms for network access
#          to privileged and non-privileged accounts. (L2)
default compliant_3_5_4 := false

compliant_3_5_4 if {
	input.identity.replay_resistant_auth == true
	input.identity.kerberos_or_pki == true
}

violation_3_5_4 contains msg if {
	not input.identity.replay_resistant_auth
	msg := "3.5.4: Replay-resistant authentication is not implemented for network access"
}

# 3.5.5 — Prevent reuse of identifiers for a defined period. (L2)
#          The period is organisation-defined (NIST SP 800-171A 3.5.5[a]). The
#          inactivity check that sat here belongs to 3.5.6 and is decided there.
default compliant_3_5_5 := false

compliant_3_5_5 if {
	input.identity.automated_account_management == true
	_at_least(["identity", "identifier_reuse_prevented_days"], "identifier_reuse_period_days")
}

violation_3_5_5 contains msg if {
	not input.identity.automated_account_management
	msg := "3.5.5: No automated tool enforcing account management policies"
}

violation_3_5_5 contains "3.5.5: evidence missing - input.org_defined.identifier_reuse_period_days (organisation-defined value, NIST SP 800-171A 3.5.5[a]) not supplied or not a number" if {
	not _odp("identifier_reuse_period_days")
}

violation_3_5_5 contains "3.5.5: evidence missing - input.identity.identifier_reuse_prevented_days not collected or not a number" if {
	not _actual(["identity", "identifier_reuse_prevented_days"])
}

violation_3_5_5 contains msg if {
	_actual(["identity", "identifier_reuse_prevented_days"]) < _odp("identifier_reuse_period_days")
	msg := sprintf("3.5.5: identifiers can be reused after %v days, sooner than the organisation-defined period of %v days", [_actual(["identity", "identifier_reuse_prevented_days"]), _odp("identifier_reuse_period_days")])
}

# 3.5.6 — Manage system identifiers by disabling the user identifier after a
#          defined inactivity period. (L2)
default compliant_3_5_6 := false

compliant_3_5_6 if {
	input.identity.identifier_management_policy == true
	_at_most(["identity", "inactive_account_disable_days"], "identifier_inactivity_days")
	input.identity.terminated_accounts_disabled_immediately == true
}

violation_3_5_6 contains msg if {
	not input.identity.identifier_management_policy
	msg := "3.5.6: No policy for managing and disabling inactive system identifiers"
}

violation_3_5_6 contains msg if {
	not input.identity.terminated_accounts_disabled_immediately
	msg := "3.5.6: Terminated user accounts are not disabled immediately upon separation"
}

violation_3_5_6 contains "3.5.6: evidence missing - input.org_defined.identifier_inactivity_days (organisation-defined value, NIST SP 800-171A 3.5.6[a]) not supplied or not a number" if {
	not _odp("identifier_inactivity_days")
}

violation_3_5_6 contains "3.5.6: evidence missing - input.identity.inactive_account_disable_days not collected or not a number" if {
	not _actual(["identity", "inactive_account_disable_days"])
}

violation_3_5_6 contains msg if {
	_actual(["identity", "inactive_account_disable_days"]) > _odp("identifier_inactivity_days")
	msg := sprintf("3.5.6: identifiers disabled after %v days of inactivity, beyond the organisation-defined period of %v days", [_actual(["identity", "inactive_account_disable_days"]), _odp("identifier_inactivity_days")])
}

# 3.5.7 — Enforce a minimum password complexity and change when new passwords
#          are created. (L2)
default compliant_3_5_7 := false

compliant_3_5_7 if {
	_at_least(["identity", "password_min_length"], "password_min_length")
	input.identity.password_complexity_uppercase == true
	input.identity.password_complexity_lowercase == true
	input.identity.password_complexity_numbers == true
	input.identity.password_complexity_special == true
}

violation_3_5_7 contains "3.5.7: evidence missing - input.org_defined.password_min_length (organisation-defined value, NIST SP 800-171A 3.5.7[a]) not supplied or not a number" if {
	not _odp("password_min_length")
}

violation_3_5_7 contains "3.5.7: evidence missing - input.identity.password_min_length not collected or not a number" if {
	not _actual(["identity", "password_min_length"])
}

violation_3_5_7 contains msg if {
	_actual(["identity", "password_min_length"]) < _odp("password_min_length")
	msg := sprintf("3.5.7: minimum password length %v is below the organisation-defined %v", [_actual(["identity", "password_min_length"]), _odp("password_min_length")])
}

violation_3_5_7 contains msg if {
	not input.identity.password_complexity_uppercase
	msg := "3.5.7: Password policy does not require uppercase characters"
}

violation_3_5_7 contains msg if {
	not input.identity.password_complexity_numbers
	msg := "3.5.7: Password policy does not require numeric characters"
}

violation_3_5_7 contains msg if {
	not input.identity.password_complexity_special
	msg := "3.5.7: Password policy does not require special characters"
}

# 3.5.8 — Prohibit password reuse for a specified number of generations. (L2)
default compliant_3_5_8 := false

compliant_3_5_8 if {
	_at_least(["identity", "password_history_count"], "password_history_generations")
}

violation_3_5_8 contains "3.5.8: evidence missing - input.org_defined.password_history_generations (organisation-defined value, NIST SP 800-171A 3.5.8[a]) not supplied or not a number" if {
	not _odp("password_history_generations")
}

violation_3_5_8 contains "3.5.8: evidence missing - input.identity.password_history_count not collected or not a number" if {
	not _actual(["identity", "password_history_count"])
}

violation_3_5_8 contains msg if {
	_actual(["identity", "password_history_count"]) < _odp("password_history_generations")
	msg := sprintf("3.5.8: password reuse prohibited for %v generations, fewer than the organisation-specified %v", [_actual(["identity", "password_history_count"]), _odp("password_history_generations")])
}

# 3.5.9 — Allow temporary password use with an immediate change requirement. (L2)
#          R2 3.5.9 requires the immediate change; it sets no expiry for a
#          temporary password, so the former 24-hour expiry limit is removed.
default compliant_3_5_9 := false

compliant_3_5_9 if {
	input.identity.temp_password_change_on_first_login == true
}

violation_3_5_9 contains msg if {
	not input.identity.temp_password_change_on_first_login
	msg := "3.5.9: Temporary passwords do not require immediate change on first use"
}

# 3.5.10 — Store and transmit only cryptographically protected passwords. (L2)
default compliant_3_5_10 := false

compliant_3_5_10 if {
	input.identity.passwords_hashed == true
	input.identity.hash_algorithm != "md5"
	input.identity.hash_algorithm != "sha1"
	input.identity.passwords_transmitted_encrypted == true
}

violation_3_5_10 contains msg if {
	not input.identity.passwords_hashed
	msg := "3.5.10: Passwords are not stored using cryptographic hashing"
}

violation_3_5_10 contains msg if {
	input.identity.hash_algorithm == "md5"
	msg := "3.5.10: Passwords are hashed with MD5 — must use SHA-256 or stronger"
}

violation_3_5_10 contains msg if {
	input.identity.hash_algorithm == "sha1"
	msg := "3.5.10: Passwords are hashed with SHA-1 — must use SHA-256 or stronger"
}

violation_3_5_10 contains msg if {
	not input.identity.passwords_transmitted_encrypted
	msg := "3.5.10: Passwords are transmitted without encryption"
}

# 3.5.11 — Obscure feedback of authentication information during the
#           authentication process. (L2)
default compliant_3_5_11 := false

compliant_3_5_11 if {
	input.identity.password_masking_enabled == true
	input.identity.failed_login_no_detail == true
}

violation_3_5_11 contains msg if {
	not input.identity.password_masking_enabled
	msg := "3.5.11: Authentication feedback (password echo) is not obscured"
}

violation_3_5_11 contains msg if {
	not input.identity.failed_login_no_detail
	msg := "3.5.11: Failed authentication attempts reveal excessive detail about credentials"
}

# ---------------------------------------------------------------------------
# Aggregate compliance
# ---------------------------------------------------------------------------

base_violations := array.concat(
	array.concat(
		array.concat(
			[v | some v in violation_3_5_1],
			[v | some v in violation_3_5_2],
		),
		array.concat(
			[v | some v in violation_3_5_3],
			[v | some v in violation_3_5_4],
		),
	),
	array.concat(
		array.concat(
			[v | some v in violation_3_5_5],
			[v | some v in violation_3_5_6],
		),
		array.concat(
			array.concat(
				[v | some v in violation_3_5_7],
				[v | some v in violation_3_5_8],
			),
			array.concat(
				[v | some v in violation_3_5_9],
				array.concat(
					[v | some v in violation_3_5_10],
					[v | some v in violation_3_5_11],
				),
			),
		),
	),
)

# ---------------------------------------------------------------------------
# Unmet practices without a specific finding (fail closed)
#   A practice whose compliant_N rule is false because a required fact is
#   missing or failing must surface a violation, so that the domain verdict
#   (count(all_violations) == 0) can never be true while a practice fails.
# ---------------------------------------------------------------------------

violation_unmet contains msg if {
	not compliant_3_5_1
	count(violation_3_5_1) == 0
	msg := "3.5.1: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_2
	count(violation_3_5_2) == 0
	msg := "3.5.2: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_3
	count(violation_3_5_3) == 0
	msg := "3.5.3: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_4
	count(violation_3_5_4) == 0
	msg := "3.5.4: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_5
	count(violation_3_5_5) == 0
	msg := "3.5.5: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_6
	count(violation_3_5_6) == 0
	msg := "3.5.6: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_7
	count(violation_3_5_7) == 0
	msg := "3.5.7: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_8
	count(violation_3_5_8) == 0
	msg := "3.5.8: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_9
	count(violation_3_5_9) == 0
	msg := "3.5.9: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_10
	count(violation_3_5_10) == 0
	msg := "3.5.10: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

violation_unmet contains msg if {
	not compliant_3_5_11
	count(violation_3_5_11) == 0
	msg := "3.5.11: evidence missing or requirement not met — all facts required by this practice must be present and passing"
}

all_violations := array.concat(base_violations, [m | some m in violation_unmet])

practices := [
	{"id": "3.5.1", "level": 1, "compliant": compliant_3_5_1},
	{"id": "3.5.2", "level": 1, "compliant": compliant_3_5_2},
	{"id": "3.5.3", "level": 2, "compliant": compliant_3_5_3},
	{"id": "3.5.4", "level": 2, "compliant": compliant_3_5_4},
	{"id": "3.5.5", "level": 2, "compliant": compliant_3_5_5},
	{"id": "3.5.6", "level": 2, "compliant": compliant_3_5_6},
	{"id": "3.5.7", "level": 2, "compliant": compliant_3_5_7},
	{"id": "3.5.8", "level": 2, "compliant": compliant_3_5_8},
	{"id": "3.5.9", "level": 2, "compliant": compliant_3_5_9},
	{"id": "3.5.10", "level": 2, "compliant": compliant_3_5_10},
	{"id": "3.5.11", "level": 2, "compliant": compliant_3_5_11},
]

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false

compliant if count(all_violations) == 0

# Level 1 practices only (FAR 52.204-21 subset). Used by cmmc_main for
# cmmc_level_1_compliant so Level 2 practices in this domain do not gate Level 1.
default level_1_passing := false

level_1_passing if {
	level_1_practices := [p | some p in practices; p.level == 1]
	count(level_1_practices) > 0
	every p in level_1_practices {
		p.compliant == true
	}
}

compliance_report := {
	"domain": "Identification & Authentication",
	"domain_id": "3.5",
	"total_practices": 11,
	"passing": passing_count,
	"failing": 11 - passing_count,
	"compliant": compliant,
	"violations": all_violations,
	"practices": practices,
	"level_1_passing": level_1_passing,
}
