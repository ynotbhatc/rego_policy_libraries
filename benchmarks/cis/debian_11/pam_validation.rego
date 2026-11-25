# METADATA
# title: "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 5.4-5.5: PAM and..."
# custom:
#   class: security
#   framework: cis_debian_11
#   source: cis
#   domains: [linux, debian]
#   coverage:
#     checks: 36
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.5.0
package cis_debian_11.pam

# DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 — applied to Debian 11 (provenance: see README) - Sections 5.4-5.5: PAM and Password Policies

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in pwquality_violations], [v | some v in faillock_violations]),
	array.concat([v | some v in password_aging_violations], [v | some v in account_violations]),
)

has_key(obj, k) if {
	_ = obj[k]
}

# Missing evidence fails closed (conditional facts are required only when their feature is configured).
account_violations contains msg if {
	some k in ["default_umask", "pwquality_conf_raw", "common_password_raw"]
	not has_key(object.get(input, "pam", {}), k)
	msg := sprintf("CIS 5.x: evidence missing — pam.%s not collected", [k])
}

# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# non-comment, non-empty lines of a config text
conf_lines(raw) := [t |
	some l in split(raw, "\n")
	t := trim_space(l)
	t != ""
	not startswith(t, "#")
]

# last "key = value" assignment in a pwquality-style file (undefined when unset)
pwq_value(key) := v if {
	vals := [m[1] |
		some l in conf_lines(object.get(input.pam, "pwquality_conf_raw", ""))
		m := regex.find_all_string_submatch_n(sprintf(`^%s\s*=\s*(-?[0-9]+)\s*$`, [key]), l, 1)[0]
	]
	count(vals) > 0
	v := to_number(vals[count(vals) - 1])
}

# CIS 5.4.1: password creation requirements must be explicitly configured (pwquality)

# CIS 5.4.1.1: Minimum password length >= 14
pwquality_violations contains msg if {
	pwq_value("minlen") < 14
	msg := sprintf("CIS 5.4.1.1: Password minimum length is %v, should be at least 14", [pwq_value("minlen")])
}

pwquality_violations contains msg if {
	not pwq_value("minlen")
	msg := "CIS 5.4.1.1: Password minimum length (minlen) not configured in pwquality.conf"
}

# CIS 5.4.1.2: checked condition — password complexity (minclass or dcredit/ucredit/lcredit/ocredit)
pwquality_violations contains msg if {
	not pwq_value("minclass")
	not pwq_value("dcredit")
	msg := "CIS 5.4.1.2: Password complexity not configured (minclass or dcredit not set)"
}

# CIS 5.4.2: checked condition — lockout for failed password attempts
faillock_violations contains msg if {
	input.pam.faillock_configured == false
	msg := "CIS 5.4.2: pam_faillock (or pam_tally2) not configured for failed password lockout"
}

faillock_violations contains msg if {
	input.pam.faillock_configured == true
	is_number(input.pam.faillock_deny)
	input.pam.faillock_deny > 5
	msg := sprintf("CIS 5.4.2: Account lockout threshold is %d attempts, should be 5 or less", [input.pam.faillock_deny])
}

faillock_violations contains msg if {
	input.pam.faillock_configured == true
	not is_number(object.get(input, ["pam", "faillock_deny"], 0))
	msg := "CIS 5.4.2: evidence missing — pam.faillock_deny is not a number"
}

faillock_violations contains msg if {
	input.pam.faillock_configured == true
	is_number(input.pam.faillock_unlock_time)
	input.pam.faillock_unlock_time > 0
	input.pam.faillock_unlock_time < 900
	msg := sprintf("CIS 5.4.2: Account unlock time is %d seconds, should be 900 or more (or 0 for never)", [input.pam.faillock_unlock_time])
}

faillock_violations contains msg if {
	input.pam.faillock_configured == true
	not is_number(object.get(input, ["pam", "faillock_unlock_time"], 0))
	msg := "CIS 5.4.2: evidence missing — pam.faillock_unlock_time is not a number"
}

# CIS 5.4.3: password reuse must be limited to named principals
faillock_violations contains msg if {
	input.pam.remember_configured == false
	msg := "CIS 5.4.3: Password history (remember) not configured in PAM"
}

faillock_violations contains msg if {
	input.pam.remember_configured == true
	is_number(input.pam.remember_count)
	input.pam.remember_count < 5
	msg := sprintf("CIS 5.4.3: Password history remembers only %d passwords, should be 5 or more", [input.pam.remember_count])
}

faillock_violations contains msg if {
	input.pam.remember_configured == true
	not is_number(object.get(input, ["pam", "remember_count"], 0))
	msg := "CIS 5.4.3: evidence missing — pam.remember_count is not a number"
}

# CIS 5.4.4: password hashing algorithm must be SHA-512 or yescrypt
pwquality_violations contains msg if {
	not hash_ok
	msg := "CIS 5.4.4: Password hashing algorithm is not SHA-512 or yescrypt"
}

hash_ok if {
	some l in conf_lines(object.get(input.pam, "common_password_raw", ""))
	regex.match(`\bpam_unix\.so\b`, l)
	regex.match(`\b(sha512|yescrypt)\b`, l)
}

# CIS 5.5.1: checked condition — minimum days between password changes
password_aging_violations contains msg if {
	is_number(input.pam.pass_min_days)
	input.pam.pass_min_days < 1
	msg := sprintf("CIS 5.5.1: PASS_MIN_DAYS is %d, should be 1 or more", [input.pam.pass_min_days])
}

password_aging_violations contains msg if {
	not is_number(object.get(input, ["pam", "pass_min_days"], 0))
	msg := "CIS 5.5.1: evidence missing — pam.pass_min_days is not a number"
}

# CIS 5.5.2: password expiration must be 365 days or less
password_aging_violations contains msg if {
	is_number(input.pam.pass_max_days)
	input.pam.pass_max_days > 365
	msg := sprintf("CIS 5.5.2: PASS_MAX_DAYS is %d, should be 365 or less", [input.pam.pass_max_days])
}

password_aging_violations contains msg if {
	not is_number(object.get(input, ["pam", "pass_max_days"], 0))
	msg := "CIS 5.5.2: evidence missing — pam.pass_max_days is not a number"
}

# CIS 5.5.3: password expiration warning days must be 7 or more
password_aging_violations contains msg if {
	is_number(input.pam.pass_warn_age)
	input.pam.pass_warn_age < 7
	msg := sprintf("CIS 5.5.3: PASS_WARN_AGE is %d, should be 7 or more", [input.pam.pass_warn_age])
}

password_aging_violations contains msg if {
	not is_number(object.get(input, ["pam", "pass_warn_age"], 0))
	msg := "CIS 5.5.3: evidence missing — pam.pass_warn_age is not a number"
}

# CIS 5.5.4: inactive password lock must be 30 days or less
account_violations contains msg if {
	is_number(input.pam.inactive_days)
	input.pam.inactive_days > 30
	msg := sprintf("CIS 5.5.4: INACTIVE is %d days, should be 30 or less", [input.pam.inactive_days])
}

account_violations contains msg if {
	is_number(input.pam.inactive_days)
	input.pam.inactive_days < 0
	msg := "CIS 5.5.4: INACTIVE is not set (-1), inactive accounts will never be locked"
}

account_violations contains msg if {
	not is_number(object.get(input, ["pam", "inactive_days"], 0))
	msg := "CIS 5.5.4: evidence missing — pam.inactive_days is not a number"
}

# CIS 5.5.5: all users last password change date must be in the past
account_violations contains msg if {
	some user in input.pam.users_with_future_password_change
	msg := sprintf("CIS 5.5.5: User %s has a last password change date in the future", [user])
}

# CIS 5.6: system accounts must be secured
account_violations contains msg if {
	some user in input.pam.system_accounts_with_login_shell
	msg := sprintf("CIS 5.6: System account %s has an interactive login shell", [user])
}

# TMOUT for idle session timeout
account_violations contains msg if {
	input.pam.tmout_configured == false
	msg := "CIS 5.5.x: TMOUT is not configured for automatic session timeout"
}

account_violations contains msg if {
	input.pam.tmout_configured == true
	is_number(input.pam.tmout_value)
	input.pam.tmout_value > 900
	msg := sprintf("CIS 5.5.x: TMOUT is %d seconds, should be 900 or less", [input.pam.tmout_value])
}

account_violations contains msg if {
	input.pam.tmout_configured == true
	not is_number(object.get(input, ["pam", "tmout_value"], 0))
	msg := "CIS 5.5.x: evidence missing — pam.tmout_value is not a number"
}

# at least as restrictive as 027 (group write and all other bits masked)
umask_ok(u) if bits.and(octal(u), 23) == 23

# Default umask
account_violations contains msg if {
	u := input.pam.default_umask
	not umask_ok(u)
	msg := sprintf("CIS 5.5.x: Default umask is %v, should be 027 or more restrictive", [u])
}

# ---------------------------------------------------------------------------
# Evidence rule: a yes/no fact is answered only by a JSON boolean. A missing fact, null, a string
# ("true", "false", "no") or a number is an evidence problem: the control fails and the finding names it.
# ---------------------------------------------------------------------------
flag_problem(path) := "not collected" if is_null(object.get(input, path, null))

flag_problem(path) := sprintf("is not a boolean (got %s)", [type_name(v)]) if {
	v := object.get(input, path, null)
	not is_null(v)
	not is_boolean(v)
}

flag_evidence(prefix, path) := sprintf("%s: evidence missing — %s %s", [prefix, concat(".", path), flag_problem(path)])

# a number that must be collected: missing and null are "not collected" (a wrong type is reported by the rule that reads it)
number_missing(path) if is_null(object.get(input, path, null))

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags_faillock_violations := [
	["CIS 5.4.2", ["pam", "faillock_configured"]],
	["CIS 5.4.3", ["pam", "remember_configured"]],
]

faillock_violations contains msg if {
	some [prefix, path] in required_flags_faillock_violations
	msg := flag_evidence(prefix, path)
}

# yes/no facts read unconditionally: [finding prefix, input path]
required_flags_account_violations := [
	["CIS 5.5.x", ["pam", "tmout_configured"]],
]

account_violations contains msg if {
	some [prefix, path] in required_flags_account_violations
	msg := flag_evidence(prefix, path)
}

# Numbers that must be collected: a missing value is not a passing value.
required_numbers := {
	"pass_min_days": "5.5.1",
	"pass_max_days": "5.5.2",
	"pass_warn_age": "5.5.3",
}

account_violations contains msg if {
	some key, ctl in required_numbers
	number_missing(["pam", key])
	msg := sprintf("CIS %s: evidence missing — pam.%s not collected", [ctl, key])
}

account_violations contains msg if {
	number_missing(["pam", "inactive_days"])
	msg := "CIS 5.5.4: evidence missing — pam.inactive_days not collected"
}

# numbers read only when the feature they belong to is configured: [finding prefix, key, gate key]
gated_numbers := [
	["CIS 5.4.2", "faillock_deny", "faillock_configured"],
	["CIS 5.4.2", "faillock_unlock_time", "faillock_configured"],
	["CIS 5.4.3", "remember_count", "remember_configured"],
	["CIS 5.5.x", "tmout_value", "tmout_configured"],
]

gated_number_violations contains msg if {
	some [prefix, key, gate] in gated_numbers
	input.pam[gate] == true
	number_missing(["pam", key])
	msg := sprintf("%s: evidence missing — pam.%s not collected", [prefix, key])
}

faillock_violations contains msg if {
	some msg in gated_number_violations
	not startswith(msg, "CIS 5.5.x:")
}

account_violations contains msg if {
	some msg in gated_number_violations
	startswith(msg, "CIS 5.5.x:")
}

# offender lists: an empty list is an answer ("none found"), a missing list is not
required_lists := {
	"users_with_future_password_change": "5.5.5",
	"system_accounts_with_login_shell": "5.6",
}

account_violations contains msg if {
	some key, ctl in required_lists
	not is_array(object.get(input, ["pam", key], null))
	msg := sprintf("CIS %s: evidence missing — pam.%s not collected", [ctl, key])
}

report := {
	"compliant": compliant,
	"total_violations": count(violations),
	"violations": violations,
	"pwquality_violations": count(pwquality_violations),
	"faillock_violations": count(faillock_violations),
	"password_aging_violations": count(password_aging_violations),
	"account_violations": count(account_violations),
	"controls_checked": 17,
	"section": "5.4-5.5 PAM and Password Policies",
	"benchmark": "DERIVED from CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0 (applied to Debian 11)",
}
