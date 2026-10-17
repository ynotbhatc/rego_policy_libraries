# METADATA
# title: "CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Sections 5.4-5.5: PAM and Password Policies"
# custom:
#   class: security
#   framework: cis_ubuntu_22_04
#   source: cis
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 21
#     cited: 13
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: report
#     guard: self
#     as_of: v2.4.2
package cis_ubuntu_22_04.pam

# CIS Ubuntu 22.04 LTS Benchmark v3.0.0 - Sections 5.4-5.5: PAM and Password Policies

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in pwquality_violations], [v | some v in faillock_violations]),
	array.concat([v | some v in password_aging_violations], [v | some v in account_violations]),
)

# CIS 5.4.1: Ensure password creation requirements are configured (pwquality)

# Config text: only non-comment lines count. A commented default ("# minlen = 8") is not configuration.
# libpwquality reads the file in order and the last assignment wins.
pwquality_lines := [trim_space(l) |
	some l in split(input.pam.pwquality_conf_raw, "\n")
	trim_space(l) != ""
	not startswith(trim_space(l), "#")
]

pwquality_value(key) := v if {
	vals := [trim_space(m[1]) |
		some l in pwquality_lines
		m := regex.find_all_string_submatch_n(sprintf(`^%s\s*=\s*(\S+)`, [key]), l, 1)[0]
	]
	count(vals) > 0
	v := vals[count(vals) - 1]
}

# CIS 5.4.1.1: Minimum password length >= 14
minlen_ok if to_number(pwquality_value("minlen")) >= 14

pwquality_violations contains msg if {
	minlen := pwquality_value("minlen")
	not minlen_ok
	msg := sprintf("CIS 5.4.1.1: Password minimum length is %s, should be at least 14", [minlen])
}

minlen_configured if pwquality_value("minlen")

pwquality_violations contains msg if {
	not minlen_configured
	msg := "CIS 5.4.1.1: Password minimum length (minlen) not configured in pwquality.conf"
}

# CIS 5.4.1.2: Ensure password complexity (minclass or dcredit/ucredit/lcredit/ocredit)
complexity_configured if {
	some key in ["minclass", "dcredit", "ucredit", "lcredit", "ocredit"]
	pwquality_value(key)
}

pwquality_violations contains msg if {
	not complexity_configured
	msg := "CIS 5.4.1.2: Password complexity not configured (minclass or dcredit not set)"
}

# CIS 5.4.2: Ensure lockout for failed password attempts
faillock_violations contains msg if {
	not input.pam.faillock_configured
	msg := "CIS 5.4.2: pam_faillock (or pam_tally2) not configured for failed password lockout"
}

faillock_violations contains msg if {
	input.pam.faillock_configured
	input.pam.faillock_deny > 5
	msg := sprintf("CIS 5.4.2: Account lockout threshold is %d attempts, should be 5 or less", [input.pam.faillock_deny])
}

faillock_violations contains msg if {
	input.pam.faillock_configured
	input.pam.faillock_unlock_time > 0
	input.pam.faillock_unlock_time < 900
	msg := sprintf("CIS 5.4.2: Account unlock time is %d seconds, should be 900 or more (or 0 for never)", [input.pam.faillock_unlock_time])
}

# CIS 5.4.3: Ensure password reuse is limited
faillock_violations contains msg if {
	not input.pam.remember_configured
	msg := "CIS 5.4.3: Password history (remember) not configured in PAM"
}

faillock_violations contains msg if {
	input.pam.remember_configured
	input.pam.remember_count < 5
	msg := sprintf("CIS 5.4.3: Password history remembers only %d passwords, should be 5 or more", [input.pam.remember_count])
}

# CIS 5.4.4: Ensure password hashing algorithm is SHA-512 or yescrypt
# a non-comment pam_unix line must name sha512 or yescrypt (as a whole word)
strong_hash if {
	some l in split(input.pam.common_password_raw, "\n")
	not startswith(trim_space(l), "#")
	contains(l, "pam_unix")
	regex.match(`(^|[\s=])(sha512|yescrypt)($|[\s])`, l)
}

pwquality_violations contains msg if {
	not strong_hash
	msg := "CIS 5.4.4: Password hashing algorithm is not SHA-512 or yescrypt"
}

# CIS 5.5.1: Ensure minimum days between password changes
password_aging_violations contains msg if {
	input.pam.pass_min_days < 1
	msg := sprintf("CIS 5.5.1: PASS_MIN_DAYS is %d, should be 1 or more", [input.pam.pass_min_days])
}

# CIS 5.5.2: Ensure password expiration is 365 days or less
password_aging_violations contains msg if {
	input.pam.pass_max_days > 365
	msg := sprintf("CIS 5.5.2: PASS_MAX_DAYS is %d, should be 365 or less", [input.pam.pass_max_days])
}

# CIS 5.5.3: Ensure password expiration warning days is 7 or more
password_aging_violations contains msg if {
	input.pam.pass_warn_age < 7
	msg := sprintf("CIS 5.5.3: PASS_WARN_AGE is %d, should be 7 or more", [input.pam.pass_warn_age])
}

# CIS 5.5.4: Ensure inactive password lock is 30 days or less
account_violations contains msg if {
	input.pam.inactive_days > 30
	msg := sprintf("CIS 5.5.4: INACTIVE is %d days, should be 30 or less", [input.pam.inactive_days])
}

account_violations contains msg if {
	input.pam.inactive_days < 0
	msg := "CIS 5.5.4: INACTIVE is not set (-1), inactive accounts will never be locked"
}

# CIS 5.5.5: Ensure all users last password change date is in the past
account_violations contains msg if {
	some user in input.pam.users_with_future_password_change
	msg := sprintf("CIS 5.5.5: User %s has a last password change date in the future", [user])
}

# CIS 5.6: Ensure system accounts are secured
account_violations contains msg if {
	some user in input.pam.system_accounts_with_login_shell
	msg := sprintf("CIS 5.6: System account %s has an interactive login shell", [user])
}

# TMOUT for idle session timeout
account_violations contains msg if {
	not input.pam.tmout_configured
	msg := "CIS 5.5.x: TMOUT is not configured for automatic session timeout"
}

account_violations contains msg if {
	input.pam.tmout_configured
	input.pam.tmout_value > 900
	msg := sprintf("CIS 5.5.x: TMOUT is %d seconds, should be 900 or less", [input.pam.tmout_value])
}

# Default umask
# "027 or more restrictive" in octal: group write (020), other r/w/x (007) must be masked
# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.
octal(s) := n if {
	t := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(d) | some d in split(p, "")]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode grants nothing beyond max (both octal strings)
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

umask_ok if bits.and(octal(input.pam.default_umask), 23) == 23

account_violations contains msg if {
	not umask_ok
	msg := sprintf("CIS 5.5.x: Default umask is %v, should be 027 or more restrictive (or not collected)", [object.get(input, ["pam", "default_umask"], "<missing>")])
}

# Evidence: numeric facts must have been collected; an absent number never satisfies a limit.
num_known(key) if is_number(input.pam[key])

account_violations contains msg if {
	some key, ctl in {"pass_min_days": "5.5.1", "pass_max_days": "5.5.2", "pass_warn_age": "5.5.3", "inactive_days": "5.5.4"}
	not num_known(key)
	msg := sprintf("CIS %s: evidence missing — pam.%s not collected", [ctl, key])
}

account_violations contains msg if {
	some key, flag in {"faillock_deny": "faillock_configured", "faillock_unlock_time": "faillock_configured", "remember_count": "remember_configured", "tmout_value": "tmout_configured"}
	input.pam[flag]
	not num_known(key)
	msg := sprintf("CIS 5.4/5.5: evidence missing — pam.%s not collected", [key])
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
	"benchmark": "CIS Ubuntu 22.04 v3.0.0",
}
