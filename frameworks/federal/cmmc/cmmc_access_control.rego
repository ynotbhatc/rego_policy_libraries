# METADATA
# title: "CMMC 2.0 — Access Control Domain (AC)"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 39
#     cited: 19
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package cmmc.access_control

import rego.v1

# =============================================================================
# CMMC — Access Control Domain (AC), NIST SP 800-171 Rev 2 family 3.1 (22 requirements)
#
# Ids (32 CFR 170.14(c)(1)): Level 2 practices are AC.L2-3.1.1 ... AC.L2-3.1.22.
# Four of them carry a Level 1 safeguard of FAR 52.204-21(b)(1):
#   AC.L1-b.1.i = 3.1.1, AC.L1-b.1.ii = 3.1.2, AC.L1-b.1.iii = 3.1.20, AC.L1-b.1.iv = 3.1.22.
# Every finding starts with the 800-171 R2 number it decides (data.cmmc scores
# it under the practice id of the assessed level).
#
# Fail-closed: an inventory that a practice iterates (users, cui_systems) must be
# a non-empty array, and every item must carry the facts the check reads;
# otherwise the practice gets an "evidence missing" finding.
#
# Input shape:
#   input.users[]               - user accounts {username, authorized, system_access,
#                                 privileged, privilege_justified, non_privileged_account_for_regular_use}
#   input.access_controls       - access control configuration (booleans)
#   input.session               - session management {lock_timeout_minutes, automatic_termination}
#   input.cui_systems[]         - in-scope systems {name, publicly_accessible, cui_posting_controls}
#   input.cmmc_level            - assessed level (1, 2 or 3)
# =============================================================================

# ---------------------------------------------------------------------------
# Inventories
# ---------------------------------------------------------------------------

_users := u if {
	u := input.users
	is_array(u)
	count(u) > 0
}

_systems := s if {
	s := input.cui_systems
	is_array(s)
	count(s) > 0
}

_name(x, key) := object.get(x, key, "<unnamed>") if is_object(x)

else := "<not an object>"

_has_bool(x, key) if is_boolean(object.get(x, key, null))

# ---------------------------------------------------------------------------
# Level 1 safeguards (decided at every level)
# ---------------------------------------------------------------------------

# 3.1.1 (AC.L1-b.1.i / AC.L2-3.1.1) — limit system access to authorized users
violation_l1_ac_1_1 contains "CMMC AC.L1-b.1.i / AC.L2-3.1.1: evidence missing - input.users not collected (absent, not an array or empty); access cannot be shown limited to authorized users" if {
	not _users
}

violation_l1_ac_1_1 contains msg if {
	some user in _users
	not _has_bool(user, "authorized")
	msg := sprintf("CMMC AC.L1-b.1.i / AC.L2-3.1.1: evidence missing - user '%v' has no boolean 'authorized'", [_name(user, "username")])
}

violation_l1_ac_1_1 contains msg if {
	some user in _users
	not _has_bool(user, "system_access")
	msg := sprintf("CMMC AC.L1-b.1.i / AC.L2-3.1.1: evidence missing - user '%v' has no boolean 'system_access'", [_name(user, "username")])
}

violation_l1_ac_1_1 contains msg if {
	some user in _users
	user.authorized == false
	user.system_access == true
	msg := sprintf(
		"CMMC AC.L1-b.1.i / AC.L2-3.1.1: Unauthorized user '%v' has system access. Access must be limited to authorized users only.",
		[user.username],
	)
}

# 3.1.2 (AC.L1-b.1.ii / AC.L2-3.1.2) — limit access to permitted transactions and functions
violation_l1_ac_1_2 contains msg if {
	not input.access_controls.least_privilege_enforced == true
	msg := "CMMC AC.L1-b.1.ii / AC.L2-3.1.2: Access is not shown limited to the transactions and functions authorized users are permitted to execute (input.access_controls.least_privilege_enforced is not true)."
}

# 3.1.20 (AC.L1-b.1.iii / AC.L2-3.1.20) — verify and control/limit connections to external systems
violation_l1_ac_1_20 contains msg if {
	not input.access_controls.external_connections_controlled == true
	msg := "CMMC AC.L1-b.1.iii / AC.L2-3.1.20: External system connections are not shown verified and controlled (input.access_controls.external_connections_controlled is not true)."
}

# 3.1.22 (AC.L1-b.1.iv / AC.L2-3.1.22) — control information posted on publicly accessible systems
violation_l1_ac_1_22 contains "CMMC AC.L1-b.1.iv / AC.L2-3.1.22: evidence missing - input.cui_systems not collected (absent, not an array or empty); publicly accessible systems cannot be identified" if {
	not _systems
}

violation_l1_ac_1_22 contains msg if {
	some system in _systems
	not _has_bool(system, "publicly_accessible")
	msg := sprintf("CMMC AC.L1-b.1.iv / AC.L2-3.1.22: evidence missing - system '%v' has no boolean 'publicly_accessible'", [_name(system, "name")])
}

violation_l1_ac_1_22 contains msg if {
	some system in _systems
	system.publicly_accessible == true
	not system.cui_posting_controls == true
	msg := sprintf(
		"CMMC AC.L1-b.1.iv / AC.L2-3.1.22: System '%v' is publicly accessible without controls on the information posted or processed on it.",
		[system.name],
	)
}

# ---------------------------------------------------------------------------
# Level 2 practices (NIST SP 800-171 R2), decided when cmmc_level >= 2
# ---------------------------------------------------------------------------

# AC.L2-3.1.3 — Control the flow of CUI
violation_l2_ac_1_3 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.cui_flow_controls
	msg := "CMMC AC.L2-3.1.3: No CUI information flow controls implemented. Data flow enforcement is required at Level 2."
}

# AC.L2-3.1.4 — Separate duties of individuals to reduce risk of malevolent activity
violation_l2_ac_1_4 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.separation_of_duties
	msg := "CMMC AC.L2-3.1.4: Separation of duties is not implemented. No single user should be able to complete a high-risk action alone."
}

# AC.L2-3.1.5 / 3.1.6 iterate the user inventory
violation_l2_ac_1_5 contains "CMMC AC.L2-3.1.5: evidence missing - input.users not collected (absent, not an array or empty); privileged accounts cannot be reviewed" if {
	input.cmmc_level >= 2
	not _users
}

violation_l2_ac_1_5 contains msg if {
	input.cmmc_level >= 2
	some user in _users
	not _has_bool(user, "privileged")
	msg := sprintf("CMMC AC.L2-3.1.5: evidence missing - user '%v' has no boolean 'privileged'", [_name(user, "username")])
}

# AC.L2-3.1.5 — Employ least privilege
violation_l2_ac_1_5 contains msg if {
	input.cmmc_level >= 2
	some user in _users
	user.privileged == true
	not user.privilege_justified
	msg := sprintf(
		"CMMC AC.L2-3.1.5: Privileged user '%v' has no documented justification. Least privilege must be enforced with documented need.",
		[user.username],
	)
}

violation_l2_ac_1_6 contains "CMMC AC.L2-3.1.6: evidence missing - input.users not collected (absent, not an array or empty); use of non-privileged accounts cannot be shown" if {
	input.cmmc_level >= 2
	not _users
}

violation_l2_ac_1_6 contains msg if {
	input.cmmc_level >= 2
	some user in _users
	not _has_bool(user, "privileged")
	msg := sprintf("CMMC AC.L2-3.1.6: evidence missing - user '%v' has no boolean 'privileged'", [_name(user, "username")])
}

# AC.L2-3.1.6 — Use non-privileged accounts for non-privileged actions
violation_l2_ac_1_6 contains msg if {
	input.cmmc_level >= 2
	some user in _users
	user.privileged == true
	not user.non_privileged_account_for_regular_use
	msg := sprintf(
		"CMMC AC.L2-3.1.6: Privileged user '%v' does not have a separate non-privileged account for routine tasks.",
		[user.username],
	)
}

# AC.L2-3.1.7 — Prevent non-privileged users from executing privileged functions
violation_l2_ac_1_7 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.privileged_function_auditing
	msg := "CMMC AC.L2-3.1.7: Privileged function execution is not audited. All privileged function use must be logged."
}

# AC.L2-3.1.8 — Limit unsuccessful logon attempts
violation_l2_ac_1_8 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.unsuccessful_logon_attempts_limited == true
	msg := "CMMC AC.L2-3.1.8: Unsuccessful logon attempts are not shown limited (input.access_controls.unsuccessful_logon_attempts_limited is not true)."
}

# AC.L2-3.1.9 — Provide privacy and security notices consistent with applicable CUI rules
violation_l2_ac_1_9 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.privacy_security_notices_displayed == true
	msg := "CMMC AC.L2-3.1.9: Privacy and security notices are not shown displayed (input.access_controls.privacy_security_notices_displayed is not true)."
}

# AC.L2-3.1.10 — Use session lock
# The inactivity period is kept at 15 minutes as before (see the module notes); a
# missing value is a finding, not a pass.
violation_l2_ac_1_10 contains msg if {
	input.cmmc_level >= 2
	not is_number(object.get(input, ["session", "lock_timeout_minutes"], null))
	msg := "CMMC AC.L2-3.1.10: evidence missing - input.session.lock_timeout_minutes not collected (not a number); session lock cannot be shown."
}

violation_l2_ac_1_10 contains msg if {
	input.cmmc_level >= 2
	input.session.lock_timeout_minutes > 15
	msg := sprintf(
		"CMMC AC.L2-3.1.10: Session lock timeout is %v minutes. Maximum 15 minutes of inactivity before lock is required.",
		[input.session.lock_timeout_minutes],
	)
}

# AC.L2-3.1.11 — Terminate sessions after defined period
violation_l2_ac_1_11 contains msg if {
	input.cmmc_level >= 2
	not input.session.automatic_termination
	msg := "CMMC AC.L2-3.1.11: Sessions are not automatically terminated after inactivity. Implement session termination for CUI access."
}

# AC.L2-3.1.12 — Monitor and control remote access sessions
violation_l2_ac_1_12 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.remote_access_monitored
	msg := "CMMC AC.L2-3.1.12: Remote access sessions are not monitored. All remote access to CUI systems must be monitored."
}

# AC.L2-3.1.13 — Use cryptographic mechanisms for remote access
violation_l2_ac_1_13 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.remote_access_encrypted
	msg := "CMMC AC.L2-3.1.13: Remote access does not use cryptographic mechanisms. VPN or equivalent encryption is required."
}

# AC.L2-3.1.14 — Route remote access via managed access control points
violation_l2_ac_1_14 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.remote_access_via_managed_points
	msg := "CMMC AC.L2-3.1.14: Remote access is not routed through managed access control points (e.g., jump servers, VPN gateways)."
}

# AC.L2-3.1.15 — Authorize remote execution of privileged commands
violation_l2_ac_1_15 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.remote_privileged_commands_controlled
	msg := "CMMC AC.L2-3.1.15: Remote execution of privileged commands is not controlled. Explicit authorization is required."
}

# Wireless and mobile practices apply only when the capability exists; whether
# it exists must be stated (a missing flag is not "no wireless").
violation_l2_ac_1_16 contains msg if {
	input.cmmc_level >= 2
	not is_boolean(object.get(input, ["access_controls", "wireless_access_enabled"], null))
	msg := "CMMC AC.L2-3.1.16: evidence missing - input.access_controls.wireless_access_enabled not collected (not a boolean); wireless authorization cannot be decided."
}

# AC.L2-3.1.16 — Authorize wireless access prior to allowing such connections
violation_l2_ac_1_16 contains msg if {
	input.cmmc_level >= 2
	input.access_controls.wireless_access_enabled == true
	not input.access_controls.wireless_access_authorized == true
	msg := "CMMC AC.L2-3.1.16: Wireless access is not shown authorized before connections are allowed (input.access_controls.wireless_access_authorized is not true)."
}

violation_l2_ac_1_17 contains msg if {
	input.cmmc_level >= 2
	not is_boolean(object.get(input, ["access_controls", "wireless_access_enabled"], null))
	msg := "CMMC AC.L2-3.1.17: evidence missing - input.access_controls.wireless_access_enabled not collected (not a boolean); wireless protection cannot be decided."
}

# AC.L2-3.1.17 — Protect wireless access using authentication/encryption
violation_l2_ac_1_17 contains msg if {
	input.cmmc_level >= 2
	input.access_controls.wireless_access_enabled == true
	not input.access_controls.wireless_access_encrypted
	msg := "CMMC AC.L2-3.1.17: Wireless access to CUI systems is not encrypted. WPA3 or equivalent is required."
}

# AC.L2-3.1.18 — Control connection of mobile devices
violation_l2_ac_1_18 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.mobile_device_policy
	msg := "CMMC AC.L2-3.1.18: No mobile device policy for CUI access. Mobile devices connecting to CUI systems must be managed."
}

violation_l2_ac_1_19 contains msg if {
	input.cmmc_level >= 2
	not is_boolean(object.get(input, ["access_controls", "mobile_device_cui_access"], null))
	msg := "CMMC AC.L2-3.1.19: evidence missing - input.access_controls.mobile_device_cui_access not collected (not a boolean); mobile-device encryption cannot be decided."
}

# AC.L2-3.1.19 — Encrypt CUI on mobile devices
violation_l2_ac_1_19 contains msg if {
	input.cmmc_level >= 2
	input.access_controls.mobile_device_cui_access == true
	not input.access_controls.mobile_device_encryption
	msg := "CMMC AC.L2-3.1.19: Mobile devices accessing CUI do not enforce encryption. Full-device encryption is required."
}

# AC.L2-3.1.21 — Limit use of portable storage devices on external systems
violation_l2_ac_1_21 contains msg if {
	input.cmmc_level >= 2
	not input.access_controls.portable_storage_external_use_limited == true
	msg := "CMMC AC.L2-3.1.21: Use of portable storage devices on external systems is not shown limited (input.access_controls.portable_storage_external_use_limited is not true)."
}

# ---------------------------------------------------------------------------
# Aggregate violations by level
# ---------------------------------------------------------------------------

_by_practice := {
	"3.1.1": violation_l1_ac_1_1, "3.1.2": violation_l1_ac_1_2, "3.1.3": violation_l2_ac_1_3,
	"3.1.4": violation_l2_ac_1_4, "3.1.5": violation_l2_ac_1_5, "3.1.6": violation_l2_ac_1_6,
	"3.1.7": violation_l2_ac_1_7, "3.1.8": violation_l2_ac_1_8, "3.1.9": violation_l2_ac_1_9,
	"3.1.10": violation_l2_ac_1_10, "3.1.11": violation_l2_ac_1_11, "3.1.12": violation_l2_ac_1_12,
	"3.1.13": violation_l2_ac_1_13, "3.1.14": violation_l2_ac_1_14, "3.1.15": violation_l2_ac_1_15,
	"3.1.16": violation_l2_ac_1_16, "3.1.17": violation_l2_ac_1_17, "3.1.18": violation_l2_ac_1_18,
	"3.1.19": violation_l2_ac_1_19, "3.1.20": violation_l1_ac_1_20, "3.1.21": violation_l2_ac_1_21,
	"3.1.22": violation_l1_ac_1_22,
}

_level_1_ids := {"3.1.1", "3.1.2", "3.1.20", "3.1.22"}

level_1_violations contains msg if {
	some id in _level_1_ids
	some msg in _by_practice[id]
}

level_2_violations contains msg if {
	some id, vs in _by_practice
	not id in _level_1_ids
	some msg in vs
}

violations contains msg if some msg in level_1_violations

violations contains msg if {
	input.cmmc_level >= 2
	some msg in level_2_violations
}

# Input contract: every Level 2 rule is gated on input.cmmc_level >= 2, so a
# missing level would silently evaluate the Level 1 safeguards only. This
# finding names no practice (data.cmmc reports the missing level itself).
violations contains "CMMC AC input contract: FAIL-CLOSED - input.cmmc_level was not supplied; the Level 2 access-control practices were not evaluated and the domain is reported non-compliant" if {
	not input.cmmc_level
}

default compliant := false

compliant if count(violations) == 0

# Per-practice verdicts (a practice with any finding fails; Level 2 practices are
# decided only when the level is at least 2).
practices := [{"id": id, "level": _lvl(id), "compliant": _practice_ok(id)} |
	some id in _order
]

_order := [
	"3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7", "3.1.8", "3.1.9", "3.1.10", "3.1.11",
	"3.1.12", "3.1.13", "3.1.14", "3.1.15", "3.1.16", "3.1.17", "3.1.18", "3.1.19", "3.1.20", "3.1.21", "3.1.22",
]

_lvl(id) := 1 if id in _level_1_ids

else := 2

_practice_ok(id) if {
	_decided(id)
	count(_by_practice[id]) == 0
}

else := false

_decided(id) if id in _level_1_ids

_decided(_) if input.cmmc_level >= 2

failing_practices := {p.id | some p in practices; p.compliant == false}

compliance_report := {
	"domain": "Access Control (AC)",
	"cmmc_level": object.get(input, "cmmc_level", 0),
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"practices": practices,
	"total_practices": count(practices),
	"level_1_passing": count(level_1_violations) == 0,
	"level_2_passing": count(level_2_violations) == 0,
	"passing": count(practices) - count(failing_practices),
}
