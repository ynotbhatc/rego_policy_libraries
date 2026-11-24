# METADATA
# title: "HIPAA Security Rule — 45 CFR 164.312(a)"
# custom:
#   class: compliance
#   framework: hipaa
#   source: hhs
#   domains: [privacy, healthcare]
#   coverage:
#     checks: 25
#     cited: 11
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package hipaa.access_control

import rego.v1

# =============================================================================
# HIPAA Security Rule — 45 CFR 164.312(a)
# Technical Safeguard: Access Control
#
# Implementation specifications (marking as printed in 45 CFR 164.312(a)(2), eCFR current text checked
# 2026-11-17):
#   164.312(a)(2)(i)  - Unique User Identification (R)
#   164.312(a)(2)(ii) - Emergency Access Procedure (R)
#   164.312(a)(2)(iii)- Automatic Logoff (A)
#   164.312(a)(2)(iv) - Encryption and Decryption (A)
#
# Addressable specifications (45 CFR 164.306(d)(3)): the entity either implements the specification, or
# documents why it is not reasonable and appropriate AND implements an equivalent alternative measure (or
# documents why no alternative is reasonable and appropriate). The second path is read from
#   input.hipaa.addressable_decisions["164.312(a)(2)(iii)" | "164.312(a)(2)(iv)"] = {
#     "not_reasonable_and_appropriate_documented": true,
#     "equivalent_alternative_implemented": true   OR   "no_reasonable_alternative_documented": true }
# When that decision is evidenced, the findings cited to that paragraph are not violations (they are listed
# under addressed_by_alternative). When neither path is evidenced, the findings stand (fail closed).
#
# Advisories: library-chosen periods the regulation does not contain (key rotation every 365 days, a
# 15-minute logoff ceiling, 90-day emergency-account and ePHI-access review cadences) are reported in
# `advisories`. They are not cited to 45 CFR and do not affect `compliant`.
#
# Input shape:
#   input.users[]               - user accounts on the system
#   input.access_controls       - access control configuration
#   input.session               - session management settings
#   input.encryption            - encryption/decryption capabilities
#   input.phi_systems[]         - systems storing ePHI
#   input.hipaa.addressable_decisions - documented 164.306(d)(3) decisions for addressable specifications
# =============================================================================

_addressable_ids := {"164.312(a)(2)(iii)", "164.312(a)(2)(iv)"}

_decision(id) := d if {
	d := object.get(input, ["hipaa", "addressable_decisions", id], null)
	is_object(d)
}

# 164.306(d)(3)(ii)(B): (1) documented why not reasonable and appropriate, and (2) an equivalent alternative
# implemented, or documented that none is reasonable and appropriate.
_alternative_documented(id) if {
	id in _addressable_ids
	d := _decision(id)
	d.not_reasonable_and_appropriate_documented == true
	_alternative_or_none(d)
}

_alternative_or_none(d) if d.equivalent_alternative_implemented == true

_alternative_or_none(d) if d.no_reasonable_alternative_documented == true

# ---------------------------------------------------------------------------
# 164.312(a)(2)(i) — Unique User Identification (Required)
# Assign a unique name/number for identifying and tracking user identity
# ---------------------------------------------------------------------------

violation_unique_user_id contains msg if {
	some user in input.users
	user.shared_account == true
	msg := sprintf(
		"HIPAA 164.312(a)(2)(i): User account '%v' is a shared account. Each user must have a unique identifier.",
		[user.username],
	)
}

violation_unique_user_id contains msg if {
	some user in input.users
	not _nonempty_string(object.get(user, "username", null))
	msg := "HIPAA 164.312(a)(2)(i): User account found with no username — unique identification required."
}

_nonempty_string(x) if {
	is_string(x)
	trim_space(x) != ""
}

# The account list is the evidence for unique user identification: without it the control cannot be shown.
violation_unique_user_id contains msg if {
	count(_users) == 0
	msg := "HIPAA 164.312(a)(2)(i): evidence missing — input.users not collected (or empty). Unique user identification cannot be verified without the account list."
}

# Whether an account is shared is a yes/no the collector states for every account; an absent answer is not "no".
violation_unique_user_id contains msg if {
	some i, user in _users
	is_object(user)
	not "shared_account" in object.keys(user)
	msg := sprintf(
		"HIPAA 164.312(a)(2)(i): evidence missing — input.users[%d].shared_account not collected for account '%v'.",
		[i, object.get(user, "username", "unknown")],
	)
}

_users := us if {
	us := object.get(input, "users", null)
	is_array(us)
} else := []

advisories contains msg if {
	generic_accounts := [u | some u in input.users; u.username in {"admin", "administrator", "root", "guest", "test", "demo", "shared"}; not u.phi_access_disabled == true]
	count(generic_accounts) > 0
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): Generic/shared accounts with potential ePHI access detected: %v. Disable or restrict these accounts.",
		[[u.username | some u in generic_accounts]],
	)
}

default control_a2i_compliant := false

default control_a2ii_compliant := false

default control_a2iii_compliant := false

default control_a2iv_compliant := false

control_a2i_compliant if {
	count(violation_unique_user_id) == 0
}

# ---------------------------------------------------------------------------
# 164.312(a)(2)(ii) — Emergency Access Procedure (Required)
# Obtain necessary ePHI during an emergency
# ---------------------------------------------------------------------------

violation_emergency_access contains msg if {
	not input.access_controls.emergency_access_procedure_documented == true
	msg := "HIPAA 164.312(a)(2)(ii): No documented emergency access procedure found. An emergency access procedure for ePHI must be documented and implemented."
}

advisories contains msg if {
	not input.access_controls.emergency_access_tested == true
	msg := "Advisory (library practice, not a 45 CFR requirement): Emergency access procedure has not been tested. Procedures must be regularly tested to ensure operability."
}

advisories contains msg if {
	is_number(input.access_controls.emergency_accounts_reviewed_days)
	input.access_controls.emergency_accounts_reviewed_days > 90
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): emergency access accounts have not been reviewed in %v days (library practice: 90 days).",
		[input.access_controls.emergency_accounts_reviewed_days],
	)
}

advisories contains msg if {
	not is_number(object.get(input, ["access_controls", "emergency_accounts_reviewed_days"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): access_controls.emergency_accounts_reviewed_days not collected; emergency account review cadence not reported."
}

control_a2ii_compliant if {
	count(violation_emergency_access) == 0
}

# ---------------------------------------------------------------------------
# 164.312(a)(2)(iii) — Automatic Logoff (Addressable)
# Terminate electronic session after predetermined time of inactivity
# ---------------------------------------------------------------------------

violation_automatic_logoff contains msg if {
	not input.session.automatic_logoff_enabled == true
	msg := "HIPAA 164.312(a)(2)(iii): Automatic logoff is not enabled. Sessions must terminate after inactivity."
}

# The regulation requires a "predetermined time of inactivity" and sets no value: a positive number of
# minutes is the evidence. Longer than 15 minutes is a library advisory only.
advisories contains msg if {
	input.session.automatic_logoff_enabled == true
	is_number(input.session.inactivity_timeout_minutes)
	input.session.inactivity_timeout_minutes > 15
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): automatic logoff timeout is %v minutes; the library suggests at most 15 minutes for systems with ePHI access.",
		[input.session.inactivity_timeout_minutes],
	)
}

violation_automatic_logoff contains msg if {
	input.session.automatic_logoff_enabled == true
	not _positive_number(object.get(input, ["session", "inactivity_timeout_minutes"], null))
	msg := "HIPAA 164.312(a)(2)(iii): evidence missing — session.inactivity_timeout_minutes not collected (or not a positive number). The predetermined inactivity time cannot be verified."
}

_positive_number(x) if {
	is_number(x)
	x > 0
}

advisories contains msg if {
	object.get(input, ["session", "screen_lock_enabled"], false) != true
	msg := "Advisory (library practice, not a 45 CFR requirement): Screen lock is not enabled or evidence missing (session.screen_lock_enabled not collected). Unattended workstations accessing ePHI must lock automatically."
}

control_a2iii_compliant if {
	count(violation_automatic_logoff) == 0
}

control_a2iii_compliant if _alternative_documented("164.312(a)(2)(iii)")

# ---------------------------------------------------------------------------
# 164.312(a)(2)(iv) — Encryption and Decryption (Addressable)
# Implement a mechanism to encrypt and decrypt ePHI
# ---------------------------------------------------------------------------

violation_encryption contains msg if {
	some phi_system in input.phi_systems
	not phi_system.data_at_rest_encrypted == true
	msg := sprintf(
		"HIPAA 164.312(a)(2)(iv): System '%v' stores ePHI but data-at-rest encryption is not enabled.",
		[phi_system.name],
	)
}

advisories contains msg if {
	some phi_system in input.phi_systems
	phi_system.data_at_rest_encrypted == true
	phi_system.encryption_algorithm in {"DES", "3DES", "RC4", "RC2", "MD5"}
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): System '%v' uses deprecated encryption algorithm '%v'. Use AES-256 or equivalent.",
		[phi_system.name, phi_system.encryption_algorithm],
	)
}

advisories contains msg if {
	not input.encryption.key_management_policy_documented == true
	msg := "Advisory (library practice, not a 45 CFR requirement): No documented encryption key management policy. Key management procedures must be documented."
}

# Key rotation: 45 CFR 164.312(a)(2)(iv) sets no rotation period. Kept as a library advisory, not cited to
# the regulation and not part of `compliant` (audit 2026-11-17, finding 6).
advisories contains msg if {
	is_number(input.encryption.key_rotation_days)
	input.encryption.key_rotation_days > 365
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): encryption keys have not been rotated in %v days; the library suggests annual rotation.",
		[input.encryption.key_rotation_days],
	)
}

advisories contains msg if {
	not is_number(object.get(input, ["encryption", "key_rotation_days"], null))
	msg := "Advisory (library practice, not a 45 CFR requirement): encryption.key_rotation_days not collected; key rotation cadence not reported."
}

control_a2iv_compliant if {
	count(violation_encryption) == 0
}

control_a2iv_compliant if _alternative_documented("164.312(a)(2)(iv)")

# ---------------------------------------------------------------------------
# Role-Based Access Control (RBAC) for ePHI
# ---------------------------------------------------------------------------

# 164.312(a)(1) requires access only for persons or programs granted access rights; role-based access is one
# way to show it, and a direct statement that access is restricted to granted rights is the other.
_access_restricted if input.access_controls.role_based_access_implemented == true

_access_restricted if input.access_controls.access_restricted_to_granted_rights == true

violation_rbac contains msg if {
	not _access_restricted
	msg := "HIPAA 164.312(a)(1): access to ePHI is not shown to be limited to persons or software programs granted access rights (access_controls.role_based_access_implemented or access_controls.access_restricted_to_granted_rights not true)."
}

advisories contains msg if {
	some user in input.users
	user.phi_access == true
	not user.phi_access_justified == true
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): User '%v' has ePHI access with no documented business justification.",
		[user.username],
	)
}

advisories contains msg if {
	some user in input.users
	user.phi_access == true
	is_number(user.last_access_review_days)
	user.last_access_review_days > 90
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): user '%v' ePHI access has not been reviewed in %v days (library practice: 90 days).",
		[user.username, user.last_access_review_days],
	)
}

advisories contains msg if {
	some user in input.users
	user.phi_access == true
	not is_number(object.get(user, "last_access_review_days", null))
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): last_access_review_days not collected for ePHI user '%v'.",
		[object.get(user, "username", "unknown")],
	)
}

# ---------------------------------------------------------------------------
# Minimum Necessary Access
# ---------------------------------------------------------------------------

advisories contains msg if {
	some user in input.users
	user.phi_access_level == "full"
	not user.minimum_necessary_justified == true
	msg := sprintf(
		"Advisory (library practice, not a 45 CFR requirement): User '%v' has full ePHI access. Minimum necessary access principle requires limiting access to only what is needed.",
		[user.username],
	)
}

# ---------------------------------------------------------------------------
# All violations aggregated
# ---------------------------------------------------------------------------

violations contains msg if {
	some msg in violation_unique_user_id
}

violations contains msg if {
	some msg in violation_emergency_access
}

violations contains msg if {
	some msg in violation_automatic_logoff
	not _alternative_documented("164.312(a)(2)(iii)")
}

violations contains msg if {
	some msg in violation_encryption
	not _alternative_documented("164.312(a)(2)(iv)")
}

# Addressable findings set aside because the 164.306(d)(3)(ii)(B) decision is documented.
addressed_by_alternative contains id if {
	some id in _addressable_ids
	_alternative_documented(id)
}

violations contains msg if {
	some msg in violation_rbac
}

# Fail-closed: no ePHI systems in scope → cannot certify this safeguard
violations contains msg if {
	count(object.get(input, "phi_systems", [])) == 0
	msg := "HIPAA 164.312(a): no ePHI systems in scope (input.phi_systems is empty) — cannot certify Access Control. Declare the ePHI systems to be evaluated."
}

# ---------------------------------------------------------------------------
# Evidence typing (bad input never passes, issue #301)
# Only the booleans true and false are yes/no evidence, and only a number is a count or a period. A section
# sent as null, a string such as "true", "false" or "90", or a number where a yes/no belongs is a collection
# error: it is a finding against this standard whether the fact decides a control or only feeds an
# advisory, because the verdict cannot rest on evidence of the wrong type. A fact that is absent is handled
# by the rule that reads it (a required fact fails its control; an advisory fact is reported as an advisory).
# ---------------------------------------------------------------------------

_std := "164.312(a)"

# section -> the yes/no facts and the numeric facts this module reads from it
_typed_sections := {
	"access_controls": {"bool": {"emergency_access_procedure_documented", "emergency_access_tested", "role_based_access_implemented", "access_restricted_to_granted_rights"}, "num": {"emergency_accounts_reviewed_days"}},
	"session": {"bool": {"automatic_logoff_enabled", "screen_lock_enabled"}, "num": {"inactivity_timeout_minutes"}},
	"encryption": {"bool": {"key_management_policy_documented"}, "num": {"key_rotation_days"}},
}

# list -> the yes/no facts and the numeric facts this module reads from each entry
_typed_items := {
	"users": {"bool": {"shared_account", "phi_access_disabled", "phi_access", "phi_access_justified", "minimum_necessary_justified"}, "num": {"last_access_review_days"}},
	"phi_systems": {"bool": {"data_at_rest_encrypted"}, "num": {}},
}

evidence_invalid contains msg if {
	some s, _ in _typed_sections
	v := input[s]
	not is_object(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s is not an object (got %s)", [_std, s, type_name(v)])
}

evidence_invalid contains msg if {
	some s, _ in _typed_items
	v := input[s]
	not is_array(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s is not a list (got %s)", [_std, s, type_name(v)])
}

evidence_invalid contains msg if {
	some s, t in _typed_sections
	some f in t.bool
	v := input[s][f]
	not is_boolean(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s.%s is not a boolean (got %s)", [_std, s, f, type_name(v)])
}

evidence_invalid contains msg if {
	some s, t in _typed_sections
	some f in t.num
	v := input[s][f]
	not is_number(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s.%s is not a number (got %s)", [_std, s, f, type_name(v)])
}

evidence_invalid contains msg if {
	some s, _ in _typed_items
	is_array(input[s])
	some i, item in input[s]
	not is_object(item)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s[%d] is not an object (got %s)", [_std, s, i, type_name(item)])
}

evidence_invalid contains msg if {
	some s, t in _typed_items
	is_array(input[s])
	some i, item in input[s]
	some f in t.bool
	v := item[f]
	not is_boolean(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s[%d].%s is not a boolean (got %s)", [_std, s, i, f, type_name(v)])
}

evidence_invalid contains msg if {
	some s, t in _typed_items
	is_array(input[s])
	some i, item in input[s]
	some f in t.num
	v := item[f]
	not is_number(v)
	msg := sprintf("HIPAA %s: evidence invalid — input.%s[%d].%s is not a number (got %s)", [_std, s, i, f, type_name(v)])
}

violations contains msg if some msg in evidence_invalid

# ---------------------------------------------------------------------------
# Overall compliance
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
	count(violations) == 0
}

compliance_report := {
	"section": "164.312(a)",
	"title": "Access Control",
	"required": true,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
	"addressed_by_alternative": addressed_by_alternative,
	"advisories": advisories,
	"controls": {
		"unique_user_id": control_a2i_compliant,
		"emergency_access": control_a2ii_compliant,
		"automatic_logoff": control_a2iii_compliant,
		"encryption_decryption": control_a2iv_compliant,
	},
}
