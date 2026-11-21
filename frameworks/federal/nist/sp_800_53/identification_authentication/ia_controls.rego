# METADATA
# title: "NIST SP 800-53 Rev 5 — Identification and Authentication (IA) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 43
#     cited: 33
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.identification_authentication

import rego.v1

# NIST SP 800-53 Rev 5 — Identification and Authentication (IA) Family
# Identify and authenticate users, devices, processes acting on behalf of users. Every active base control (IA-1 to
# IA-13) and the enhancements the SP 800-53B Moderate and High baselines (and FedRAMP High) select. Each enhancement is its own
# requirement with its own finding; a base control never fails for an enhancement.

default compliant := false

# ---------------------------------------------------------------------------------------------------------------
# Evidence helpers. Facts live under input.ia_controls.<name>; `path` is the list of keys below that root. A fact
# that is absent (or whose parent is not an object) is missing evidence, never a pass.
# ---------------------------------------------------------------------------------------------------------------

_root := "ia_controls"

_path_str(path) := concat(".", array.concat(["input", _root], path))

_obj(path) := v if {
	v := object.get(input, array.concat([_root], path), {})
	is_object(v)
} else := {}

_nonempty_array(x) if {
	is_array(x)
	count(x) > 0
}

# Boolean facts: `checks` is a list of [key, description of the unmet state]. Absent or null is missing evidence;
# any other value except the boolean true ("true", 1, false) is a finding.
_bool_missing(path, checks) := {concat(".", [_path_str(path), c[0]]) |
	some c in checks
	not is_boolean(object.get(_obj(path), c[0], null))
}

_bool_failed(path, checks) := {sprintf("%s (%s.%s is not true)", [c[1], _path_str(path), c[0]]) |
	some c in checks
	object.get(_obj(path), c[0], null) == false
}

# A count that must be zero: <path>.<key> not a non-negative whole number is missing evidence; above zero is a finding.
# A count: a non-negative whole number. Anything else (absent, null, "1", a negative or a fractional number) is
# evidence missing.
_count_ok(x) if {
	is_number(x)
	x >= 0
	floor(x) == x
}

_count_missing(path, key) := {concat(".", [_path_str(path), key]) |
	not _count_ok(object.get(_obj(path), key, null))
}

_count_nonzero(path, key, fmt) := {sprintf(fmt, [n]) |
	n := object.get(_obj(path), key, null)
	is_number(n)
	_count_ok(n)
	n > 0
}

# Organization-defined lists: <path>.odp.<odp> is the non-empty list the organisation requires and <path>.<obs> the
# list observed. Either not a list (or the ODP list empty) is missing evidence; each required item that was not
# observed is a finding.
_list_missing(path, obs, odp) := {concat(".", [_path_str(path), obs]) |
	not is_array(object.get(_obj(path), obs, null))
} | {sprintf("%s.odp.%s (organization-defined)", [_path_str(path), odp]) |
	not _nonempty_array(object.get(_obj(path), ["odp", odp], null))
}

_list_unmet(path, obs, odp, fmt) := {sprintf(fmt, [x]) |
	o := _obj(path)
	is_array(o[obs])
	_nonempty_array(o.odp[odp])
	some x in o.odp[odp]
	not x in o[obs]
}

# The text of a control's one finding, after its "NIST <id>: " prefix: the unmet elements, then the evidence
# that was not collected.
_detail(missing, failed) := sprintf("evidence missing — %s not collected", [concat(", ", sort(missing))]) if {
	count(missing) > 0
	count(failed) == 0
}

_detail(missing, failed) := concat("; ", sort(failed)) if {
	count(missing) == 0
	count(failed) > 0
}

_detail(missing, failed) := sprintf("%s; evidence missing — %s not collected", [concat("; ", sort(failed)), concat(", ", sort(missing))]) if {
	count(missing) > 0
	count(failed) > 0
}

# ---------------------------------------------------------------------------------------------------------------
# Original single-fact rules. Each reads one boolean fact and passes only when it is true. A fact that is absent or
# not a boolean ("true", 1, null, an object) is reported as missing evidence; false keeps the original text.
# ---------------------------------------------------------------------------------------------------------------

# One rule pair per id, each message with its literal "NIST <id>: " prefix (the OSCAL catalog and the coverage
# stamp read the id from the message literal).
_fact(path) := object.get(input, array.concat([_root], path), null)

# IA-1: input.ia_controls.policy.documented
violation contains msg if {
	not is_boolean(_fact(["policy", "documented"]))
	msg := "NIST IA-1: evidence missing — input.ia_controls.policy.documented not collected"
}

violation contains msg if {
	_fact(["policy", "documented"]) == false
	msg := "NIST IA-1: Identification and authentication policy not documented"
}

# IA-2: input.ia_controls.user_id_auth.uniquely_identified
violation contains msg if {
	not is_boolean(_fact(["user_id_auth", "uniquely_identified"]))
	msg := "NIST IA-2: evidence missing — input.ia_controls.user_id_auth.uniquely_identified not collected"
}

violation contains msg if {
	_fact(["user_id_auth", "uniquely_identified"]) == false
	msg := "NIST IA-2: Organizational users not uniquely identified and authenticated"
}

# IA-2(1): input.ia_controls.user_id_auth.mfa_for_privileged
violation contains msg if {
	not is_boolean(_fact(["user_id_auth", "mfa_for_privileged"]))
	msg := "NIST IA-2(1): evidence missing — input.ia_controls.user_id_auth.mfa_for_privileged not collected"
}

violation contains msg if {
	_fact(["user_id_auth", "mfa_for_privileged"]) == false
	msg := "NIST IA-2(1): Multi-factor authentication not required for privileged accounts"
}

# IA-2(2): input.ia_controls.user_id_auth.mfa_for_non_privileged
violation contains msg if {
	not is_boolean(_fact(["user_id_auth", "mfa_for_non_privileged"]))
	msg := "NIST IA-2(2): evidence missing — input.ia_controls.user_id_auth.mfa_for_non_privileged not collected"
}

violation contains msg if {
	_fact(["user_id_auth", "mfa_for_non_privileged"]) == false
	msg := "NIST IA-2(2): Multi-factor authentication not required for non-privileged accounts"
}

# IA-3: input.ia_controls.device_identification.implemented
violation contains msg if {
	not is_boolean(_fact(["device_identification", "implemented"]))
	msg := "NIST IA-3: evidence missing — input.ia_controls.device_identification.implemented not collected"
}

violation contains msg if {
	_fact(["device_identification", "implemented"]) == false
	msg := "NIST IA-3: Device identification and authentication not implemented"
}

# IA-4: input.ia_controls.identifier_management.unique_per_user
violation contains msg if {
	not is_boolean(_fact(["identifier_management", "unique_per_user"]))
	msg := "NIST IA-4: evidence missing — input.ia_controls.identifier_management.unique_per_user not collected"
}

violation contains msg if {
	_fact(["identifier_management", "unique_per_user"]) == false
	msg := "NIST IA-4: Identifier management does not assign unique IDs per user"
}

# IA-5: input.ia_controls.authenticator_management.complexity_enforced
violation contains msg if {
	not is_boolean(_fact(["authenticator_management", "complexity_enforced"]))
	msg := "NIST IA-5: evidence missing — input.ia_controls.authenticator_management.complexity_enforced not collected"
}

violation contains msg if {
	_fact(["authenticator_management", "complexity_enforced"]) == false
	msg := "NIST IA-5: Authenticator management lacks complexity/lifetime enforcement"
}

# IA-6: input.ia_controls.authenticator_feedback.obscured
violation contains msg if {
	not is_boolean(_fact(["authenticator_feedback", "obscured"]))
	msg := "NIST IA-6: evidence missing — input.ia_controls.authenticator_feedback.obscured not collected"
}

violation contains msg if {
	_fact(["authenticator_feedback", "obscured"]) == false
	msg := "NIST IA-6: Authentication feedback (e.g., password entry) is not obscured"
}

# IA-8: input.ia_controls.non_organizational_users.identified
violation contains msg if {
	not is_boolean(_fact(["non_organizational_users", "identified"]))
	msg := "NIST IA-8: evidence missing — input.ia_controls.non_organizational_users.identified not collected"
}

violation contains msg if {
	_fact(["non_organizational_users", "identified"]) == false
	msg := "NIST IA-8: Non-organizational users not uniquely identified and authenticated"
}

# IA-5(1) Password-based Authentication: passwords transmitted only over cryptographically protected
# channels and stored in a protected (approved salted key-derivation) form. One finding for the enhancement.
# Facts (input.ia_controls.authenticator_management): encrypted_in_transit, encrypted_at_rest (booleans; only true
# passes, absent or not a boolean is missing evidence, false is a finding).
_ia5_1_facts := [
	["encrypted_in_transit", "transmitted only over cryptographically protected channels"],
	["encrypted_at_rest", "stored cryptographically protected"],
]

_ia5_1_missing := {_path_str(["authenticator_management", c[0]]) |
	some c in _ia5_1_facts
	not is_boolean(_fact(["authenticator_management", c[0]]))
}

_ia5_1_gaps := {sprintf("%s (%s)", [c[1], _path_str(["authenticator_management", c[0]])]) |
	some c in _ia5_1_facts
	_fact(["authenticator_management", c[0]]) == false
}

_ia5_1_failed := {sprintf("Password-based authentication — not evidenced: %s", [concat("; ", sort(_ia5_1_gaps))]) |
	count(_ia5_1_gaps) > 0
}

violation contains msg if {
	count(_ia5_1_missing | _ia5_1_failed) > 0
	msg := sprintf("NIST IA-5(1): %s", [_detail(_ia5_1_missing, _ia5_1_failed)])
}

# IA-7: authentication to a cryptographic module must meet "applicable laws, executive orders, directives,
# policies, regulations, standards, and guidelines". Which standard applies is the organisation's input
# (FedRAMP's FIPS-validated-or-NSA-approved parameter is applied in the FedRAMP module, not here).
_ia7 := _obj(["cryptographic_module_auth"])

_ia7_missing contains "input.ia_controls.cryptographic_module_auth.odp.required_standards (applicable standards)" if {
	x := object.get(_ia7, ["odp", "required_standards"], null)
	not is_array(x)
}

_ia7_missing contains "input.ia_controls.cryptographic_module_auth.odp.required_standards (applicable standards)" if {
	count(object.get(_ia7, ["odp", "required_standards"], [])) == 0
}

_ia7_missing contains "input.ia_controls.cryptographic_module_auth.standards_met" if {
	not is_array(object.get(_ia7, "standards_met", null))
}

ia7_unmet contains s if {
	count(_ia7_missing) == 0
	some s in _ia7.odp.required_standards
	not s in _ia7.standards_met
}

violation contains msg if {
	count(_ia7_missing) > 0
	msg := sprintf("NIST IA-7: evidence missing — %s not collected", [concat(", ", sort(_ia7_missing))])
}

violation contains msg if {
	count(ia7_unmet) > 0
	msg := sprintf("NIST IA-7: Cryptographic module authentication does not meet the applicable standards: %v", [sort(ia7_unmet)])
}

# ---------------------------------------------------------------------------------------------------------------
# Moderate-baseline enhancements and base controls added 2026-11 (IA-2(8), IA-2(12), IA-4(4), IA-5(2), IA-5(6),
# IA-8(1), IA-8(2), IA-8(4), IA-11, IA-12, IA-12(2), IA-12(3), IA-12(5)). Each reads only its own keys and has
# its own single finding.
# ---------------------------------------------------------------------------------------------------------------

# IA-2(8) Access to Accounts — Replay Resistant: replay-resistant authentication for access to the
# organization-defined account types.
# Facts (input.ia_controls.user_id_auth.replay_resistance): odp.account_types (organization-defined, e.g.
# ["privileged", "non_privileged"]); replay_resistant_account_types (account types whose every authentication
# mechanism is replay-resistant — nonce/challenge-response, TLS-bound, FIDO2, Kerberos — from the IdP configuration).
_ia2_8_path := ["user_id_auth", "replay_resistance"]

_ia2_8_missing := _list_missing(_ia2_8_path, "replay_resistant_account_types", "account_types")

_ia2_8_failed := _list_unmet(_ia2_8_path, "replay_resistant_account_types", "account_types", "authentication for %v accounts is not replay-resistant")

violation contains msg if {
	count(_ia2_8_missing | _ia2_8_failed) > 0
	msg := sprintf("NIST IA-2(8): %s", [_detail(_ia2_8_missing, _ia2_8_failed)])
}

# IA-2(12) Acceptance of PIV Credentials: PIV-compliant credentials accepted and electronically verified.
# Facts (input.ia_controls.user_id_auth.piv): piv_accepted (PIV/smart-card authentication enabled),
# electronically_verified (certificate chain and status validated on use) — booleans.
_ia2_12_path := ["user_id_auth", "piv"]

_ia2_12_bools := [
	["piv_accepted", "PIV-compliant credentials not accepted"],
	["electronically_verified", "PIV-compliant credentials not electronically verified"],
]

_ia2_12_missing := _bool_missing(_ia2_12_path, _ia2_12_bools)

_ia2_12_failed := _bool_failed(_ia2_12_path, _ia2_12_bools)

violation contains msg if {
	count(_ia2_12_missing | _ia2_12_failed) > 0
	msg := sprintf("NIST IA-2(12): %s", [_detail(_ia2_12_missing, _ia2_12_failed)])
}

# IA-4(4) Identify User Status: individual identifiers indicate the organization-defined characteristics
# (e.g. contractor, foreign national).
# Facts (input.ia_controls.identifier_management.user_status): odp.characteristics (organization-defined);
# characteristics_indicated (characteristics the identifier scheme or directory attributes mark on every account).
_ia4_4_path := ["identifier_management", "user_status"]

_ia4_4_missing := _list_missing(_ia4_4_path, "characteristics_indicated", "characteristics")

_ia4_4_failed := _list_unmet(_ia4_4_path, "characteristics_indicated", "characteristics", "identifiers do not indicate user status characteristic %v")

violation contains msg if {
	count(_ia4_4_missing | _ia4_4_failed) > 0
	msg := sprintf("NIST IA-4(4): %s", [_detail(_ia4_4_missing, _ia4_4_failed)])
}

# IA-5(2) Public Key-based Authentication: authorized access to the private key enforced; the authenticated
# identity mapped to the individual or group account; when PKI is used, certificates validated by building and
# verifying a certification path to an accepted trust anchor including status checks, and a local cache of
# revocation data kept.
# Facts (input.ia_controls.authenticator_management.public_key): private_key_access_enforced,
# identity_mapped_to_account, pki_used (booleans; pki_used must be a boolean); when pki_used is true also
# certification_path_validated, revocation_status_checked, local_revocation_cache (booleans).
_ia5_2_path := ["authenticator_management", "public_key"]

_ia5_2_obj := _obj(_ia5_2_path)

_ia5_2_base_bools := [
	["private_key_access_enforced", "authorized access to the private key not enforced"],
	["identity_mapped_to_account", "authenticated identity not mapped to the individual or group account"],
]

_ia5_2_pki_bools := [
	["certification_path_validated", "certificates not validated by a certification path to an accepted trust anchor"],
	["revocation_status_checked", "certificate status information not checked during path validation"],
	["local_revocation_cache", "no local cache of revocation data"],
] if {
	_ia5_2_obj.pki_used == true
} else := []

_ia5_2_bools := array.concat(_ia5_2_base_bools, _ia5_2_pki_bools)

_ia5_2_pki_missing := {concat(".", [_path_str(_ia5_2_path), "pki_used"]) |
	not is_boolean(object.get(_ia5_2_obj, "pki_used", null))
}

_ia5_2_missing := _bool_missing(_ia5_2_path, _ia5_2_bools) | _ia5_2_pki_missing

_ia5_2_failed := _bool_failed(_ia5_2_path, _ia5_2_bools)

violation contains msg if {
	count(_ia5_2_missing | _ia5_2_failed) > 0
	msg := sprintf("NIST IA-5(2): %s", [_detail(_ia5_2_missing, _ia5_2_failed)])
}

# IA-5(6) Protection of Authenticators: authenticators protected commensurate with the security category of the
# information their use gives access to.
# Facts (input.ia_controls.authenticator_management.authenticator_protection): plaintext_authenticators_found
# (count of unprotected authenticators — passwords, keys, tokens — found by the latest secret scan; must be 0);
# protection_meets_security_category (boolean: authenticator storage and handling controls are those required for
# the system's security category).
_ia5_6_path := ["authenticator_management", "authenticator_protection"]

_ia5_6_bools := [["protection_meets_security_category", "authenticator protection not commensurate with the security category of the information accessed"]]

_ia5_6_missing := _bool_missing(_ia5_6_path, _ia5_6_bools) | _count_missing(_ia5_6_path, "plaintext_authenticators_found")

_ia5_6_failed := _bool_failed(_ia5_6_path, _ia5_6_bools) | _count_nonzero(_ia5_6_path, "plaintext_authenticators_found", "%v unprotected authenticators found by secret scanning")

violation contains msg if {
	count(_ia5_6_missing | _ia5_6_failed) > 0
	msg := sprintf("NIST IA-5(6): %s", [_detail(_ia5_6_missing, _ia5_6_failed)])
}

# IA-8(1) Acceptance of PIV Credentials from Other Agencies: PIV-compliant credentials from other federal agencies
# accepted and electronically verified.
# Facts (input.ia_controls.non_organizational_users.piv_other_agencies): piv_accepted, electronically_verified
# (booleans; e.g. the other agencies' issuing CAs are trusted through the Federal PKI bridge).
_ia8_1_path := ["non_organizational_users", "piv_other_agencies"]

_ia8_1_bools := [
	["piv_accepted", "PIV-compliant credentials from other federal agencies not accepted"],
	["electronically_verified", "PIV-compliant credentials from other federal agencies not electronically verified"],
]

_ia8_1_missing := _bool_missing(_ia8_1_path, _ia8_1_bools)

_ia8_1_failed := _bool_failed(_ia8_1_path, _ia8_1_bools)

violation contains msg if {
	count(_ia8_1_missing | _ia8_1_failed) > 0
	msg := sprintf("NIST IA-8(1): %s", [_detail(_ia8_1_missing, _ia8_1_failed)])
}

# IA-8(2) Acceptance of External Authenticators: only NIST-compliant external authenticators accepted; a list of
# accepted external authenticators documented and maintained.
# Facts (input.ia_controls.non_organizational_users.external_authenticators): list_maintained (boolean);
# accepted (list of {name, nist_compliant} for every external authenticator the system accepts; an empty list
# means none is accepted and passes).
_ia8_2_path := ["non_organizational_users", "external_authenticators"]

_ia8_2_bools := [["list_maintained", "list of accepted external authenticators not documented and maintained"]]

_ia8_2_accepted := object.get(_obj(_ia8_2_path), "accepted", null)

_ia8_2_list_missing := {concat(".", [_path_str(_ia8_2_path), "accepted"]) | not is_array(_ia8_2_accepted)}

_nist_compliant(a) if {
	is_object(a)
	a.nist_compliant == true
}

_auth_name(a) := a.name if {
	is_object(a)
	is_string(a.name)
} else := sprintf("%v", [a])

_ia8_2_list_failed := {sprintf("external authenticator %s accepted but not evidenced as NIST-compliant", [_auth_name(a)]) |
	is_array(_ia8_2_accepted)
	some a in _ia8_2_accepted
	not _nist_compliant(a)
}

_ia8_2_missing := _bool_missing(_ia8_2_path, _ia8_2_bools) | _ia8_2_list_missing

_ia8_2_failed := _bool_failed(_ia8_2_path, _ia8_2_bools) | _ia8_2_list_failed

violation contains msg if {
	count(_ia8_2_missing | _ia8_2_failed) > 0
	msg := sprintf("NIST IA-8(2): %s", [_detail(_ia8_2_missing, _ia8_2_failed)])
}

# IA-8(4) Use of Defined Profiles: identity management conforms to the organization-defined profiles (e.g. SAML
# 2.0 or OpenID Connect federation profiles).
# Facts (input.ia_controls.non_organizational_users.identity_profiles): odp.profiles (organization-defined);
# conformed_profiles (profiles the identity federation configuration conforms to).
_ia8_4_path := ["non_organizational_users", "identity_profiles"]

_ia8_4_missing := _list_missing(_ia8_4_path, "conformed_profiles", "profiles")

_ia8_4_failed := _list_unmet(_ia8_4_path, "conformed_profiles", "profiles", "identity management does not conform to profile %v")

violation contains msg if {
	count(_ia8_4_missing | _ia8_4_failed) > 0
	msg := sprintf("NIST IA-8(4): %s", [_detail(_ia8_4_missing, _ia8_4_failed)])
}

# IA-11 Re-authentication: users re-authenticate in the organization-defined circumstances (e.g. role change,
# privileged function, session timeout).
# Facts (input.ia_controls.reauthentication): odp.circumstances (organization-defined); enforced_circumstances
# (circumstances for which the IdP or session policy forces re-authentication).
_ia11_path := ["reauthentication"]

_ia11_missing := _list_missing(_ia11_path, "enforced_circumstances", "circumstances")

_ia11_failed := _list_unmet(_ia11_path, "enforced_circumstances", "circumstances", "re-authentication not required when %v")

violation contains msg if {
	count(_ia11_missing | _ia11_failed) > 0
	msg := sprintf("NIST IA-11: %s", [_detail(_ia11_missing, _ia11_failed)])
}

# IA-12 Identity Proofing: users who need accounts for logical access are identity proofed at the assurance level
# the applicable standards require; identities resolved to a unique individual; identity evidence collected,
# validated and verified.
# Facts (input.ia_controls.identity_proofing): accounts_without_proofing (count of active accounts with no
# identity proofing record; must be 0); assurance_level_meets_requirement, resolved_to_unique_individual,
# evidence_collected_validated_verified (booleans).
_ia12_path := ["identity_proofing"]

_ia12_bools := [
	["assurance_level_meets_requirement", "identity proofing not performed at the identity assurance level the applicable standards require"],
	["resolved_to_unique_individual", "user identities not resolved to a unique individual"],
	["evidence_collected_validated_verified", "identity evidence not collected, validated and verified"],
]

_ia12_missing := _bool_missing(_ia12_path, _ia12_bools) | _count_missing(_ia12_path, "accounts_without_proofing")

_ia12_failed := _bool_failed(_ia12_path, _ia12_bools) | _count_nonzero(_ia12_path, "accounts_without_proofing", "%v accounts for logical access have no identity proofing record")

violation contains msg if {
	count(_ia12_missing | _ia12_failed) > 0
	msg := sprintf("NIST IA-12: %s", [_detail(_ia12_missing, _ia12_failed)])
}

# IA-12(2) Identity Evidence: evidence of individual identification presented to the registration authority.
# Facts (input.ia_controls.identity_proofing.identity_evidence): presented_to_registration_authority (boolean).
_ia12_2_path := ["identity_proofing", "identity_evidence"]

_ia12_2_bools := [["presented_to_registration_authority", "evidence of individual identification not required to be presented to the registration authority"]]

_ia12_2_missing := _bool_missing(_ia12_2_path, _ia12_2_bools)

_ia12_2_failed := _bool_failed(_ia12_2_path, _ia12_2_bools)

violation contains msg if {
	count(_ia12_2_missing | _ia12_2_failed) > 0
	msg := sprintf("NIST IA-12(2): %s", [_detail(_ia12_2_missing, _ia12_2_failed)])
}

# IA-12(3) Identity Evidence Validation and Verification: presented identity evidence validated and verified
# through the organization-defined methods.
# Facts (input.ia_controls.identity_proofing.validation): odp.methods (organization-defined); methods_used
# (methods the proofing workflow applies).
_ia12_3_path := ["identity_proofing", "validation"]

_ia12_3_missing := _list_missing(_ia12_3_path, "methods_used", "methods")

_ia12_3_failed := _list_unmet(_ia12_3_path, "methods_used", "methods", "identity evidence not validated and verified through %v")

violation contains msg if {
	count(_ia12_3_missing | _ia12_3_failed) > 0
	msg := sprintf("NIST IA-12(3): %s", [_detail(_ia12_3_missing, _ia12_3_failed)])
}

# IA-12(5) Address Confirmation: the organization-defined item (a registration code or a notice of proofing)
# delivered through an out-of-band channel to verify the user's address of record.
# Facts (input.ia_controls.identity_proofing.address_confirmation): odp.delivered_item ("registration code" or
# "notice of proofing"); delivered_item (what the proofing workflow sends); out_of_band (boolean: sent over a
# channel separate from the one used for proofing).
_ia12_5_path := ["identity_proofing", "address_confirmation"]

_ia12_5_obj := _obj(_ia12_5_path)

_ia12_5_bools := [["out_of_band", "address confirmation not delivered through an out-of-band channel"]]

_ia12_5_item_missing := {sprintf("%s.odp.delivered_item (organization-defined: registration code or notice of proofing)", [_path_str(_ia12_5_path)]) |
	not object.get(_ia12_5_obj, ["odp", "delivered_item"], null) in {"registration code", "notice of proofing"}
} | {concat(".", [_path_str(_ia12_5_path), "delivered_item"]) |
	not is_string(object.get(_ia12_5_obj, "delivered_item", null))
}

_ia12_5_item_failed := {sprintf("address confirmation delivers %v; the organization-defined item is %v", [_ia12_5_obj.delivered_item, _ia12_5_obj.odp.delivered_item]) |
	count(_ia12_5_item_missing) == 0
	_ia12_5_obj.delivered_item != _ia12_5_obj.odp.delivered_item
}

_ia12_5_missing := _bool_missing(_ia12_5_path, _ia12_5_bools) | _ia12_5_item_missing

_ia12_5_failed := _bool_failed(_ia12_5_path, _ia12_5_bools) | _ia12_5_item_failed

violation contains msg if {
	count(_ia12_5_missing | _ia12_5_failed) > 0
	msg := sprintf("NIST IA-12(5): %s", [_detail(_ia12_5_missing, _ia12_5_failed)])
}

# ---------------------------------------------------------------------------------------------------------------
# Remaining base controls (IA-9, IA-10, IA-13) and the High-baseline enhancements (NIST SP 800-53B High and
# FedRAMP High: IA-2(5), IA-2(6), IA-5(7), IA-5(8), IA-5(13), IA-12(4)). Each reads only its own keys and has its
# own single finding.
# ---------------------------------------------------------------------------------------------------------------

# Organization-defined maximum: <path>.<obs> may not exceed <path>.odp.<odp>. Either one not a number is missing
# evidence. `fmt` takes the observed value and the organization-defined value, in that order.
_num_missing(path, obs, odp) := {concat(".", [_path_str(path), pair[0]]) |
	o := _obj(path)
	some pair in [[obs, object.get(o, obs, null)], [concat(".", ["odp", odp]), object.get(o, ["odp", odp], null)]]
	not is_number(pair[1])
}

_over(path, obs, odp, fmt) := {sprintf(fmt, [n, m]) |
	o := _obj(path)
	n := object.get(o, obs, null)
	m := object.get(o, ["odp", odp], null)
	is_number(n)
	is_number(m)
	n > m
}

# IA-2(5) Individual Authentication with Group Authentication: users are individually authenticated before they
# can use a shared account or authenticator.
# Facts (input.ia_controls.user_id_auth.shared_accounts): reachable_without_individual_auth (number of shared
# accounts that can be used without first authenticating as an individual, e.g. not behind a privileged access
# management checkout; from the PAM and directory inventory; 0 also when there are no shared accounts).
_ia2_5_path := ["user_id_auth", "shared_accounts"]

_ia2_5_missing := _count_missing(_ia2_5_path, "reachable_without_individual_auth")

_ia2_5_failed := _count_nonzero(_ia2_5_path, "reachable_without_individual_auth", "%v shared accounts can be used without individual authentication first")

violation contains msg if {
	count(_ia2_5_missing | _ia2_5_failed) > 0
	msg := sprintf("NIST IA-2(5): %s", [_detail(_ia2_5_missing, _ia2_5_failed)])
}

# IA-2(6) Access to Accounts — Separate Device: multi-factor authentication for the organization-defined access
# types (local, network, remote) to the organization-defined account types, with one factor on a device separate
# from the system gaining access that meets the organization-defined strength of mechanism.
# Facts (input.ia_controls.user_id_auth.separate_device): odp.access_types, odp.account_types
# (organization-defined lists); separate_device_access_types, separate_device_account_types (lists the IdP or
# MFA policy enforces a separate-device factor for); device_meets_strength_requirements (boolean: the separate
# device, e.g. a FIDO2 key or PIV card, meets the organization-defined strength of mechanism).
_ia2_6_path := ["user_id_auth", "separate_device"]

_ia2_6_bools := [["device_meets_strength_requirements", "separate authentication device does not meet the organization-defined strength of mechanism requirements"]]

_ia2_6_missing := (_bool_missing(_ia2_6_path, _ia2_6_bools) | _list_missing(_ia2_6_path, "separate_device_access_types", "access_types")) | _list_missing(_ia2_6_path, "separate_device_account_types", "account_types")

_ia2_6_failed := (_bool_failed(_ia2_6_path, _ia2_6_bools) | _list_unmet(_ia2_6_path, "separate_device_access_types", "access_types", "%v access does not require a factor from a separate device")) | _list_unmet(_ia2_6_path, "separate_device_account_types", "account_types", "access to %v accounts does not require a factor from a separate device")

violation contains msg if {
	count(_ia2_6_missing | _ia2_6_failed) > 0
	msg := sprintf("NIST IA-2(6): %s", [_detail(_ia2_6_missing, _ia2_6_failed)])
}

# IA-5(7) No Embedded Unencrypted Static Authenticators: unencrypted static authenticators are not embedded in
# applications or other static storage (source code, scripts, images, configuration files).
# Facts (input.ia_controls.authenticator_management.embedded_authenticators): unencrypted_static_found (number of
# unencrypted static authenticators the latest secret scan of code repositories, images and configuration found;
# must be 0).
_ia5_7_path := ["authenticator_management", "embedded_authenticators"]

_ia5_7_missing := _count_missing(_ia5_7_path, "unencrypted_static_found")

_ia5_7_failed := _count_nonzero(_ia5_7_path, "unencrypted_static_found", "%v unencrypted static authenticators embedded in applications or static storage")

violation contains msg if {
	count(_ia5_7_missing | _ia5_7_failed) > 0
	msg := sprintf("NIST IA-5(7): %s", [_detail(_ia5_7_missing, _ia5_7_failed)])
}

# IA-5(8) Multiple System Accounts: the organization-defined security controls manage the risk of compromise from
# individuals having accounts on multiple systems.
# Facts (input.ia_controls.authenticator_management.multiple_system_accounts): odp.controls (organization-defined
# list, e.g. "single sign-on", "distinct authenticators per system"); controls_implemented (controls in place).
_ia5_8_path := ["authenticator_management", "multiple_system_accounts"]

_ia5_8_missing := _list_missing(_ia5_8_path, "controls_implemented", "controls")

_ia5_8_failed := _list_unmet(_ia5_8_path, "controls_implemented", "controls", "control %v for individuals with accounts on multiple systems not implemented")

violation contains msg if {
	count(_ia5_8_missing | _ia5_8_failed) > 0
	msg := sprintf("NIST IA-5(8): %s", [_detail(_ia5_8_missing, _ia5_8_failed)])
}

# IA-5(13) Expiration of Cached Authenticators: cached authenticators may not be used after the
# organization-defined time period.
# Facts (input.ia_controls.authenticator_management.cached_authenticators): max_cache_hours (longest configured
# lifetime of a cached credential, e.g. SSSD offline_credentials_expiration or the Windows cached logon setting,
# across the estate) + odp.max_hours.
_ia5_13_path := ["authenticator_management", "cached_authenticators"]

_ia5_13_missing := _num_missing(_ia5_13_path, "max_cache_hours", "max_hours")

_ia5_13_failed := _over(_ia5_13_path, "max_cache_hours", "max_hours", "cached authenticators usable for up to %v hours; the organization-defined period is %v hours")

violation contains msg if {
	count(_ia5_13_missing | _ia5_13_failed) > 0
	msg := sprintf("NIST IA-5(13): %s", [_detail(_ia5_13_missing, _ia5_13_failed)])
}

# IA-9 Service Identification and Authentication: the organization-defined system services and applications are
# uniquely identified and authenticated before communications are established.
# Facts (input.ia_controls.service_authentication): odp.services (organization-defined list);
# authenticated_services (services that present a unique identity and are authenticated, e.g. mutual TLS
# certificates or workload identities, from the service mesh or PKI inventory).
_ia9_path := ["service_authentication"]

_ia9_missing := _list_missing(_ia9_path, "authenticated_services", "services")

_ia9_failed := _list_unmet(_ia9_path, "authenticated_services", "services", "service %v not uniquely identified and authenticated before communicating")

violation contains msg if {
	count(_ia9_missing | _ia9_failed) > 0
	msg := sprintf("NIST IA-9: %s", [_detail(_ia9_missing, _ia9_failed)])
}

# IA-10 Adaptive Authentication: the organization-defined supplemental authentication techniques are required in
# the organization-defined circumstances (e.g. new device, unusual location, high-risk sign-in).
# Facts (input.ia_controls.adaptive_authentication): odp.circumstances, odp.techniques (organization-defined
# lists); enforced_circumstances (circumstances for which a conditional access or risk policy is enabled);
# techniques_configured (supplemental techniques those policies require).
_ia10_path := ["adaptive_authentication"]

_ia10_missing := _list_missing(_ia10_path, "enforced_circumstances", "circumstances") | _list_missing(_ia10_path, "techniques_configured", "techniques")

_ia10_failed := _list_unmet(_ia10_path, "enforced_circumstances", "circumstances", "supplemental authentication not required when %v") | _list_unmet(_ia10_path, "techniques_configured", "techniques", "supplemental authentication technique %v not configured")

violation contains msg if {
	count(_ia10_missing | _ia10_failed) > 0
	msg := sprintf("NIST IA-10: %s", [_detail(_ia10_missing, _ia10_failed)])
}

# IA-12(4) In-person Validation and Verification: identity evidence validated and verified in person before a
# designated registration authority.
# Facts (input.ia_controls.identity_proofing.in_person): required (boolean: the proofing workflow requires an
# in-person or supervised remote session with the registration authority); accounts_without_in_person_proofing
# (number of active accounts whose proofing record shows no in-person verification; must be 0).
_ia12_4_path := ["identity_proofing", "in_person"]

_ia12_4_bools := [["required", "identity proofing workflow does not require in-person validation and verification"]]

_ia12_4_missing := _bool_missing(_ia12_4_path, _ia12_4_bools) | _count_missing(_ia12_4_path, "accounts_without_in_person_proofing")

_ia12_4_failed := _bool_failed(_ia12_4_path, _ia12_4_bools) | _count_nonzero(_ia12_4_path, "accounts_without_in_person_proofing", "%v accounts proofed without in-person validation and verification")

violation contains msg if {
	count(_ia12_4_missing | _ia12_4_failed) > 0
	msg := sprintf("NIST IA-12(4): %s", [_detail(_ia12_4_missing, _ia12_4_failed)])
}

# IA-13 Identity Providers and Authorization Servers: identity providers and authorization servers manage user,
# device and non-person entity identities, attributes and access rights for authentication and authorization
# decisions, according to the organization-defined policy and mechanisms.
# Facts (input.ia_controls.identity_providers): applications_with_local_authentication (number of applications
# that authenticate or authorize users themselves instead of through an approved identity provider or
# authorization server; must be 0); npe_and_device_identities_managed (boolean: device and NPE identities are
# issued and managed by an identity provider).
_ia13_path := ["identity_providers"]

_ia13_bools := [["npe_and_device_identities_managed", "device and non-person entity identities not managed by an identity provider"]]

_ia13_missing := _bool_missing(_ia13_path, _ia13_bools) | _count_missing(_ia13_path, "applications_with_local_authentication")

_ia13_failed := _bool_failed(_ia13_path, _ia13_bools) | _count_nonzero(_ia13_path, "applications_with_local_authentication", "%v applications authenticate or authorize users outside an approved identity provider or authorization server")

violation contains msg if {
	count(_ia13_missing | _ia13_failed) > 0
	msg := sprintf("NIST IA-13: %s", [_detail(_ia13_missing, _ia13_failed)])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"IA-1", "IA-2", "IA-2(1)", "IA-2(2)", "IA-2(5)", "IA-2(6)", "IA-2(8)", "IA-2(12)", "IA-3", "IA-4", "IA-4(4)",
	"IA-5", "IA-5(1)", "IA-5(2)", "IA-5(6)", "IA-5(7)", "IA-5(8)", "IA-5(13)", "IA-6", "IA-7", "IA-8", "IA-8(1)",
	"IA-8(2)", "IA-8(4)", "IA-9", "IA-10", "IA-11", "IA-12", "IA-12(2)", "IA-12(3)", "IA-12(4)", "IA-12(5)", "IA-13",
}

compliance_report := {
	"family": "IA",
	"name": "Identification and Authentication",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
