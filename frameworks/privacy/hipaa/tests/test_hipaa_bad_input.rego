# Bad input never passes (issue #301, audit 2026-11-24): data-driven over the shared all-pass fixture.
# Every yes/no fact of the fixture is replaced by the strings "true" and "false", by null and by 0 / 1, every
# number by a string, and every fact is removed in turn; the module that owns the fact must not report
# compliant, with one stated exception for removal (see test_removed_fact_fails_unless_advisory). Each fact
# is evaluated against its owning module, not hipaa.main, to keep the run short; hipaa.main requires every
# module (test_hipaa_main.rego) and is checked end to end at the bottom of this file.
package hipaa.bad_input_test

import rego.v1

import data.hipaa.test_fixtures as fx

# --- which module decides a fact -------------------------------------------------------------------------
_owner(path) := "privacy_rule" if {
	array.slice(path, 0, 2) == ["hipaa", "privacy"]
} else := "hitech" if {
	path[0] == "hitech"
} else := "security_rule" if {
	array.slice(path, 0, 2) in {["hipaa", "administrative"], ["hipaa", "physical"]}
} else := "technical" if {
	path[0] != "hipaa"
}

_compliant("privacy_rule", inp) if data.hipaa.privacy_rule.compliant with input as inp

_compliant("hitech", inp) if data.hipaa.hitech.compliant with input as inp

_compliant("security_rule", inp) if data.hipaa.security_rule.compliant with input as inp

_compliant("part160", inp) if data.hipaa.part160.compliant with input as inp

_compliant("part162", inp) if data.hipaa.part162.compliant with input as inp

_compliant("technical", inp) if {
	data.hipaa.access_control.compliant with input as inp
	data.hipaa.audit_controls.compliant with input as inp
	data.hipaa.authentication.compliant with input as inp
	data.hipaa.integrity.compliant with input as inp
	data.hipaa.transmission_security.compliant with input as inp
}

# --- the fixture's facts (attestation maps and the scope declaration are tested separately below) ------------
_facts[path] := v if {
	walk(fx.full_input, [path, v])
	not is_object(v)
	not is_array(v)
	_owner(path)
}

_bool_paths := {p | some p, v in _facts; is_boolean(v)}

_num_paths := {p | some p, v in _facts; is_number(v)}

_ptr(path) := concat("/", array.concat([""], [sprintf("%v", [p]) | some p in path]))

_replaced(path, value) := json.patch(fx.full_input, [{"op": "replace", "path": path, "value": value}])

_passing_with(paths, value) := {_ptr(p) | some p in paths; _compliant(_owner(p), _replaced(p, value))}

test_fixture_is_compliant if {
	r := data.hipaa.main.compliance_report with input as fx.full_input
	r.compliant == true
	count(r.violations) == 0
	every o in ["privacy_rule", "hitech", "security_rule", "technical"] {
		_compliant(o, fx.full_input)
	}
}

test_empty_input_fails if {
	r := data.hipaa.main.compliance_report with input as {}
	r.compliant == false
	r.violation_count > 0
}

test_fixture_covers_booleans_and_numbers if {
	count(_bool_paths) > 200
	count(_num_paths) > 15
}

test_string_true_never_passes if _passing_with(_bool_paths, "true") == set()

test_string_false_never_passes if _passing_with(_bool_paths, "false") == set()

test_null_never_passes if _passing_with(_bool_paths | _num_paths, null) == set()

test_one_is_not_a_boolean if _passing_with(_bool_paths, 1) == set()

test_zero_is_not_a_boolean if _passing_with(_bool_paths, 0) == set()

test_number_as_string_never_passes if {
	passing := {_ptr(p) | some p in _num_paths; _compliant(_owner(p), _replaced(p, sprintf("%v", [_facts[p]])))}
	passing == set()
}

# Removing a fact fails its module unless the fact is an advisory fact: library practice the regulation does
# not state, reported in `advisories` and by design never part of `compliant` (audit 2026-11-17). The test
# pins the exact set, so a new fact that can be removed without failing has to be listed here.
test_removed_fact_fails_unless_advisory if {
	passing := {_ptr(p) |
		some p in (_bool_paths | _num_paths)
		_compliant(_owner(p), json.patch(fx.full_input, [{"op": "remove", "path": p}]))
	}
	passing == _advisory_facts
}

# --- attestation maps -----------------------------------------------------------------------------------
_maps := {
	"specifications": "security_rule",
	"subpart_d": "hitech",
	"subpart_e": "privacy_rule",
	"part_160": "part160",
	"part_162": "part162",
}

_violations("security_rule", inp) := vs if vs := data.hipaa.security_rule.violations with input as inp

_violations("hitech", inp) := vs if vs := data.hipaa.hitech.violations with input as inp

_violations("privacy_rule", inp) := vs if vs := data.hipaa.privacy_rule.violations with input as inp

_violations("part160", inp) := vs if vs := data.hipaa.part160.violations with input as inp

_violations("part162", inp) := vs if vs := data.hipaa.part162.violations with input as inp

# Every attestation of a map set to the same wrong value: each id is named by a finding, whether the row
# needed the attestation ("not attested") or facts decide it ("evidence invalid").
_all_named(value) if {
	every key, module in _maps {
		bad := {id: value | some id, _ in fx.full_input.hipaa[key]}
		inp := json.patch(fx.full_input, [{"op": "replace", "path": ["hipaa", key], "value": bad}])
		vs := _violations(module, inp)
		every id, _ in bad {
			some v in vs
			contains(v, id)
		}
	}
}

test_string_true_attestations_all_reported if _all_named("true")

test_string_false_attestations_all_reported if _all_named("false")

test_null_attestations_all_reported if _all_named(null)

test_numeric_attestations_all_reported if _all_named(1)

# One mistyped attestation on a row that facts decide is enough to fail the module.
test_single_mistyped_attestation_on_a_fact_row_fails if {
	every key, module in {"specifications": "security_rule", "subpart_d": "hitech", "subpart_e": "privacy_rule"} {
		some id, _ in data.hipaa[module].fact_basis
		inp := json.patch(fx.full_input, [{"op": "add", "path": ["hipaa", key, id], "value": "true"}])
		some v in _violations(module, inp)
		contains(v, "evidence invalid")
		contains(v, id)
	}
}

# Audit 2026-11-24, round 3. The all-pass fixture carries an attestation only for the rows that read one.
# Each such attestation removed, false, null or of another type fails the module that owns it.
# The attestations are swept in 4 slices (index modulo 4 in the order of map, then id), so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every attestation is in exactly one slice.
_attestations := [[key, id] |
	some key in sort([k | some k, _ in _maps])
	some id in sort([i | some i, _ in fx.full_input.hipaa[key]])
]

_attestation_slice(i) := [a | some j, a in _attestations; j % 4 == i]

test_the_attestation_slices_cover_every_attestation if {
	sum([count(_attestation_slice(i)) | some i in numbers.range(0, 3)]) == count(_attestations)
	count(_attestations) == sum([count(fx.full_input.hipaa[key]) | some key, _ in _maps])
	every j, a in _attestations {
		a in _attestation_slice(j % 4)
	}
}

test_every_attestation_the_fixture_carries_is_required_slice_0 if {
	every a in _attestation_slice(0) {
		key := a[0]
		id := a[1]
		module := _maps[key]
		not _compliant(module, json.remove(fx.full_input, [sprintf("hipaa/%s/%s", [key, id])]))
		every value in [false, null, "true", "false", 1] {
			not _compliant(module, _replaced(["hipaa", key, id], value))
		}
	}
}

test_every_attestation_the_fixture_carries_is_required_slice_1 if {
	every a in _attestation_slice(1) {
		key := a[0]
		id := a[1]
		module := _maps[key]
		not _compliant(module, json.remove(fx.full_input, [sprintf("hipaa/%s/%s", [key, id])]))
		every value in [false, null, "true", "false", 1] {
			not _compliant(module, _replaced(["hipaa", key, id], value))
		}
	}
}

test_every_attestation_the_fixture_carries_is_required_slice_2 if {
	every a in _attestation_slice(2) {
		key := a[0]
		id := a[1]
		module := _maps[key]
		not _compliant(module, json.remove(fx.full_input, [sprintf("hipaa/%s/%s", [key, id])]))
		every value in [false, null, "true", "false", 1] {
			not _compliant(module, _replaced(["hipaa", key, id], value))
		}
	}
}

test_every_attestation_the_fixture_carries_is_required_slice_3 if {
	every a in _attestation_slice(3) {
		key := a[0]
		id := a[1]
		module := _maps[key]
		not _compliant(module, json.remove(fx.full_input, [sprintf("hipaa/%s/%s", [key, id])]))
		every value in [false, null, "true", "false", 1] {
			not _compliant(module, _replaced(["hipaa", key, id], value))
		}
	}
}

test_fixture_carries_no_attestation_for_a_fact_row if {
	every key, module in {"specifications": "security_rule", "subpart_d": "hitech", "subpart_e": "privacy_rule"} {
		every id, _ in data.hipaa[module].fact_basis {
			not id in object.keys(fx.full_input.hipaa[key])
		}
	}
}

# A fact-decided row does not read its attestation: true is accepted, a mistyped value is invalid evidence
# (above), and false contradicts the passing facts and is reported. None of them passes except true.
test_attestation_on_a_fact_row if {
	every key, module in {"specifications": "security_rule", "subpart_d": "hitech", "subpart_e": "privacy_rule"} {
		every id, _ in data.hipaa[module].fact_basis {
			_compliant(module, json.patch(fx.full_input, [{"op": "add", "path": ["hipaa", key, id], "value": true}]))
			inp := json.patch(fx.full_input, [{"op": "add", "path": ["hipaa", key, id], "value": false}])
			not _compliant(module, inp)
			some v in _violations(module, inp)
			contains(v, "evidence contradictory")
			contains(v, id)
		}
	}
}

# false on a fact row whose facts already fail adds nothing: the row is reported once, as a failed fact check.
test_false_attestation_on_a_failed_fact_row_is_not_double_counted if {
	base := object.union(fx.full_input, {"hipaa": {"physical": {"workstation_security": {"ephi_access": {"restricted": false}}}}})
	with_false := json.patch(base, [{"op": "add", "path": ["hipaa", "specifications", "164.310(c)"], "value": false}])
	count(data.hipaa.security_rule.violations) == 1 with input as base
	count(data.hipaa.security_rule.violations) == 1 with input as with_false
}

# An addressable row not implemented (its fact is false) and met by a documented 164.306(d)(3) alternative
# may truthfully attest false.
test_false_attestation_with_documented_alternative_passes if {
	id := "164.308(a)(5)(ii)(B)"
	data.hipaa.security_rule.fact_basis[id]
	data.hipaa.security_rule.specifications[id].status == "addressable"
	inp := json.patch(fx.full_input, [
		{"op": "add", "path": ["hipaa", "specifications", id], "value": false},
		{"op": "replace", "path": ["hipaa", "administrative", "training", "malicious_software", "covered"], "value": false},
		{"op": "add", "path": ["hipaa", "addressable_decisions"], "value": {id: {
			"not_reasonable_and_appropriate_documented": true,
			"equivalent_alternative_implemented": true,
		}}},
	])
	not _contradiction(inp)
}

_contradiction(inp) if {
	some v in data.hipaa.security_rule.violations with input as inp
	contains(v, "evidence contradictory")
}

test_scope_roles_must_be_booleans if {
	every role, _ in fx.full_input.hipaa.scope {
		every value in ["true", "false", null, 1] {
			inp := _replaced(["hipaa", "scope", role], value)
			_scope_rejected(inp)
		}
	}
}

# The four roles are read by every part; the two activity flags (de-identification, fundraising) by the Privacy Rule.
_scope_rejected(inp) if not data.hipaa.part160.compliant with input as inp

_scope_rejected(inp) if not data.hipaa.privacy_rule.compliant with input as inp

# --- wording and end-to-end ------------------------------------------------------------------------------
# An advisory fact of the wrong type is still a finding: the verdict does not rest on mistyped evidence.
test_mistyped_advisory_fact_is_reported if {
	inp := _replaced(["vpn", "split_tunneling_enabled"], "false")
	"HIPAA 164.312(e): evidence invalid — input.vpn.split_tunneling_enabled is not a boolean (got string)" in data.hipaa.transmission_security.violations with input as inp
	r := data.hipaa.main.compliance_report with input as inp
	r.compliant == false
}

test_null_section_is_reported if {
	inp := object.union(fx.full_input, {"tls": null})
	"HIPAA 164.312(e): evidence invalid — input.tls is not an object (got null)" in data.hipaa.transmission_security.violations with input as inp
	r := data.hipaa.main.compliance_report with input as inp
	r.compliant == false
}

test_missing_account_list_fails_unique_user_identification if {
	inp := object.remove(fx.full_input, ["users"])
	r := data.hipaa.access_control.compliance_report with input as inp
	r.controls.unique_user_id == false
	some v in r.violations
	contains(v, "evidence missing — input.users not collected")
}

test_unstated_email_use_fails if {
	inp := object.remove(fx.full_input, ["email"])
	some v in data.hipaa.transmission_security.violations with input as inp
	contains(v, "evidence missing — email.phi_sent_via_email not collected")
}

test_string_false_no_longer_clears_a_technical_finding if {
	inp := _replaced(["session", "automatic_logoff_enabled"], "false")
	some v in data.hipaa.access_control.violations with input as inp
	startswith(v, "HIPAA 164.312(a)(2)(iii): Automatic logoff is not enabled")
}

# Advisories still never decide compliance by their value (audit 2026-11-17).
test_false_advisory_fact_still_passes if {
	inp := _replaced(["tls", "mutual_tls_for_phi_apis"], false)
	r := data.hipaa.main.compliance_report with input as inp
	r.compliant == true
}

_advisory_facts := {
	"/access_controls/emergency_access_tested",
	"/access_controls/emergency_accounts_reviewed_days",
	"/audit_logging/centralized",
	"/audit_logging/includes_action_type",
	"/audit_logging/includes_source_ip",
	"/audit_logging/includes_timestamp",
	"/audit_logging/includes_user_id",
	"/audit_logging/offsite_backup_enabled",
	"/audit_logging/retention_days",
	"/audit_logging/tamper_evident",
	"/authentication/concurrent_sessions_unlimited",
	"/authentication/re_authentication_for_sensitive_ops",
	"/backup/backup_frequency_hours",
	"/backup/offsite_or_cloud_backup",
	"/backup/regular_backups_enabled",
	"/backup/restore_test_days",
	"/backup/restore_tested",
	"/email/dlp_enabled",
	"/email/encrypted_email_required",
	"/encryption/key_management_policy_documented",
	"/encryption/key_rotation_days",
	"/hipaa/administrative/business_associates/compliance/monitored",
	"/hipaa/administrative/business_associates/inventory/maintained",
	"/hipaa/administrative/contingency/testing/frequency_months",
	"/hipaa/administrative/evaluation/frequency_months",
	"/hipaa/administrative/incident_response/forensic_capability/available",
	"/hipaa/administrative/security_management/risk_analysis/frequency_months",
	"/hipaa/administrative/training/frequency_months",
	"/hipaa/physical/workstation_use/physical_access/restricted",
	"/hipaa/physical/workstation_use/screen_lock/configured",
	"/hipaa/privacy/workforce/training/frequency/annual",
	"/hitech/ehr/access_controls/automatic_logoff/configured",
	"/hitech/ehr/access_controls/emergency_access/procedure",
	"/hitech/ehr/access_controls/unique_user_id",
	"/hitech/ehr/audit_log/enabled",
	"/hitech/ehr/audit_log/tamper_evident",
	"/hitech/ehr/encryption/at_rest",
	"/hitech/ehr/encryption/in_transit",
	"/hitech/ehr/integrity/data_authentication",
	"/hitech/enforcement/audit_response/procedures_defined",
	"/hitech/enforcement/cap_template/available",
	"/hitech/enforcement/compliance_monitoring/internal",
	"/hitech/enforcement/hhs_ocr_cooperation/policy",
	"/hitech/meaningful_use/security_deficiencies/corrected",
	"/hitech/meaningful_use/security_risk_analysis/annually",
	"/hitech/meaningful_use/security_risk_analysis/conducted",
	"/hitech/meaningful_use/security_updates/implemented",
	"/integrity/change_management_process",
	"/integrity/checksum_or_hash_enabled",
	"/integrity/digital_signatures_for_phi_export",
	"/integrity/media_reuse_without_sanitization",
	"/integrity/secure_deletion_policy",
	"/integrity/write_protection_on_archived_phi",
	"/mfa/required_for_privileged_accounts",
	"/mfa/required_for_remote_access",
	"/mfa/stronger_method_also_available",
	"/monitoring/after_hours_access_alerts",
	"/monitoring/automated_alerting_enabled",
	"/monitoring/unauthorized_access_alerts",
	"/network/phi_network_segmented",
	"/network/remote_phi_access_enabled",
	"/password_policy/complexity_required",
	"/password_policy/history_count",
	"/password_policy/lockout_enabled",
	"/password_policy/lockout_threshold",
	"/password_policy/max_age_days",
	"/password_policy/minimum_length",
	"/phi_systems/0/integrity_check_frequency_hours",
	"/phi_systems/0/integrity_checking_enabled",
	"/phi_systems/0/request_signing_enabled",
	"/session/screen_lock_enabled",
	"/tls/certificate_expiry_days",
	"/tls/certificate_expiry_monitoring",
	"/tls/mutual_tls_for_phi_apis",
	"/users/0/phi_access_disabled",
	"/vpn/required_for_remote_phi_access",
	"/vpn/split_tunneling_enabled",
}
