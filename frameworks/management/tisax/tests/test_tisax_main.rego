package tisax.main_test

import rego.v1

# Behaviour tests for the ISA2027.1 rebuild: pass, fail and no-data for each part, the attestation rules,
# part scoping and the report contract.

_controls := data.tisax.main.isa_controls

_spec := data.tisax.main.evidence_spec

_signed := {"attested": true, "by": "ISMS owner", "date": "2026-11-01"}

_all_attestations := {id: _signed | some id, _ in _controls; not _spec[id]}

_good_evidence := {
	"software": {"unapproved_packages": 0, "package_signature_verification": true},
	"endpoint": {"disk_encryption_enabled": true, "removable_storage_restricted": true},
	"authentication": {"mfa_privileged_access": true, "failed_login_lockout": true, "session_idle_timeout_minutes": 10},
	"accounts": {"password_min_length": 14, "shared_accounts": 0, "empty_password_accounts": 0, "default_credential_accounts": 0},
	"access": {"unapproved_privileged_accounts": 0, "remote_root_login_permitted": false, "dormant_enabled_accounts": 0},
	"crypto": {"system_policy_approved": true, "weak_algorithms_permitted": false},
	"transport": {"tls_min_version": 1.2, "cleartext_services_enabled": 0},
	"malware": {"agent_running": true, "on_access_scanning": true, "signature_age_days": 1},
	"logging": {"audit_daemon_active": true, "central_forwarding": true, "time_synchronized": true},
	"vulnerabilities": {"last_scan_age_days": 7, "critical_past_due": 0},
	"system_audit": {"last_test_age_days": 200, "high_findings_past_due": 0},
	"network": {"host_firewall_enabled": true, "default_deny_inbound": true},
	"backup": {"configured": true, "last_success_age_days": 1, "last_restore_test_age_days": 90},
}

_good := {"tisax": {"evidence": _good_evidence, "attestations": _all_attestations}}

_report(inp) := r if {
	r := data.tisax.main.compliance_report with input as inp
}

_status(inp, id) := st if {
	some r in _report(inp).control_results
	r.id == id
	st := r.status
}

_with_evidence(area, fact, value) := {"tisax": {
	"evidence": object.union(_good_evidence, {area: object.union(_good_evidence[area], {fact: value})}),
	"attestations": _all_attestations,
}}

_with_attestation(id, a) := {"tisax": {
	"evidence": _good_evidence,
	"attestations": object.union(object.remove(_all_attestations, [id]), {id: a}),
}}

_without_attestation(id) := {"tisax": {
	"evidence": _good_evidence,
	"attestations": object.remove(_all_attestations, [id]),
}}

# ── Catalogue shape ──────────────────────────────────────────────────────────

test_catalogue_has_77_active_controls if {
	count(_controls) == 77
	data.tisax.main.standard_total == 77
	_report({}).standard_total == data.tisax.main.standard_total
	count({id | some id, _ in _controls; not startswith(id, "8."); not startswith(id, "9.")}) == 45
	count({id | some id, _ in _controls; startswith(id, "8.")}) == 20
	count({id | some id, _ in _controls; startswith(id, "9.")}) == 12
}

test_superseded_3_1_2_not_assessed if {
	not "3.1.2" in object.keys(_controls)
	some n in _report({}).not_assessed
	n.number == "3.1.2"
}

test_thirteen_technical_controls_all_in_information_security if {
	count(_spec) == 13
	every id, _ in _spec {
		_controls[id]
		not startswith(id, "8.")
		not startswith(id, "9.")
	}
}

test_control_results_in_catalogue_order if {
	ids := [r.id | some r in _report(_good).control_results]
	ids[0] == "1.1.1"
	ids[76] == "9.8.1"
	some i, j
	ids[i] == "8.1.9"
	ids[j] == "8.1.10"
	i < j
}

# ── Everything supplied: compliant ───────────────────────────────────────────

test_full_evidence_and_attestations_compliant if {
	r := _report(_good)
	r.compliant == true
	r.total_controls == 77
	r.failed_controls == 0
	r.violation_count == 0
	r.control_result_counts.pass == 77
}

# ── No data never passes ─────────────────────────────────────────────────────

test_empty_input_fails_closed if {
	r := _report({})
	r.compliant == false
	r.total_controls == 77
	r.failed_controls == 77
	r.control_result_counts.evidence_missing == 77
	r.failed_controls <= r.total_controls
}

test_empty_tisax_object_fails_closed if {
	r := _report({"tisax": {}})
	r.compliant == false
	r.failed_controls == 77
}

test_non_object_tisax_reported if {
	r := _report({"tisax": "yes"})
	r.compliant == false
	some v in r.violations
	contains(v, "input.tisax is missing or not an object")
}

# ── Information Security, technical control (5.2.9 backup) ──────────────────

test_is_technical_pass if _status(_good, "5.2.9") == "pass"

test_is_technical_fail_on_stale_backup if {
	inp := _with_evidence("backup", "last_success_age_days", 30)
	_status(inp, "5.2.9") == "fail"
	r := _report(inp)
	r.compliant == false
	r.failed_control_ids == ["5.2.9"]
	some v in r.violations
	contains(v, "input.tisax.evidence.backup.last_success_age_days is 30, required at most 7")
}

test_is_technical_missing_fact_is_evidence_missing if {
	inp := {"tisax": {
		"evidence": object.union(object.remove(_good_evidence, ["backup"]), {"backup": {"configured": true, "last_restore_test_age_days": 90}}),
		"attestations": _all_attestations,
	}}
	_status(inp, "5.2.9") == "evidence_missing"
}

test_is_technical_wrong_type_is_evidence_missing if {
	_status(_with_evidence("backup", "configured", "true"), "5.2.9") == "evidence_missing"
}

test_is_technical_fail_beats_missing if {
	inp := {"tisax": {
		"evidence": object.union(object.remove(_good_evidence, ["backup"]), {"backup": {"configured": false}}),
		"attestations": _all_attestations,
	}}
	_status(inp, "5.2.9") == "fail"
}

test_is_technical_password_length_min if {
	_status(_with_evidence("accounts", "password_min_length", 8), "4.1.3") == "fail"
	_status(_with_evidence("accounts", "password_min_length", 12), "4.1.3") == "pass"
}

test_is_technical_false_test if {
	_status(_with_evidence("access", "remote_root_login_permitted", true), "4.2.1") == "fail"
}

test_is_technical_tls_floor if {
	_status(_with_evidence("transport", "tls_min_version", 1.0), "5.1.2") == "fail"
	_status(_with_evidence("transport", "tls_min_version", 1.3), "5.1.2") == "pass"
}

test_technical_control_ignores_attestation if {
	inp := {"tisax": {"attestations": {"5.2.9": _signed}}}
	_status(inp, "5.2.9") == "evidence_missing"
}

# ── Information Security, organisational control (1.1.1 policies) ────────────

test_is_attestation_pass if _status(_good, "1.1.1") == "pass"

test_is_attestation_absent_is_evidence_missing if {
	_status(_without_attestation("1.1.1"), "1.1.1") == "evidence_missing"
}

test_is_attestation_false_is_not_attested if {
	_status(_with_attestation("1.1.1", {"attested": false, "by": "x", "date": "2026-11-01"}), "1.1.1") == "not_attested"
}

test_is_attestation_without_signer_is_not_attested if {
	_status(_with_attestation("1.1.1", {"attested": true, "by": " ", "date": "2026-11-01"}), "1.1.1") == "not_attested"
	_status(_with_attestation("1.1.1", {"attested": true, "by": "x"}), "1.1.1") == "not_attested"
	_status(_with_attestation("1.1.1", true), "1.1.1") == "not_attested"
}

test_is_attestation_maturity_below_target_fails if {
	a := object.union(_signed, {"maturity_level": 2})
	_status(_with_attestation("1.1.1", a), "1.1.1") == "fail"
}

test_is_attestation_maturity_at_target_passes if {
	a := object.union(_signed, {"maturity_level": 3})
	_status(_with_attestation("1.1.1", a), "1.1.1") == "pass"
}

test_is_attestation_maturity_not_a_number_fails if {
	a := object.union(_signed, {"maturity_level": "3"})
	inp := _with_attestation("1.1.1", a)
	_status(inp, "1.1.1") == "fail"
	some v in _report(inp).violations
	contains(v, "maturity_level must be a number")
}

# ── Prototype Protection (8.2.6 intrusion detection) ─────────────────────────

test_pp_pass if _status(_good, "8.2.6") == "pass"

test_pp_absent_is_evidence_missing if {
	inp := _without_attestation("8.2.6")
	_status(inp, "8.2.6") == "evidence_missing"
	_report(inp).compliant == false
}

test_pp_not_attested if {
	_status(_with_attestation("8.2.6", {"attested": true, "date": "2026-11-01"}), "8.2.6") == "not_attested"
}

test_pp_out_of_scope_only_on_boolean_false if {
	inp := {"tisax": {"scope": {"prototype_protection": false}}}
	r := _report(inp)
	r.total_controls == 57
	r.parts_not_in_scope == ["prototype_protection"]
	not _status(inp, "8.2.6")
	r.part_results.prototype_protection.in_scope == false
}

test_pp_scope_flag_not_boolean_keeps_scope if {
	r := _report({"tisax": {"scope": {"prototype_protection": "no"}}})
	r.total_controls == 77
}

# ── Data Protection (9.5.3 third-country transfers) ──────────────────────────

test_dp_pass if _status(_good, "9.5.3") == "pass"

test_dp_absent_is_evidence_missing if _status(_without_attestation("9.5.3"), "9.5.3") == "evidence_missing"

test_dp_maturity_fail if {
	a := object.union(_signed, {"maturity_level": 1})
	inp := _with_attestation("9.5.3", a)
	_status(inp, "9.5.3") == "fail"
	_report(inp).failed_control_ids == ["9.5.3"]
}

test_dp_out_of_scope if {
	r := _report({"tisax": {"scope": {"data_protection": false}}})
	r.total_controls == 65
}

test_only_information_security_in_scope if {
	inp := {"tisax": {
		"scope": {"prototype_protection": false, "data_protection": false},
		"evidence": _good_evidence,
		"attestations": {id: _signed | some id, _ in _all_attestations; not startswith(id, "8."); not startswith(id, "9.")},
	}}
	r := _report(inp)
	r.total_controls == 45
	r.compliant == true
}

# ── Input contract ───────────────────────────────────────────────────────────

test_unknown_attestation_key_blocks_compliance if {
	inp := _with_attestation("3.1.2", _signed)
	r := _report(inp)
	r.compliant == false
	r.failed_controls == 0
	some v in r.violations
	contains(v, "\"3.1.2\" is not an active ISA2027.1 control number")
}

test_part_results_counts if {
	p := _report({}).part_results
	p.information_security.controls == 45
	p.information_security.evidence_based == 13
	p.information_security.attestation_based == 32
	p.prototype_protection.attestation_based == 20
	p.data_protection.attestation_based == 12
}
