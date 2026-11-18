package hipaa.security_rule_test

import rego.v1

import data.hipaa.security_rule as sr

# Audit 2026-11-17, finding 6. 45 CFR 164.306(d)(3) (eCFR current text): an addressable specification is
# met by implementing it, or by documenting why it is not reasonable and appropriate and implementing an
# equivalent alternative (or documenting why none is). Required specifications have no such path.

_alt := {"not_reasonable_and_appropriate_documented": true, "equivalent_alternative_implemented": true}

_none := {"not_reasonable_and_appropriate_documented": true, "no_reasonable_alternative_documented": true}

_with(base, patch) := object.union(base, patch)

_decide(id, d) := {"hipaa": {"addressable_decisions": {id: d}}}

_no_clearance := _with(_fx.full_input, {"hipaa": {"administrative": {"workforce": {"clearance_procedure": {"implemented": false}}}}})

test_addressable_admin_row_without_decision_fails if {
	v := sr.violations with input as _no_clearance
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.308(a)(3)(ii)(B) Workforce clearance procedure (addressable)")
}

test_addressable_admin_row_with_documented_alternative_passes if {
	inp := _with(_no_clearance, _decide("164.308(a)(3)(ii)(B)", _alt))
	r := sr.report with input as inp
	r.compliant == true
	r.specifications["164.308(a)(3)(ii)(B)"].satisfied == true
	r.specifications["164.308(a)(3)(ii)(B)"].addressed_by_alternative == true
	r.addressed_by_alternative == ["164.308(a)(3)(ii)(B)"]
}

test_addressable_physical_row_with_no_reasonable_alternative_documented_passes if {
	inp := _with(
		_with(_fx.full_input, {"hipaa": {"physical": {"facility_access": {"maintenance_records": {"tracked": false}}}}}),
		_decide("164.310(a)(2)(iv)", _none),
	)
	sr.compliant with input as inp
}

test_incomplete_decision_does_not_satisfy if {
	inp := _with(_no_clearance, _decide("164.308(a)(3)(ii)(B)", {"not_reasonable_and_appropriate_documented": true}))
	not sr.compliant with input as inp
}

test_decision_for_required_spec_never_satisfies_and_is_flagged if {
	inp := _with(
		_with(_fx.full_input, {"hipaa": {"administrative": {"security_management": {"risk_analysis": {"conducted": false}}}}}),
		_decide("164.308(a)(1)(ii)(A)", _alt),
	)
	v := sr.violations with input as inp
	count(v) == 2
	some a in v
	startswith(a, "HIPAA 164.308(a)(1)(ii)(A) Risk analysis (required): fact check failed")
	some b in v
	contains(b, "addressable decision supplied for 164.308(a)(1)(ii)(A), which is required")
}

test_decision_for_unknown_id_is_flagged if {
	v := sr.violations with input as _with(_fx.full_input, _decide("164.312(a)(2)(v)", _alt))
	count(v) == 1
	some m in v
	contains(m, "addressable decision for unknown id 164.312(a)(2)(v)")
}

test_decisions_not_an_object_is_flagged if {
	v := sr.violations with input as _with(_fx.full_input, {"hipaa": {"addressable_decisions": ["164.312(a)(2)(iv)"]}})
	some m in v
	contains(m, "addressable_decisions is not an object")
}

# --- technical rows ------------------------------------------------------------------------

_unencrypted_at_rest := _with(_fx.full_input, {"phi_systems": [_with(_fx.full_input.phi_systems[0], {"data_at_rest_encrypted": false})]})

test_unencrypted_at_rest_without_decision_fails_on_a2iv if {
	v := sr.violations with input as _unencrypted_at_rest
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.312(a)(2)(iv) Encryption and decryption (addressable)")
}

test_unencrypted_at_rest_with_documented_alternative_is_compliant if {
	inp := _with(_unencrypted_at_rest, _decide("164.312(a)(2)(iv)", _alt))
	sr.compliant with input as inp
	sr.technical_safeguards_compliant with input as inp
}

_unencrypted_in_transit := _with(_fx.full_input, {"phi_systems": [_with(_fx.full_input.phi_systems[0], {"transmission_encrypted": false})]})

test_unencrypted_in_transit_is_cited_to_e2ii_not_e1 if {
	v := sr.violations with input as _unencrypted_in_transit
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.312(e)(2)(ii) Encryption (addressable)")
}

test_unencrypted_in_transit_with_documented_alternative_is_compliant if {
	sr.compliant with input as _with(_unencrypted_in_transit, _decide("164.312(e)(2)(ii)", _alt))
}

_no_hashing := _with(_fx.full_input, {"integrity": {"checksum_or_hash_enabled": false}})

test_no_hashing_without_decision_fails_on_c2 if {
	v := sr.violations with input as _no_hashing
	count(v) == 1
	some m in v
	startswith(m, "HIPAA 164.312(c)(2)")
}

test_no_hashing_with_documented_alternative_is_compliant if {
	sr.compliant with input as _with(_no_hashing, _decide("164.312(c)(2)", _none))
}

test_no_message_authentication_with_documented_alternative_is_compliant if {
	inp := _with(_with(_fx.full_input, {"network": {"message_authentication_enabled": false}}), _decide("164.312(e)(2)(i)", _alt))
	sr.compliant with input as inp
}

test_technical_decision_does_not_replace_ephi_scope if {
	inp := _with(_with(_fx.full_input, {"phi_systems": []}), _decide("164.312(a)(2)(iv)", _alt))
	r := sr.report with input as inp
	r.specifications["164.312(a)(2)(iv)"].satisfied == false
	r.compliant == false
}

test_key_rotation_does_not_affect_the_security_rule_result if {
	sr.compliant with input as _with(_fx.full_input, {"encryption": {"key_rotation_days": 900}})
}
