package hipaa.access_control_test

import rego.v1

import data.hipaa.access_control as ac
import data.hipaa.test_fixtures as fx

# Audit 2026-11-17, finding 6. 164.312(a)(2)(iii) and (a)(2)(iv) are addressable (eCFR, 45 CFR 164.312);
# 164.306(d)(3) lets the entity implement them, or document why not and implement an equivalent
# alternative (or document why none is reasonable). Neither evidenced -> the findings stand.

_unencrypted := object.union(fx.full_input, {"phi_systems": [object.union(fx.full_input.phi_systems[0], {"data_at_rest_encrypted": false})]})

_decision(id, d) := {"hipaa": {"addressable_decisions": {id: d}}}

_alt := {"not_reasonable_and_appropriate_documented": true, "equivalent_alternative_implemented": true}

_none := {"not_reasonable_and_appropriate_documented": true, "no_reasonable_alternative_documented": true}

test_unencrypted_phi_without_decision_fails if {
	not ac.compliant with input as _unencrypted
	some v in ac.violations with input as _unencrypted
	startswith(v, "HIPAA 164.312(a)(2)(iv)")
}

test_unencrypted_phi_with_documented_equivalent_alternative_passes if {
	inp := object.union(_unencrypted, _decision("164.312(a)(2)(iv)", _alt))
	ac.compliant with input as inp
	ac.control_a2iv_compliant with input as inp
	"164.312(a)(2)(iv)" in ac.addressed_by_alternative with input as inp
}

test_unencrypted_phi_with_documented_no_alternative_passes if {
	inp := object.union(_unencrypted, _decision("164.312(a)(2)(iv)", _none))
	ac.compliant with input as inp
}

test_decision_without_not_reasonable_documentation_fails if {
	inp := object.union(_unencrypted, _decision("164.312(a)(2)(iv)", {"equivalent_alternative_implemented": true}))
	not ac.compliant with input as inp
}

test_decision_without_alternative_or_rationale_fails if {
	inp := object.union(_unencrypted, _decision("164.312(a)(2)(iv)", {"not_reasonable_and_appropriate_documented": true}))
	not ac.compliant with input as inp
}

test_string_true_is_not_a_decision if {
	inp := object.union(_unencrypted, _decision("164.312(a)(2)(iv)", {"not_reasonable_and_appropriate_documented": "true", "equivalent_alternative_implemented": true}))
	not ac.compliant with input as inp
}

test_decision_for_a_different_paragraph_does_not_cover_encryption if {
	inp := object.union(_unencrypted, _decision("164.312(a)(2)(iii)", _alt))
	not ac.compliant with input as inp
}

# 164.312(a)(2)(i) is Required: a decision for it is ignored and its findings stand.
test_decision_for_required_unique_id_is_ignored if {
	inp := object.union(
		object.union(fx.full_input, {"users": [{"username": "alice", "shared_account": true}]}),
		_decision("164.312(a)(2)(i)", _alt),
	)
	not ac.compliant with input as inp
	some v in ac.violations with input as inp
	startswith(v, "HIPAA 164.312(a)(2)(i):")
}

test_logoff_disabled_with_documented_alternative_passes if {
	inp := object.union(
		object.union(fx.full_input, {"session": {"automatic_logoff_enabled": false}}),
		_decision("164.312(a)(2)(iii)", _alt),
	)
	ac.compliant with input as inp
}

test_logoff_disabled_without_decision_fails if {
	inp := object.union(fx.full_input, {"session": {"automatic_logoff_enabled": false}})
	not ac.compliant with input as inp
}

# --- re-homed library periods --------------------------------------------------------------

test_key_rotation_400_days_is_advisory_only if {
	inp := object.union(fx.full_input, {"encryption": {"key_rotation_days": 400}})
	ac.compliant with input as inp
	some a in ac.advisories with input as inp
	contains(a, "400 days")
	vs := ac.violations with input as inp
	every v in vs {
		not contains(v, "rotat")
	}
}

test_thirty_minute_logoff_is_advisory_only if {
	inp := object.union(fx.full_input, {"session": {"inactivity_timeout_minutes": 30}})
	ac.compliant with input as inp
	count(ac.advisories) == 1 with input as inp
}

test_logoff_timeout_zero_is_a_violation if {
	inp := object.union(fx.full_input, {"session": {"inactivity_timeout_minutes": 0}})
	not ac.compliant with input as inp
}

test_logoff_timeout_missing_is_a_violation if {
	inp := object.union(object.remove(fx.full_input, ["session"]), {"session": {"automatic_logoff_enabled": true, "screen_lock_enabled": true}})
	not ac.compliant with input as inp
}

test_access_review_period_is_advisory_only if {
	inp := object.union(fx.full_input, {"users": [{"username": "alice", "shared_account": false, "phi_access": true, "phi_access_justified": true, "last_access_review_days": 200}]})
	ac.compliant with input as inp
	some a in ac.advisories with input as inp
	contains(a, "200 days")
}

test_no_phi_systems_still_fails_closed_even_with_decisions if {
	inp := object.union(object.union(fx.full_input, {"phi_systems": []}), _decision("164.312(a)(2)(iv)", _alt))
	not ac.compliant with input as inp
}

test_report_carries_advisories_and_alternatives if {
	r := ac.compliance_report with input as {}
	r.compliant == false
	is_set(r.advisories)
	count(r.addressed_by_alternative) == 0
}

# String values are not numbers: "900" must not be read as a rotation age (OPA orders strings above numbers).
test_string_rotation_age_is_reported_as_not_collected if {
	inp := object.union(fx.full_input, {"encryption": {"key_rotation_days": "900"}})
	adv := ac.advisories with input as inp
	count(adv) == 1
	some a in adv
	contains(a, "key_rotation_days not collected")
}
