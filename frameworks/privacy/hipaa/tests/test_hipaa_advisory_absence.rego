# Audit 2026-11-24 round 2: the facts the bad-input harness still lists for hipaa.main as "removed and the
# report passes". Each one feeds only library advisories (decision 2026-11-17: periods and mechanisms the
# Security Rule does not name do not decide HIPAA); the 45 CFR 164.312 specification beside it is decided by
# another fact, which the tests below name. What is pinned here:
#   - removed: the report stays compliant AND says so in `advisories` (absence leaves a trace), except where
#     the input states that the practice does not apply;
#   - wrong type ("true", null, 1): an input-contract finding, the report is not compliant;
#   - the deciding fact of the same specification, removed: the report is not compliant.
package hipaa.advisory_absence_test

import rego.v1

import data.hipaa.test_fixtures as fx

_report(inp) := r if r := data.hipaa.main.compliance_report with input as inp

_ptr(path) := concat("/", array.concat([""], path))

_removed(path) := json.remove(fx.full_input, [_ptr(path)])

_replaced(path, value) := json.patch(fx.full_input, [{"op": "replace", "path": _ptr(path), "value": value}])

# advisory-only fact or section -> minimum number of advisories its removal adds
_advisory_only := [
	[["audit_logging"], 1],
	[["authentication"], 1],
	[["backup"], 1],
	[["encryption"], 1],
	[["password_policy"], 1],
	[["privileged_accounts"], 1],
	[["tls"], 1],
	[["vpn"], 1],
	[["access_controls", "emergency_access_tested"], 1],
	[["authentication", "re_authentication_for_sensitive_ops"], 1],
	[["hipaa", "privacy", "workforce", "training", "frequency", "annual"], 1],
	[["hitech", "ehr", "audit_log", "tamper_evident"], 1],
	[["hitech", "meaningful_use", "security_updates", "implemented"], 1],
	[["monitoring", "unauthorized_access_alerts"], 1],
	[["tls", "certificate_expiry_monitoring"], 1],
	[["vpn", "split_tunneling_enabled"], 1],
	# the fixture states email.phi_sent_via_email == false, so email DLP does not apply: no advisory
	[["email", "dlp_enabled"], 0],
]

# The sweeps are split into slices (item index modulo the slice count), one test per slice, so that no test runs long
# enough to meet the suite's per-test timeout on the oldest supported OPA. Every item is in exactly one slice; the
# test_the_slices_cover_* tests check it.
_slice(xs, i, n) := [x | some j, x in xs; j % n == i]

test_the_slices_cover_advisory_only_8 if {
	sum([count(_slice(_advisory_only, i, 8)) | some i in numbers.range(0, 7)]) == count(_advisory_only)
	every j, x in _advisory_only {
		x in _slice(_advisory_only, j % 8, 8)
	}
}

test_fixture_passes_without_advisories if {
	r := _report(fx.full_input)
	r.compliant == true
	count(r.advisories) == 0
}

test_advisory_only_fact_removed_stays_compliant_and_is_visible if {
	every c in _advisory_only {
		r := _report(_removed(c[0]))
		r.compliant == true
		count(r.advisories) >= c[1]
	}
}

test_advisory_only_fact_of_the_wrong_type_is_an_input_contract_finding_slice_0 if {
	every c in _slice(_advisory_only, 0, 8) {
		every bad in ["true", null, 1] {
			r := _report(_replaced(c[0], bad))
			r.compliant == false
			r.violation_count > 0
		}
	}
}

test_advisory_only_fact_of_the_wrong_type_is_an_input_contract_finding_slice_1 if {
	every c in _slice(_advisory_only, 1, 8) {
		every bad in ["true", null, 1] {
			r := _report(_replaced(c[0], bad))
			r.compliant == false
			r.violation_count > 0
		}
	}
}

test_advisory_only_fact_of_the_wrong_type_is_an_input_contract_finding_slice_2 if {
	every c in _slice(_advisory_only, 2, 8) {
		every bad in ["true", null, 1] {
			r := _report(_replaced(c[0], bad))
			r.compliant == false
			r.violation_count > 0
		}
	}
}

test_advisory_only_fact_of_the_wrong_type_is_an_input_contract_finding_slice_3 if {
	every c in _slice(_advisory_only, 3, 8) {
		every bad in ["true", null, 1] {
			r := _report(_replaced(c[0], bad))
			r.compliant == false
			r.violation_count > 0
		}
	}
}

test_advisory_only_fact_of_the_wrong_type_is_an_input_contract_finding_slice_4 if {
	every c in _slice(_advisory_only, 4, 8) {
		every bad in ["true", null, 1] {
			r := _report(_replaced(c[0], bad))
			r.compliant == false
			r.violation_count > 0
		}
	}
}

test_advisory_only_fact_of_the_wrong_type_is_an_input_contract_finding_slice_5 if {
	every c in _slice(_advisory_only, 5, 8) {
		every bad in ["true", null, 1] {
			r := _report(_replaced(c[0], bad))
			r.compliant == false
			r.violation_count > 0
		}
	}
}

test_advisory_only_fact_of_the_wrong_type_is_an_input_contract_finding_slice_6 if {
	every c in _slice(_advisory_only, 6, 8) {
		every bad in ["true", null, 1] {
			r := _report(_replaced(c[0], bad))
			r.compliant == false
			r.violation_count > 0
		}
	}
}

test_advisory_only_fact_of_the_wrong_type_is_an_input_contract_finding_slice_7 if {
	every c in _slice(_advisory_only, 7, 8) {
		every bad in ["true", null, 1] {
			r := _report(_replaced(c[0], bad))
			r.compliant == false
			r.violation_count > 0
		}
	}
}

# Email DLP is asked for once the input says ePHI is sent by email.
test_email_dlp_absence_is_visible_when_ephi_is_emailed if {
	inp := json.remove(json.patch(fx.full_input, [{"op": "replace", "path": "/email/phi_sent_via_email", "value": true}]), ["/email/dlp_enabled"])
	r := _report(inp)
	r.compliant == true
	some a in r.advisories
	contains(a, "Data Loss Prevention")
}

test_not_collected_advisories_name_the_field if {
	a := _report(_removed(["vpn", "split_tunneling_enabled"])).advisories
	count([m | some m in a; contains(m, "vpn.split_tunneling_enabled not collected")]) == 1
	b := _report(_removed(["privileged_accounts"])).advisories
	count([m | some m in b; contains(m, "privileged_accounts not collected")]) == 1
}

# The specification beside each advisory section is decided by another fact. Removing that one fails.
_deciding := {
	"164.312(b) audit controls": ["phi_systems", "0", "audit_logging_enabled"],
	"164.312(a)(2)(ii) emergency access procedure": ["access_controls", "emergency_access_procedure_documented"],
	"164.312(a)(2)(iv) encryption and decryption": ["phi_systems", "0", "data_at_rest_encrypted"],
	"164.312(c)(1) integrity": ["integrity", "policies_and_procedures_implemented"],
	"164.312(e)(2)(ii) transmission encryption": ["phi_systems", "0", "transmission_encrypted"],
	"164.312(e)(2)(ii) email": ["email", "phi_sent_via_email"],
}

test_deciding_fact_removed_fails if {
	every _, path in _deciding {
		r := _report(_removed(path))
		r.compliant == false
	}
}

# 164.312(d): one of two proofs. The fixture carries mfa.enabled_for_phi_access; the authentication section
# carries the other (ephi_access_requires_authentication). Either alone passes, neither fails.
test_person_or_entity_authentication_needs_one_proof if {
	_report(_removed(["authentication"])).compliant == true
	other := json.patch(fx.full_input, [
		{"op": "remove", "path": "/mfa/enabled_for_phi_access"},
		{"op": "add", "path": "/authentication/ephi_access_requires_authentication", "value": true},
	])
	_report(other).compliant == true
	neither := json.remove(fx.full_input, ["/authentication", "/mfa/enabled_for_phi_access"])
	r := _report(neither)
	r.compliant == false
	some v in r.violations
	contains(v, "164.312(d)")
	every bad in ["true", null, 1] {
		mistyped := json.patch(neither, [{"op": "add", "path": "/authentication", "value": {"ephi_access_requires_authentication": bad}}])
		_report(mistyped).compliant == false
	}
}
