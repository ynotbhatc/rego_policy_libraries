# Evidence rule for the SCuBA M365 baselines: only the boolean true satisfies a yes/no fact. Data-driven over every
# leaf of the all-pass fixture, so a fact added to the fixture is covered without a new test.

package scuba_m365_test

import rego.v1

_ev_report(inp) := r if r := data.scuba_m365.main.compliance_report with input as inp

_ev_leaves := [[path, v] |
	walk(compliant_input, [path, v])
	not is_object(v)
	not is_array(v)
	path[0] == "scuba"
]

_ev_wrong(v) := ["true", "false", null, 0, 1] if is_boolean(v)

_ev_wrong(v) := [sprintf("%v", [v]), null, true] if is_number(v)

_ev_wrong(v) := [null, 0, true, ""] if is_string(v)

_ev_dotted(path) := concat(".", [sprintf("%v", [s]) | some s in path])

# a wrong-typed value never passes
test_no_wrong_typed_leaf_passes if {
	count(_ev_leaves) > 100
	every leaf in _ev_leaves {
		every nv in _ev_wrong(leaf[1]) {
			r := _ev_report(json.patch(compliant_input, [{"op": "replace", "path": leaf[0], "value": nv}]))
			r.compliant == false
			r.failed_controls > 0
		}
	}
}

# a removed fact never passes
test_no_removed_leaf_passes if {
	every leaf in _ev_leaves {
		r := _ev_report(json.patch(compliant_input, [{"op": "remove", "path": leaf[0]}]))
		r.compliant == false
		r.failed_controls > 0
	}
}

# the two-fact policy (MS.AAD.3.3) keeps its own wording; every other boolean fact names the evidence problem
_ev_own_wording := {["scuba", "aad", "auth", "authenticator", "enabled"], ["scuba", "aad", "auth", "authenticator", "login_context_shown"]}

_ev_bool_leaves := [leaf | some leaf in _ev_leaves; is_boolean(leaf[1]); not leaf[0] in _ev_own_wording]

test_boolean_of_another_type_is_evidence_invalid if {
	count(_ev_bool_leaves) > 90
	every leaf in _ev_bool_leaves {
		every nv in ["true", "false", null, 0, 1] {
			r := _ev_report(json.patch(compliant_input, [{"op": "replace", "path": leaf[0], "value": nv}]))
			r.violation_count == 1
			want := sprintf("evidence invalid — input.%s must be true or false, got %s", [_ev_dotted(leaf[0]), json.marshal(nv)])
			endswith(r.violations[0], want)
			startswith(r.violations[0], "SCuBA MS.")
		}
	}
}

test_boolean_not_collected_is_evidence_missing if {
	every leaf in _ev_bool_leaves {
		r := _ev_report(json.patch(compliant_input, [{"op": "remove", "path": leaf[0]}]))
		r.violation_count == 1
		endswith(r.violations[0], sprintf("evidence missing — input.%s not collected", [_ev_dotted(leaf[0])]))
	}
}

test_boolean_false_keeps_the_finding_as_written if {
	every leaf in _ev_bool_leaves {
		r := _ev_report(json.patch(compliant_input, [{"op": "replace", "path": leaf[0], "value": false}]))
		r.violation_count == 1
		not contains(r.violations[0], "evidence")
	}
}

test_single_number_policies_name_the_evidence_problem if {
	r := _ev_report(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/aad/privileged/global_admin_count", "value": "4"}]))
	r.violations == ["SCuBA MS.AAD.7.1v1 (SHALL): evidence invalid — input.scuba.aad.privileged.global_admin_count must be a number, got \"4\""]
	m := _ev_report(json.patch(compliant_input, [{"op": "remove", "path": "/scuba/sharepoint/anyone_links/expiration_days"}]))
	m.violations == ["SCuBA MS.SHAREPOINT.3.1v1 (SHALL): evidence missing — input.scuba.sharepoint.anyone_links.expiration_days not collected"]
	o := _ev_report(json.patch(compliant_input, [{"op": "replace", "path": "/scuba/sharepoint/anyone_links/expiration_days", "value": 90}]))
	o.violations == ["SCuBA MS.SHAREPOINT.3.1v1 (SHALL): Anyone-link expiration is not set to 30 days or less"]
}

# SHALL / SHOULD accounting reads the policy prefix, which the evidence wording keeps
test_evidence_findings_keep_shall_should_accounting if {
	r := _ev_report(json.patch(compliant_input, [
		{"op": "replace", "path": "/scuba/exo/smtp_auth_disabled", "value": "true"},
		{"op": "remove", "path": "/scuba/exo/dkim_enabled_all_domains"},
	]))
	r.violation_count == 2
	r.shall_violation_count == 1
	r.should_violation_count == 1
	r.failed_controls == 2
}

test_empty_and_null_sections_fail_every_policy if {
	every inp in [{}, {"scuba": null}, {"scuba": "true"}, {"scuba": {}}, {"scuba": {"exo": null, "aad": "x"}}] {
		r := _ev_report(inp)
		r.compliant == false
		r.failed_controls == 109
		r.violation_count == 109
	}
}
