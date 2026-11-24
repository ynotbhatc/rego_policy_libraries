package ny_dfs.evidence_rule_test

import rego.v1

# Evidence rule (weekly audit 2026-11-24): only the boolean true passes a yes/no fact. Missing, null and
# wrongly typed values ("true", "false", "no", 0, 1) fail the control and the finding names the problem.

all_pass_input := {
	"access_control": {
		"least_privilege": {
			"enforced": true,
		},
		"password_policy": {
			"strong": true,
		},
		"privileged_accounts": {
			"regular_review": true,
		},
		"terminated_users": {
			"prompt_revocation": true,
		},
	},
	"asset_inventory": {
		"maintained": true,
		"tracks_required_fields": true,
	},
	"audit_trail": {
		"retention": {
			"minimum_3_years_financial": true,
			"minimum_5_years_security": true,
		},
		"systems": {
			"tamper_resistant": true,
		},
	},
	"business_continuity": {
		"plan": {
			"documented": true,
		},
	},
	"ciso": {
		"annual_report": {
			"includes_material_issues": true,
			"to_board": true,
		},
		"designated": true,
	},
	"cybersecurity_policy": {
		"annual_review": true,
		"board_approved": true,
		"documented": true,
	},
	"cybersecurity_program": {
		"exists": true,
		"risk_based": {
			"design": true,
		},
	},
	"data_retention": {
		"nonpublic_info": {
			"disposed_when_no_longer_needed": true,
		},
		"policy": {
			"documented": true,
		},
	},
	"encryption": {
		"nonpublic_info": {
			"at_rest": true,
			"in_transit": true,
		},
	},
	"incident_response": {
		"plan": {
			"documented": true,
			"roles_defined": true,
			"tested_annually": true,
		},
	},
	"mfa": {
		"all_individuals_all_systems": {
			"enforced": true,
		},
		"privileged_accounts": {
			"enforced": true,
		},
		"remote_access": {
			"enforced": true,
		},
		"third_party_access": {
			"enforced": true,
		},
	},
	"monitoring": {
		"anomalous_activity": {
			"systems_in_place": true,
		},
		"user_activity": {
			"privileged_users_monitored": true,
		},
	},
	"personnel": {
		"qualified_staff": {
			"available": true,
		},
		"training": {
			"cybersecurity": {
				"annual": true,
			},
		},
	},
	"risk_assessment": {
		"conducted": true,
		"covers_nonpublic_information": true,
		"periodic_review": true,
	},
	"superintendent_notice": {
		"annual_certification": {
			"filed": true,
		},
		"process": {
			"within_72_hours": true,
		},
	},
	"testing": {
		"findings": {
			"remediation_tracked": true,
		},
		"penetration_test": {
			"annual": true,
		},
		"vulnerability_assessment": {
			"semi_annual": true,
		},
	},
	"third_party": {
		"assessment": {
			"periodic_due_diligence": true,
		},
		"contracts": {
			"prompt_notification_required": true,
			"security_controls_required": true,
		},
		"policy": {
			"documented": true,
		},
	},
	"training": {
		"security_awareness": {
			"annual": true,
		},
	},
}

# ── Mutations ───────────────────────────────────────────────────────────────
# Every leaf of an all-pass fixture is evidence. A boolean is swapped for the strings "false", "true"
# and "no", for null, 0 and 1; a number for its string form and null; a text value for null and a
# number; and every leaf is removed once. None of the resulting inputs may pass.
_leaves(fx) := [[path, value] |
	walk(fx, [path, value])
	not is_object(value)
]

_swaps(value) := ["false", "true", "no", null, 0, 1] if is_boolean(value)

_swaps(value) := [sprintf("%v", [value]), null] if is_number(value)

_swaps(value) := [null, 7] if is_string(value)

_bad_inputs(fx) := array.concat(
	[{"case": sprintf("%s := %s", [concat(".", path), json.marshal(swap)]), "input": json.patch(fx, [{"op": "replace", "path": path, "value": swap}])} |
		some [path, value] in _leaves(fx)
		some swap in _swaps(value)
	],
	[{"case": sprintf("%s removed", [concat(".", path)]), "input": json.patch(fx, [{"op": "remove", "path": path}])} |
		some [path, _] in _leaves(fx)
	],
)

test_empty_input_fails if {
	r := data.ny_dfs.main.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 45
}

# No `with input`: the input document is undefined, as when the caller sends no input at all.
test_no_input_document_fails_like_empty_input if {
	r := data.ny_dfs.main.compliance_report
	r.compliant == false
	r.violation_count == 45
}

test_all_pass_input_passes if {
	r := data.ny_dfs.main.compliance_report with input as all_pass_input
	r.compliant == true
	r.violation_count == 0
	r.failed_controls == 0
}

test_no_mutated_input_passes if {
	passing := [bad.case |
		some bad in _bad_inputs(all_pass_input)
		data.ny_dfs.main.compliant with input as bad.input
	]
	passing == []
}

# The audit's case: every yes/no fact as the string "false" cleared 45 findings down to 2.
test_string_false_everywhere_fails_like_boolean_false if {
	as_text := json.patch(all_pass_input, [{"op": "replace", "path": path, "value": "false"} | some [path, _] in _leaves(all_pass_input)])
	as_bool := json.patch(all_pass_input, [{"op": "replace", "path": path, "value": false} | some [path, _] in _leaves(all_pass_input)])
	text := data.ny_dfs.main.violations with input as as_text
	bool := data.ny_dfs.main.violations with input as as_bool
	count(text) == 45
	count(bool) == 45
}

test_finding_names_the_evidence_problem if {
	path := ["ciso", "designated"]
	missing := data.ny_dfs.main.violations with input as json.patch(all_pass_input, [{"op": "remove", "path": path}])
	missing == {"23 NYCRR 500.4(a): Qualified CISO not designated to oversee cybersecurity program — evidence missing: ciso.designated not collected"}
	wrong := data.ny_dfs.main.violations with input as json.patch(all_pass_input, [{"op": "replace", "path": path, "value": "true"}])
	wrong == {"23 NYCRR 500.4(a): Qualified CISO not designated to oversee cybersecurity program — evidence invalid: ciso.designated is not a boolean (got string)"}
	collected_false := data.ny_dfs.main.violations with input as json.patch(all_pass_input, [{"op": "replace", "path": path, "value": false}])
	collected_false == {"23 NYCRR 500.4(a): Qualified CISO not designated to oversee cybersecurity program"}
}
