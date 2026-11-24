package swift_csp.evidence_rule_test

import rego.v1

# Evidence rule (weekly audit 2026-11-24): only the boolean true passes a yes/no fact. Missing, null and
# wrongly typed values ("true", "false", "no", 0, 1) fail the control and the finding names the problem.
#
# Mandatory controls decide `compliant`; advisory controls are tracked and do not block. The facts of the
# two groups are kept apart here so each can be held to its own outcome.

mandatory_facts := {
	"access_control": {
		"access_reviews": {
			"periodic": true,
		},
		"privileged_access": {
			"mfa": true,
		},
		"swift_systems": {
			"least_privilege": true,
			"role_based": true,
		},
	},
	"authentication": {
		"passwords": {
			"change_on_compromise": true,
			"strong_policy": true,
		},
	},
	"back_office": {
		"data_flows": {
			"encrypted": true,
		},
	},
	"credential_storage": {
		"encrypted": true,
	},
	"data_security": {
		"internal_flows": {
			"encrypted": true,
		},
	},
	"environment": {
		"data_flow": {
			"documented": true,
		},
		"secure_zone": {
			"defined": true,
			"network_segmentation": true,
		},
	},
	"hardening": {
		"swift_systems": {
			"baseline_applied": true,
		},
		"unnecessary_services": {
			"disabled": true,
		},
	},
	"incident_response": {
		"plan": {
			"swift_notification_included": true,
			"swift_specific": true,
		},
		"swift_notification": {
			"process_exists": true,
		},
	},
	"infrastructure": {
		"virtualisation": {
			"host_hardened": true,
			"swift_vms_isolated": true,
		},
		"virtualised": true,
	},
	"logging": {
		"retention": {
			"minimum_2_5_years_archived": true,
			"minimum_3_months_online": true,
		},
		"swift_systems": {
			"all_events_captured": true,
		},
		"swift_transactions": {
			"logged": true,
		},
	},
	"malware_protection": {
		"swift_systems": {
			"antimalware_deployed": true,
			"signatures_current": true,
		},
	},
	"network": {
		"internet_access": {
			"restricted_from_swift_zone": true,
		},
		"outbound_filtering": {
			"enabled": true,
		},
	},
	"os_security": {
		"admin_accounts": {
			"not_used_for_daily_tasks": true,
		},
		"privileged_accounts": {
			"restricted": true,
		},
	},
	"outsourcing": {
		"service_provider": {
			"cscf_compliant": true,
		},
		"swift_activities": true,
	},
	"patch_management": {
		"os": {
			"critical_patches_within_3_months": true,
		},
		"swift_components": {
			"current": true,
		},
	},
	"sessions": {
		"operator": {
			"encrypted": true,
		},
	},
	"token_management": {
		"hardware_tokens": {
			"used_for_swift": true,
		},
		"tokens": {
			"secure_storage": true,
		},
	},
	"training": {
		"social_engineering": {
			"included": true,
		},
		"swift_staff": {
			"annual": true,
		},
	},
	"transmission": {
		"swift_messages": {
			"integrity_protected": true,
		},
	},
	"vulnerability_scanning": {
		"findings": {
			"remediated_timely": true,
		},
		"swift_zone": {
			"quarterly": true,
		},
	},
}

advisory_facts := {
	"environment": {
		"transaction_business_controls": {
			"implemented": true,
		},
	},
	"network": {
		"jump_server": {
			"deployed": true,
		},
	},
	"software_integrity": {
		"swift_components": {
			"verified": true,
		},
	},
}

# A function, not a rule: scripts/check_bad_input_fails.py takes the largest all-pass object rule of a test
# package as the module's fixture and expects every mutated leaf to turn `compliant` false, which an advisory
# fact does not do by design.
_all_facts(advisory) := json.patch(mandatory_facts, [
	{"op": "add", "path": ["network", "jump_server"], "value": advisory.network.jump_server},
	{"op": "add", "path": ["environment", "transaction_business_controls"], "value": advisory.environment.transaction_business_controls},
	{"op": "add", "path": ["software_integrity"], "value": advisory.software_integrity},
])

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
	r := data.swift_csp.main.compliance_report with input as {}
	r.compliant == false
	r.mandatory_violation_count == 39
	r.advisory_violation_count == 3
}

# No `with input`: the input document is undefined, as when the caller sends no input at all.
test_no_input_document_fails_like_empty_input if {
	r := data.swift_csp.main.compliance_report
	r.compliant == false
	r.mandatory_violation_count == 39
	r.advisory_violation_count == 3
}

test_all_facts_true_passes_with_no_findings if {
	r := data.swift_csp.main.compliance_report with input as _all_facts(advisory_facts)
	r.compliant == true
	r.violation_count == 0
	r.failed_controls == 0
}

test_no_mutated_mandatory_fact_passes if {
	passing := [bad.case |
		some bad in _bad_inputs(mandatory_facts)
		data.swift_csp.main.compliant with input as bad.input
	]
	passing == []
}

# An advisory fact that is missing or wrongly typed is an advisory finding that names the problem.
test_every_mutated_advisory_fact_is_an_advisory_finding if {
	silent := [bad.case |
		some bad in _bad_inputs(advisory_facts)
		found := data.swift_csp.main.advisory_violations with input as bad.input
		count([m | some m in found; contains(m, "evidence")]) == 0
	]
	silent == []
}

# The audit's case: every yes/no fact as the string "false" cleared 39 mandatory findings down to 2.
test_string_false_everywhere_fails_like_missing_evidence if {
	as_text := json.patch(_all_facts(advisory_facts), [{"op": "replace", "path": path, "value": "false"} | some [path, _] in _leaves(_all_facts(advisory_facts))])
	r := data.swift_csp.main.compliance_report with input as as_text
	r.compliant == false
	r.mandatory_violation_count == 39
	r.advisory_violation_count == 3
}

test_finding_names_the_evidence_problem if {
	path := ["credential_storage", "encrypted"]
	missing := data.swift_csp.main.violations with input as json.patch(_all_facts(advisory_facts), [{"op": "remove", "path": path}])
	missing == {"SWIFT CSP 5.4(M): Stored credentials for SWIFT systems not encrypted — evidence missing: credential_storage.encrypted not collected"}
	wrong := data.swift_csp.main.violations with input as json.patch(_all_facts(advisory_facts), [{"op": "replace", "path": path, "value": "false"}])
	wrong == {"SWIFT CSP 5.4(M): Stored credentials for SWIFT systems not encrypted — evidence invalid: credential_storage.encrypted is not a boolean (got string)"}
	collected_false := data.swift_csp.main.violations with input as json.patch(_all_facts(advisory_facts), [{"op": "replace", "path": path, "value": false}])
	collected_false == {"SWIFT CSP 5.4(M): Stored credentials for SWIFT systems not encrypted"}
}
