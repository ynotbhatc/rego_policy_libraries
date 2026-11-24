package hitrust.evidence_test

import rego.v1

# Evidence rule (audit 2026-11-24): only the boolean true passes a HITRUST check. Before the fix the
# string "false" on every fact cleared all 63 findings and the report said compliant.
# The fixture holds the 63 facts the module reads, all true.

all_pass := {
	"security_program": {
		"isms": {
			"established": true,
		},
		"policies": {
			"approved_by_management": true,
			"annual_review": true,
		},
	},
	"access_control": {
		"policy": {
			"documented": true,
		},
		"user_access": {
			"formal_registration": true,
		},
		"privileged_access": {
			"controlled": true,
		},
		"password_policy": {
			"strong": true,
		},
		"mfa": {
			"critical_systems": true,
		},
		"access_review": {
			"periodic": true,
		},
		"termination": {
			"prompt_revocation": true,
		},
	},
	"hr_security": {
		"background_checks": {
			"performed": true,
		},
		"confidentiality": {
			"agreements_signed": true,
		},
		"sanctions": {
			"policy_documented": true,
		},
	},
	"risk_management": {
		"assessment": {
			"conducted": true,
			"phi_scope": true,
			"periodic_review": true,
		},
		"treatment": {
			"plan_documented": true,
		},
		"encryption": {
			"phi_at_rest": true,
			"phi_in_transit": true,
		},
	},
	"security_policy": {
		"phi_specific": {
			"documented": true,
		},
		"dissemination": {
			"to_workforce": true,
		},
	},
	"compliance": {
		"hipaa": {
			"privacy_rule": {
				"policies": true,
			},
			"security_rule": {
				"policies": true,
			},
			"breach_notification": {
				"plan": true,
			},
		},
		"legal": {
			"periodic_review": true,
		},
	},
	"asset_management": {
		"inventory": {
			"maintained": true,
		},
		"classification": {
			"phi_labeled": true,
		},
		"disposal": {
			"secure_media_sanitization": true,
		},
	},
	"physical_security": {
		"perimeter": {
			"controlled_access": true,
		},
		"equipment": {
			"secured": true,
		},
		"visitor_access": {
			"logged": true,
		},
	},
	"operations": {
		"change_management": {
			"formal_process": true,
		},
		"malware": {
			"protection_deployed": true,
		},
		"backup": {
			"phi_backed_up": true,
		},
		"vulnerability_management": {
			"scanning": true,
		},
		"patch_management": {
			"timely": true,
		},
		"network_monitoring": {
			"enabled": true,
		},
	},
	"secure_development": {
		"requirements": {
			"security_included": true,
		},
		"testing": {
			"security_testing": true,
		},
		"phi": {
			"no_phi_in_test": true,
		},
	},
	"access_management": {
		"phi": {
			"minimum_necessary": true,
		},
		"remote_access": {
			"controlled": true,
		},
		"wireless": {
			"secured": true,
		},
	},
	"audit": {
		"phi_access": {
			"logged": true,
		},
		"logs": {
			"protected_from_tampering": true,
			"retention_6_years": true,
		},
		"review": {
			"regular": true,
		},
	},
	"training": {
		"hipaa": {
			"all_workforce_annual": true,
		},
		"phi_handling": {
			"included": true,
		},
		"completion": {
			"tracked": true,
		},
	},
	"third_party": {
		"baa": {
			"executed": true,
		},
		"assessment": {
			"security_evaluation": true,
		},
		"contracts": {
			"security_requirements": true,
		},
	},
	"incident_response": {
		"plan": {
			"documented": true,
			"tested_annually": true,
		},
		"phi_breach": {
			"procedures": true,
		},
		"reporting": {
			"hhs_60_days": true,
		},
	},
	"business_continuity": {
		"bcp": {
			"documented": true,
			"tested": true,
		},
		"drp": {
			"phi_systems": true,
		},
	},
	"privacy": {
		"notice": {
			"provided_to_patients": true,
		},
		"minimum_necessary": {
			"enforced": true,
		},
		"patient_rights": {
			"process_exists": true,
		},
	},
}

# Every boolean leaf of the fixture, as a path.
_leaves := [path |
	walk(all_pass, [path, value])
	is_boolean(value)
]

_pointer(path) := concat("/", array.concat([""], path))

_field(path) := concat(".", array.concat(["input"], path))

_set(path, value) := json.patch(all_pass, [{"op": "replace", "path": _pointer(path), "value": value}])

_drop(path) := json.remove(all_pass, [_pointer(path)])

# The whole fixture with every boolean leaf replaced by one value.
_all_set(value) := json.patch(all_pass, [op |
	some path in _leaves
	op := {"op": "replace", "path": _pointer(path), "value": value}
])

# Values that are not the boolean true or false: each is a collection error, never a pass.
_wrong_types := ["false", "true", "no", "yes", 0, 1]

_named(violations, path, problem) if {
	some msg in violations
	contains(msg, _field(path))
	contains(msg, problem)
}

test_fixture_has_63_facts if count(_leaves) == 63

test_all_true_passes if {
	r := data.hitrust.main.compliance_report with input as all_pass
	r.compliant == true
	r.violation_count == 0
	r.failed_controls == 0
	r.failed_checks == 0
	r.total_controls == 59
	r.total_checks == 63
}

test_empty_input_fails_every_check_as_missing_evidence if {
	r := data.hitrust.main.compliance_report with input as {}
	r.compliant == false
	r.violation_count == 63
	r.failed_checks == 63
	every msg in r.violations {
		contains(msg, "evidence missing: input.")
	}
}

test_boolean_false_everywhere_keeps_plain_findings if {
	r := data.hitrust.main.compliance_report with input as _all_set(false)
	r.compliant == false
	r.violation_count == 63
	every msg in r.violations {
		not contains(msg, " — evidence missing: ")
		not contains(msg, " — evidence invalid: ")
	}
}

test_wrong_type_everywhere_fails_every_check if {
	every value in _wrong_types {
		r := data.hitrust.main.compliance_report with input as _all_set(value)
		r.compliant == false
		r.violation_count == 63
		every msg in r.violations {
			contains(msg, sprintf("is not a boolean (got %s)", [type_name(value)]))
		}
	}
}

test_null_everywhere_fails_every_check if {
	r := data.hitrust.main.compliance_report with input as _all_set(null)
	r.compliant == false
	r.violation_count == 63
	every msg in r.violations {
		contains(msg, "evidence missing: input.")
	}
}

# One fact at a time: each of the 63 facts, sent with the wrong type, fails its own check and only that one.
test_each_fact_with_wrong_type_fails_and_is_named if {
	every path in _leaves {
		every value in _wrong_types {
			r := data.hitrust.main.compliance_report with input as _set(path, value)
			r.compliant == false
			r.violation_count == 1
			_named(r.violations, path, "evidence invalid")
		}
	}
}

test_each_fact_null_or_removed_fails_and_is_named if {
	every path in _leaves {
		r1 := data.hitrust.main.compliance_report with input as _set(path, null)
		r1.compliant == false
		r1.violation_count == 1
		_named(r1.violations, path, "evidence missing")
		r2 := data.hitrust.main.compliance_report with input as _drop(path)
		r2.compliant == false
		r2.violation_count == 1
		_named(r2.violations, path, "evidence missing")
	}
}

test_each_fact_false_fails if {
	every path in _leaves {
		r := data.hitrust.main.compliance_report with input as _set(path, false)
		r.compliant == false
		r.violation_count == 1
	}
}

# A section sent as a string or null is missing evidence for every fact under it.
test_section_of_the_wrong_type_fails if {
	every value in ["false", null, true, []] {
		r := data.hitrust.main.compliance_report with input as object.union(all_pass, {"access_control": value})
		r.compliant == false
		r.violation_count == 7
	}
}

test_input_that_is_not_an_object_fails if {
	r := data.hitrust.main.compliance_report with input as "true"
	r.compliant == false
	r.violation_count == 63
}
