# Conditional GDPR obligations (weekly audit 2026-11-23): an obligation that applies only on a condition
# is exempt only on the boolean false. A condition that is absent, null or not a boolean is missing
# evidence — the gate fails and the fact is listed under evidence_missing.
#
# Regulation (EU) 2016/679: Art. 8(1), Art. 9(1)-(2), Art. 22(1)-(4), Art. 26(1)-(3), Art. 37(1) and (7),
# Art. 38(2)-(3), Chapter V (Art. 44-49). ePrivacy Directive 2002/58/EC Art. 5(3) for the tracking gates.
package gdpr.applicability_test

import rego.v1

# One row per gate. `base` is the complete evidence for the applicable branch, without the condition
# itself; the condition lives at input[top][sec][flag].
gates := {
	"special_category_data": {
		"pkg": "compliance", "top": "gdpr", "sec": "special_category_data", "flag": "processed",
		"base": {"special_category_data": {
			"explicit_consent": true,
			"legal_basis": {"documented": true},
			"dpia": {"conducted": true},
			"additional_safeguards": {"implemented": true},
		}},
	},
	"dpo_requirements": {
		"pkg": "compliance", "top": "gdpr", "sec": "dpo", "flag": "mandatory",
		"base": {"dpo": {
			"appointed": true,
			"contact_details": {"published": true, "notified_to_supervisory_authority": true},
			"independence": {"guaranteed": true},
			"resources": {"adequate": true},
		}},
	},
	"international_transfers": {
		"pkg": "compliance", "top": "gdpr", "sec": "international_transfers", "flag": "occur",
		"base": {"international_transfers": {
			"adequacy_decision_or_safeguards": true,
			"mechanism": {"documented": true},
			"scc_or_bcr": {"implemented": true},
			"data_subjects": {"informed": true},
		}},
	},
	"joint_controller_arrangement": {
		"pkg": "controller_processor", "top": "gdpr", "sec": "joint_controllers", "flag": "arrangement_exists",
		"base": {"joint_controllers": {
			"agreement": {"documented": true, "essence_available_to_data_subjects": true},
			"responsibilities": {"defined": true},
			"data_subjects": {"can_exercise_rights_against_either": true},
			"contact_point": {"designated": true},
		}},
	},
	"fingerprinting_controlled": {
		"pkg": "cookies_tracking", "top": "cookies", "sec": "fingerprinting", "flag": "used",
		"base": {"fingerprinting": {
			"consent": {"obtained": true},
			"purpose": {"documented": true},
			"privacy_notice": {"disclosed": true},
		}},
	},
	"tracking_pixels_compliant": {
		"pkg": "cookies_tracking", "top": "cookies", "sec": "tracking_pixels", "flag": "used",
		"base": {"tracking_pixels": {
			"consent": {"obtained": true},
			"third_parties": {"disclosed": true},
		}},
	},
	"automated_decision_making": {
		"pkg": "cookies_tracking", "top": "profiling", "sec": "solely_automated_with_legal_effect", "flag": "used",
		"base": {
			"lawful_basis": {"one_of_three_bases": true},
			"data_subjects": {"informed": true, "right_to_human_review": true, "right_to_contest": true},
			"special_category_data": {"not_used_without_explicit_consent": true},
		},
	},
	"behavioural_advertising": {
		"pkg": "cookies_tracking", "top": "marketing", "sec": "behavioural_advertising", "flag": "used",
		"base": {"behavioural_advertising": {
			"consent": {"obtained": true},
			"profiling": {"disclosed": true},
			"opt_out": {"easy": true},
			"sensitive_categories": {"not_targeted": true},
		}},
	},
	"childrens_data": {
		"pkg": "cookies_tracking", "top": "gdpr", "sec": "childrens_data", "flag": "services_directed_at_children",
		"base": {"childrens_data": {
			"age_verification": {"implemented": true},
			"parental_consent": {"required_under_16": true, "verification": true},
			"privacy_notice": {"child_friendly": true},
			"behavioural_advertising": {"not_to_children": true},
			"profiling": {"not_to_children": true},
		}},
	},
}

# Full evidence, condition not stated.
unstated(g) := {g.top: g.base}

# Full evidence, condition stated as `value`.
stated(g, value) := {g.top: object.union(g.base, {g.sec: {g.flag: value}})}

# No evidence, condition stated as `value`.
bare(g, value) := {g.top: {g.sec: {g.flag: value}}}

# The package is spelled out per body: a computed package name is a recursion error in a test package
# that itself lives under data.gdpr.
passes(name, g, facts) if {
	g.pkg == "compliance"
	data.gdpr.compliance[name] with input as facts
}

passes(name, g, facts) if {
	g.pkg == "controller_processor"
	data.gdpr.controller_processor[name] with input as facts
}

passes(name, g, facts) if {
	g.pkg == "cookies_tracking"
	data.gdpr.cookies_tracking[name] with input as facts
}

status(name, g, facts) := s if {
	g.pkg == "compliance"
	s := data.gdpr.compliance.applicability[name] with input as facts
}

status(name, g, facts) := s if {
	g.pkg == "controller_processor"
	s := data.gdpr.controller_processor.applicability[name] with input as facts
}

status(name, g, facts) := s if {
	g.pkg == "cookies_tracking"
	s := data.gdpr.cookies_tracking.applicability[name] with input as facts
}

missing(name, g, facts) := found if {
	g.pkg == "compliance"
	found := [f |
		some f in data.gdpr.compliance.evidence_missing with input as facts
		f.control == name
	]
}

missing(name, g, facts) := found if {
	g.pkg == "controller_processor"
	found := [f |
		some f in data.gdpr.controller_processor.evidence_missing with input as facts
		f.control == name
	]
}

missing(name, g, facts) := found if {
	g.pkg == "cookies_tracking"
	found := [f |
		some f in data.gdpr.cookies_tracking.evidence_missing with input as facts
		f.control == name
	]
}

field(g) := sprintf("input.%v.%v.%v", [g.top, g.sec, g.flag])

# A gate that fails for missing evidence: not a pass, status evidence_missing, one finding naming the field.
fails_as_missing(name, g, facts) if {
	not passes(name, g, facts)
	status(name, g, facts) == "evidence_missing"
	found := missing(name, g, facts)
	count(found) == 1
	found[0].path == field(g)
	found[0].status == "evidence_missing"
	contains(found[0].title, field(g))
}

test_nine_gates_are_covered if {
	count(gates) == 9
	stated_gates := (object.keys(data.gdpr.compliance.applicability) | object.keys(data.gdpr.controller_processor.applicability)) | object.keys(data.gdpr.cookies_tracking.applicability)
	stated_gates == object.keys(gates)
}

test_condition_absent_on_empty_input_is_missing_evidence if {
	every name, g in gates {
		fails_as_missing(name, g, {})
	}
}

# The audit's case with everything else in place: the evidence is complete, the condition is not stated.
test_condition_absent_with_full_evidence_is_missing_evidence if {
	every name, g in gates {
		fails_as_missing(name, g, unstated(g))
	}
}

test_condition_null_is_missing_evidence if {
	every name, g in gates {
		fails_as_missing(name, g, stated(g, null))
		fails_as_missing(name, g, bare(g, null))
	}
}

test_section_null_or_wrong_type_is_missing_evidence if {
	every name, g in gates {
		fails_as_missing(name, g, {g.top: {g.sec: null}})
		fails_as_missing(name, g, {g.top: {g.sec: "none"}})
		fails_as_missing(name, g, {g.top: null})
	}
}

# A string is a collection error, not a statement: "false" does not exempt and "true" does not select the
# evidence branch, whatever evidence comes with it.
test_condition_string_is_missing_evidence if {
	every name, g in gates {
		fails_as_missing(name, g, bare(g, "false"))
		fails_as_missing(name, g, stated(g, "false"))
		fails_as_missing(name, g, stated(g, "true"))
		contains(missing(name, g, bare(g, "false"))[0].title, `got "false"`)
	}
}

test_condition_number_or_empty_object_is_missing_evidence if {
	every name, g in gates {
		fails_as_missing(name, g, stated(g, 0))
		fails_as_missing(name, g, stated(g, 1))
		fails_as_missing(name, g, stated(g, {}))
	}
}

test_explicit_false_is_the_only_exemption if {
	every name, g in gates {
		passes(name, g, bare(g, false))
		status(name, g, bare(g, false)) == "not_applicable"
		count(missing(name, g, bare(g, false))) == 0
	}
}

test_explicit_true_with_evidence_passes if {
	every name, g in gates {
		passes(name, g, stated(g, true))
		status(name, g, stated(g, true)) == "applicable"
		count(missing(name, g, stated(g, true))) == 0
	}
}

# Applicable and unevidenced is a failure of the obligation, not missing applicability evidence.
test_explicit_true_without_evidence_fails if {
	every name, g in gates {
		not passes(name, g, bare(g, true))
		status(name, g, bare(g, true)) == "applicable"
		count(missing(name, g, bare(g, true))) == 0
	}
}

# --- roll-up: an unstated condition blocks the module however complete the rest is ----------------------

test_core_not_compliant_when_one_condition_is_unstated if {
	full := data.gdpr.compliance_test.full_input
	data.gdpr.compliance.compliant with input as full
	every pointer in ["gdpr/special_category_data/processed", "gdpr/dpo/mandatory", "gdpr/international_transfers/occur"] {
		not data.gdpr.compliance.compliant with input as json.remove(full, [pointer])
	}
}

test_core_compliant_when_the_three_conditions_are_explicitly_false if {
	full := data.gdpr.compliance_test.full_input
	exempt := object.union(json.remove(full, ["gdpr/special_category_data", "gdpr/dpo", "gdpr/international_transfers"]), {"gdpr": {
		"special_category_data": {"processed": false},
		"dpo": {"mandatory": false},
		"international_transfers": {"occur": false},
	}})
	data.gdpr.compliance.compliant with input as exempt
	data.gdpr.compliance.report.evidence_missing == [] with input as exempt
}

test_reports_carry_applicability_and_evidence_missing if {
	core := data.gdpr.compliance.report with input as {}
	core.applicability == {
		"special_category_data": "evidence_missing",
		"dpo_requirements": "evidence_missing",
		"international_transfers": "evidence_missing",
	}
	[f.path | some f in core.evidence_missing] == [
		"input.gdpr.dpo.mandatory",
		"input.gdpr.international_transfers.occur",
		"input.gdpr.special_category_data.processed",
	]
	cp := data.gdpr.controller_processor.report with input as {}
	[f.article | some f in cp.evidence_missing] == ["Art. 26"]
	ct := data.gdpr.cookies_tracking.report with input as {}
	count(ct.evidence_missing) == 5
}

# --- aggregator -----------------------------------------------------------------------------------------

test_main_lists_every_unstated_condition_on_empty_input if {
	r := data.gdpr.main.compliance_report with input as {}
	r.compliant == false
	{f.path | some f in r.evidence_missing} == {field(g) | some g in gates}
	count(r.evidence_missing) == 9
	every f in r.evidence_missing {
		f.module in {"core_gdpr", "controller_processor", "cookies_and_tracking"}
	}
}

test_main_module_violation_names_the_missing_facts if {
	r := data.gdpr.main.compliance_report with input as {}
	core := [v | some v in r.violations; v.control == "core_gdpr"][0]
	sort(core.evidence_missing) == [
		"input.gdpr.dpo.mandatory",
		"input.gdpr.international_transfers.occur",
		"input.gdpr.special_category_data.processed",
	]
	contains(core.title, "evidence missing")
	contains(core.title, "input.gdpr.dpo.mandatory")
}

# failed_controls is counted from the violations, and the declared total covers every failing control.
test_main_counts_are_computed_and_consistent if {
	r := data.gdpr.main.compliance_report with input as {}
	failing := {v.control | some v in r.violations}
	r.failed_controls == count(failing)
	r.violation_count == count(r.violations)
	r.total_controls == 4
	r.total_controls >= r.failed_controls

	one := data.gdpr.main.compliance_report with input as {}
		with data.gdpr.compliance.compliant as true
		with data.gdpr.controller_processor.compliant as true
		with data.gdpr.cookies_tracking.compliant as true
	one.failed_controls == 1
	one.violations[0].control == "data_transfers"
}

# --- data transfers: a mechanism counts as in use only on the boolean true ------------------------------

bcr_evidence := {
	"approved_by_lead_dpa": true,
	"legally_binding": true,
	"covers_all_entities": true,
	"enforceable_by_data_subjects": true,
	"published": true,
	"dpo_responsible": true,
}

test_transfer_mechanism_flags_must_be_boolean if {
	data.gdpr.data_transfers.binding_corporate_rules with input as {"gdpr": {"transfers": {"bcr": object.union(bcr_evidence, {"used": true})}}}
	not data.gdpr.data_transfers.binding_corporate_rules with input as {"gdpr": {"transfers": {"bcr": object.union(bcr_evidence, {"used": "yes"})}}}
	not data.gdpr.data_transfers.binding_corporate_rules with input as {"gdpr": {"transfers": {"bcr": bcr_evidence}}}
	not data.gdpr.data_transfers.binding_corporate_rules with input as {"gdpr": {"transfers": {"bcr": {"used": "false"}}}}
	not data.gdpr.data_transfers.binding_corporate_rules with input as {"gdpr": {"transfers": {"bcr": {"used": null}}}}
	data.gdpr.data_transfers.binding_corporate_rules with input as {"gdpr": {"transfers": {"bcr": {"used": false}}}}
}

test_transfer_statement_gates_do_not_pass_unstated if {
	every facts in [{}, {"gdpr": {"transfers": null}}, {"gdpr": {"transfers": {"tia": {}, "bcr": {}, "us_transfers": {}, "derogations": {}}}}] {
		not data.gdpr.data_transfers.supplementary_measures with input as facts
		not data.gdpr.data_transfers.binding_corporate_rules with input as facts
		not data.gdpr.data_transfers.eu_us_dpf with input as facts
		not data.gdpr.data_transfers.derogation_if_used with input as facts
	}
}

test_us_transfer_and_derogation_flags_must_be_boolean if {
	us := {"mechanism": {"eu_us_dpf_or_scc": true}, "recipient": {"certified_or_scc_signed": true}, "dpf_certification": {"verified": true}}
	data.gdpr.data_transfers.eu_us_dpf with input as {"gdpr": {"transfers": {"us_transfers": object.union(us, {"occur": true})}}}
	not data.gdpr.data_transfers.eu_us_dpf with input as {"gdpr": {"transfers": {"us_transfers": object.union(us, {"occur": "true"})}}}
	der := {"basis": {"documented": true, "explicit_consent": true}}
	data.gdpr.data_transfers.derogation_if_used with input as {"gdpr": {"transfers": {"derogations": object.union(der, {"used": true})}}}
	not data.gdpr.data_transfers.derogation_if_used with input as {"gdpr": {"transfers": {"derogations": object.union(der, {"used": 1})}}}
}
