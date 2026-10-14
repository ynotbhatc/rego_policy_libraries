# Tests for RTS (EU) 2024/1774 (dora.rts_ict_risk): gate, entity roles, fail-closed contract, pinned counts.

package dora.rts_2024_1774_test

import rego.v1

import data.dora.main
import data.dora.rts_ict_risk as rts

_all_true := {id: true | some id, _ in rts.obligations}

_title(t) := {id: true | some id, r in rts.obligations; startswith(r.chapter, concat("", [t, "."]))}

_roles_none := {"central_counterparty": false, "central_securities_depository": false, "trading_venue": false, "microenterprise": false}

_t2(obl) := {"dora": {"rts": object.union(_roles_none, {"simplified_framework": false, "obligations": obl})}}

_has(v, s) if {
	some m in v
	contains(m, s)
}

test_row_counts_per_title_and_chapter if {
	count(rts.obligations) == 308
	count(rts.obligations_table) == 308
	rts.rows_by_title == {"II": 228, "III": 80}
	r := rts.compliance_report with input as {}
	{k: c.rows | some k, c in r.chapters} == {
		"II.I": 143, "II.II": 12, "II.III": 19, "II.IV": 41, "II.V": 13,
		"III.I": 28, "III.II": 29, "III.III": 14, "III.IV": 9,
	}
}

test_empty_input_fail_closed if {
	v := rts.violation with input as {}
	not rts.compliant with input as {}

	# gate + 4 undeclared roles + FAIL-CLOSED container + 206 Title II rows open without roles
	count(v) == 212
	_has(v, "simplified_framework must be declared")
	_has(v, "input.dora.rts.obligations missing or not an object")
	r := rts.compliance_report with input as {}
	r.gate.title_evaluated == "II"
	r.gate.simplified_framework == "undeclared"
	r.controls_evaluated == 206
}

test_all_true_title_ii_compliant if {
	inp := _t2(_all_true)
	rts.compliant with input as inp
	r := rts.compliance_report with input as inp
	r.controls_evaluated == 208 # 206 + the two "other than microenterprises" points
	r.attested == 208
	r.violation_count == 0
}

test_all_true_title_iii_compliant if {
	inp := {"dora": {"rts": {"simplified_framework": true, "obligations": _all_true}}}
	rts.compliant with input as inp
	r := rts.compliance_report with input as inp
	r.controls_evaluated == 80
	r.gate.title_evaluated == "III"
}

test_simplified_true_evaluates_only_title_iii if {
	inp := {"dora": {"rts": {"simplified_framework": true, "obligations": {}}}}
	v := rts.violation with input as inp
	count(v) == 80
	every m in v {
		regex.match(`^DORA RTS 2024/1774 Art\.(2[89]|3[0-9]|4[01])\(`, m)
	}
	r := rts.compliance_report with input as inp
	every k, c in r.chapters {
		c.evaluated == startswith(k, "III.")
	}
}

test_simplified_false_evaluates_only_title_ii if {
	v := rts.violation with input as _t2({})
	count(v) == 208
	not _has(v, "Art.28(")
	not _has(v, "Art.41(")
}

test_one_false_named if {
	v := rts.violation with input as _t2(object.union(_all_true, {"Art.7(2)": false}))
	count(v) == 1
	some m in v
	startswith(m, "DORA RTS 2024/1774 Art.7(2) (Cryptographic key management): Financial entities shall identify and implement controls")
	endswith(m, "— not attested")
}

test_point_message_carries_lead if {
	v := rts.violation with input as _t2(object.union(_all_true, {"Art.3(1)(a)": false}))
	v == {"DORA RTS 2024/1774 Art.3(1)(a) (ICT risk management): Financial entities shall develop, document, and implement ICT risk management policies and procedures that shall contain all of the following: an indication of the approval of the risk tolerance level for ICT risk established in accordance with Article 6(8), point (b), of Regulation (EU) 2022/2554; — not attested"}
}

test_string_true_is_not_attested if {
	v := rts.violation with input as _t2(object.union(_all_true, {"Art.21(1)(f)": "true"}))
	count(v) == 1
	_has(v, "Art.21(1)(f) (Access control)")
}

test_unknown_id_violation if {
	v := rts.violation with input as _t2(object.union(_all_true, {"Art.99(1)": true}))
	count(v) == 1
	_has(v, "attestation for unknown id Art.99(1)")
}

test_inactive_title_id_is_not_unknown if {
	inp := {"dora": {"rts": {"simplified_framework": true, "obligations": object.union(_title("III"), {"Art.2(1)(a)": true})}}}
	rts.compliant with input as inp
}

test_gate_absent_violation_and_title_ii if {
	inp := {"dora": {"rts": object.union(_roles_none, {"obligations": _all_true})}}
	v := rts.violation with input as inp
	count(v) == 1
	_has(v, "FAIL-CLOSED — input.dora.rts.simplified_framework must be declared")
	r := rts.compliance_report with input as inp
	r.gate.title_evaluated == "II"
	r.controls_evaluated == 208
}

test_gate_non_boolean_is_undeclared if {
	inp := {"dora": {"rts": object.union(_roles_none, {"simplified_framework": "true", "obligations": _all_true})}}
	v := rts.violation with input as inp
	count(v) == 1
	_has(v, "simplified_framework must be declared")
}

test_non_object_obligations_fail_closed if {
	v := rts.violation with input as _t2(["Art.3(1)(a)"])
	_has(v, "FAIL-CLOSED — input.dora.rts.obligations missing or not an object")
	count(v) == 209
}

test_roles_required_only_for_title_ii if {
	v2 := rts.violation with input as {"dora": {"rts": {"simplified_framework": false, "obligations": _all_true}}}
	count(v2) == 4
	_has(v2, "input.dora.rts.central_counterparty undeclared")
	v3 := rts.violation with input as {"dora": {"rts": {"simplified_framework": true, "obligations": _all_true}}}
	count(v3) == 0
}

test_ccp_rows_open_only_for_ccp if {
	inp := {"dora": {"rts": object.union(_roles_none, {"simplified_framework": false, "central_counterparty": true, "obligations": {}})}}
	r := rts.compliance_report with input as inp
	r.controls_evaluated == 217 # 208 + 8 central-counterparty rows + Art.17(2) (CCP or CSD)
	v := rts.violation with input as inp
	_has(v, "Art.24(2)(a) ")
	_has(v, "Art.17(2) ")
	not _has(v, "Art.24(3)(a) ")
}

test_microenterprise_closes_two_points if {
	inp := {"dora": {"rts": object.union(_roles_none, {"simplified_framework": false, "microenterprise": true, "obligations": {}})}}
	r := rts.compliance_report with input as inp
	r.controls_evaluated == 206
	v := rts.violation with input as inp
	not _has(v, "Art.4(2)(c) ")
}

test_main_aggregates_rts_2024_1774 if {
	v := main.violations with input as {}
	count([m | some m in v; contains(m, "RTS 2024/1774")]) == 212
	r := main.compliance_report with input as {}
	count(r.pillar_summary.rts_2024_1774_ict_risk_management) == 212
	r.rts_2024_1774_ict_risk_management.rows_by_title == {"II": 228, "III": 80}
	r.rts_2024_1774_ict_risk_management.gate.title_evaluated == "II"
	r.total_controls == 399
}

test_main_rts_2024_1774_not_in_level1_pillars if {
	r := main.compliance_report with input as {}
	every k in {"ict_risk_management", "incident_reporting", "resilience_testing", "third_party_risk", "information_sharing"} {
		every m in r.pillar_summary[k] {
			not contains(m, "RTS 2024/1774")
		}
	}
}

test_main_compliant_part_from_rts_when_all_attested if {
	inp := _t2(_all_true)
	v := main.violations with input as inp
	count([m | some m in v; contains(m, "RTS 2024/1774")]) == 0
}
