# Tests for the 2025 level-2 RTS modules and their aggregation.

package dora.rts_test

import rego.v1

import data.dora.main
import data.dora.rts_subcontracting
import data.dora.rts_tlpt

test_subcontracting_fails_closed_empty if {
	count(rts_subcontracting.violation) == 30 with input as {}
	not rts_subcontracting.compliant with input as {}
}

test_tlpt_fails_closed_empty if {
	count(rts_tlpt.violation) == 31 with input as {}
	not rts_tlpt.compliant with input as {}
}

test_subcontracting_flip if {
	inp := {"third_party_risk": {"subcontracting": {"due_diligence": {"full_chain_identified": true}}}}
	v := rts_subcontracting.violation with input as inp
	count(v) == 29
	count([m | some m in v; contains(m, "Art.3(1)(b)")]) == 0
}

test_tlpt_flip if {
	inp := {"resilience_testing": {"tlpt": {"red_team": {"active_phase_min_12_weeks": true}}}}
	v := rts_tlpt.violation with input as inp
	count(v) == 30
	count([m | some m in v; contains(m, "Art.11(5)")]) == 0
}

test_string_true_fails_closed if {
	inp := {"resilience_testing": {"tlpt": {"attestation": {"obtained": "true"}}}}
	v := rts_tlpt.violation with input as inp
	count([m | some m in v; contains(m, "RTS 2025/1190 Art.14")]) == 1
}

test_main_aggregates_rts if {
	v := main.violations with input as {}
	count([m | some m in v; contains(m, "RTS 2025/532")]) == 30
	count([m | some m in v; contains(m, "RTS 2025/1190")]) == 31
}

test_rts_messages_not_misbucketed_into_pillars if {
	r := main.compliance_report with input as {}
	every _, pv in {
		"p1": r.pillar_summary.ict_risk_management,
		"p2": r.pillar_summary.incident_reporting,
		"p3": r.pillar_summary.resilience_testing,
		"p4": r.pillar_summary.third_party_risk,
		"p5": r.pillar_summary.information_sharing,
	} {
		every m in pv {
			not contains(m, "RTS 2025/")
		}
	}
}

test_report_rts_buckets_populated if {
	r := main.compliance_report with input as {}
	count(r.pillar_summary.rts_2025_532_subcontracting) == 30
	count(r.pillar_summary.rts_2025_1190_tlpt) == 31
	r.total_controls == 91
}
