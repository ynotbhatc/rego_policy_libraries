package technical_debt.scoring_fixes_test

import rego.v1

ds := data.technical_debt.scoring

mk(fw, vs) := {"hostname": "h1", "framework": fw, "violations": vs}

test_nerc_versioned_standard_id_matches_catalog if {
	items := ds.debt_items with input as mk("nerc_cip", ["CIP-007-6 R2: patching"])
	some item in items
	item.effort_hours == 16
	item.debt_category == "critical_infrastructure"
}

test_nerc_plain_id_matches_catalog if {
	items := ds.debt_items with input as mk("nerc_cip", ["CIP-003: policy"])
	some item in items
	item.effort_hours == 24
}

test_sec_key_both_markers_no_conflict if {
	items := ds.debt_items with input as mk("sec_cyber", ["SEC Cyber Rule Item 1.05 and §229.106(c)(1): x"])
	count(items) == 1
}

test_object_violation_without_control_is_kept if {
	items := ds.debt_items with input as mk("digital_sovereignty", [{"description": "orphan finding", "severity": "high"}])
	count(items) == 1
	some item in items
	item.violation == "orphan finding"
	item.severity == "HIGH"
}

test_object_violation_without_any_id_or_description_is_kept if {
	items := ds.debt_items with input as mk("digital_sovereignty", [{"severity": "high"}])
	count(items) == 1
}

test_object_violation_dropped_not_counted_in_score if {
	r := ds.debt_report with input as mk("digital_sovereignty", [{"description": "orphan finding"}])
	r.total_violations == 1
	r.debt_score > 0
}

test_string_age_uses_30_89_tier if {
	numeric := ds.debt_score with input as object.union(mk("nerc_cip", ["CIP-007: x"]), {"debt_age_days": 45})
	as_string := ds.debt_score with input as object.union(mk("nerc_cip", ["CIP-007: x"]), {"debt_age_days": "45"})
	numeric == as_string
}

# Functions in other modules cannot be referenced by the standalone pre-commit
# `opa check`, so the age tiers are pinned through the scored output instead.
score_at(age) := s if {
	s := ds.debt_score with input as object.union(mk("nerc_cip", ["CIP-007: x"]), {"debt_age_days": age})
}

test_age_tiers if {
	base := score_at(10)
	score_at(45) == base * 1.25
	score_at(120) == base * 1.5
}

test_age_junk_string_counts_as_zero if score_at("soon") == score_at(0)

test_debt_report_empty_when_no_violations if ds.debt_report == {} with input as mk("nerc_cip", [])
