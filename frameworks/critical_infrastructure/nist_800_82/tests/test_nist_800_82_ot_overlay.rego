package nist_800_82.main_ot_overlay_test

import rego.v1

# OT overlay (SP 800-82 Rev. 3 Appendix F, Table 22): counts pinned to what was
# measured from the PDF on 2026-10-13, plus the target_impact gate.

overlay := data.nist_800_82.main.ot_overlay

test_overlay_key_count if {
	count(overlay) == 424
}

test_overlay_counts_per_column if {
	counts := data.nist_800_82.main.ot_overlay_counts with input as {}
	counts == {"low": 194, "moderate": 338, "high": 421}
}

test_overlay_counts_without_org_wide_pm if {
	[k | some k, r in overlay; r.low; not r.org_wide] == [k | some k, r in overlay; r.low; not startswith(k, "pm-")]
	count([k | some k, r in overlay; r.low; not r.org_wide]) == 160
	count([k | some k, r in overlay; r.moderate; not r.org_wide]) == 304
	count([k | some k, r in overlay; r.high; not r.org_wide]) == 387
	count([k | some k, r in overlay; r.org_wide]) == 34
}

# 800-53B security baselines = overlay minus its additions plus its removals
test_overlay_reconciles_to_800_53b_baselines if {
	every lvl, n in {"low": 149, "moderate": 287, "high": 370} {
		count({k | some k, r in overlay; not r.org_wide; r[lvl]; not lvl in r.added_to} | {k | some k, r in overlay; lvl in r.removed_from}) == n
	}
}

test_overlay_struck_rows_are_false if {
	overlay["sc-10"] == {"low": false, "moderate": false, "high": false, "added_to": [], "removed_from": ["moderate", "high"], "org_wide": false}
	overlay["ca-8"].high
	not overlay["ca-8.1"].high
	overlay["ca-8.1"].removed_from == ["high"]
	overlay["si-8"].moderate
	not overlay["si-8.2"].moderate
}

test_overlay_additions if {
	overlay["ac-3.11"].added_to == ["high"]
	overlay["ia-3"].added_to == ["low"]
	overlay["sc-7.29"].added_to == ["low", "moderate", "high"]
	count([k | some k, r in overlay; count(r.added_to) > 0]) == 24
}

test_overlay_profiles_nested if {
	count([k | some k, r in overlay; r.moderate; not r.high]) == 0
	count([k | some k, r in overlay; r.low; not r.moderate]) == 0
}

test_absent_impact_evaluates_high if {
	report := data.nist_800_82.main.compliance_report with input as {}
	report.ot_overlay.target_impact == "high"
	report.ot_overlay.target_impact_defaulted == true
	report.ot_overlay.selected_control_count == 421
}

test_selected_impact_low if {
	report := data.nist_800_82.main.compliance_report with input as {"nist_800_82": {"target_impact": "low"}}
	report.ot_overlay.target_impact == "low"
	report.ot_overlay.target_impact_defaulted == false
	report.ot_overlay.selected_control_count == 194
	sel := data.nist_800_82.main.ot_overlay_selected with input as {"nist_800_82": {"target_impact": "low"}}
	"ac-17.9" in sel
	not "ac-17.10" in sel
}

test_invalid_impact_is_violation if {
	v := data.nist_800_82.main.violations with input as {"nist_800_82": {"target_impact": "extreme"}}
	some msg in v
	contains(msg, "unrecognized input.nist_800_82.target_impact")
	report := data.nist_800_82.main.compliance_report with input as {"nist_800_82": {"target_impact": "extreme"}}
	report.ot_overlay.target_impact == "high"
}

test_valid_impact_adds_no_violation if {
	v := data.nist_800_82.main.violations with input as {"nist_800_82": {"target_impact": "moderate"}}
	count(v) == 35
}

test_existing_checks_unchanged_on_empty_input if {
	v := data.nist_800_82.main.violations with input as {}
	count(v) == 35
	report := data.nist_800_82.main.compliance_report with input as {}
	report.total_controls == 32
	report.compliant == false
}
