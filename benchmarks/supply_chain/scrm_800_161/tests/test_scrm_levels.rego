package supply_chain.scrm_800_161_levels_test

import rego.v1

# C-SCRM tailoring (SP 800-161r1-upd1 Appendix B, Table 6): counts pinned to
# what was measured from the PDF on 2026-10-13, plus the level gate.

tailoring := data.supply_chain.scrm_800_161.tailoring

test_tailoring_row_count if {
	count(tailoring) == 297
}

test_tailoring_counts_per_column if {
	counts := data.supply_chain.scrm_800_161.tailoring_counts with input as {}
	counts == {"baseline": 95, "flow_down": 69, "level_1": 76, "level_2": 236, "level_3": 251}
}

test_tailoring_rows_spot_check if {
	tailoring["ac-1"] == {"baseline": true, "flow_down": true, "level_1": true, "level_2": true, "level_3": true, "new_control": false}
	tailoring["ra-3.1"] == {"baseline": true, "flow_down": true, "level_1": true, "level_2": true, "level_3": true, "new_control": false}
	tailoring["pm-30"] == {"baseline": true, "flow_down": true, "level_1": true, "level_2": true, "level_3": false, "new_control": false}
	tailoring["sr-13"].new_control
	tailoring["ma-8"].new_control
	count([k | some k, r in tailoring; r.new_control]) == 2
}

test_absent_level_evaluates_level_3 if {
	report := data.supply_chain.scrm_800_161.report with input as {}
	report.level == "level_3"
	report.level_defaulted == true
	report.selected_control_count == 251
	count(report.violations) == 0
}

test_selected_level_1 if {
	report := data.supply_chain.scrm_800_161.report with input as {"scrm_800_161": {"level": "level_1"}}
	report.level == "level_1"
	report.level_defaulted == false
	report.selected_control_count == 76
	"pm-9" in report.selected_controls
	not "ac-2" in report.selected_controls
}

test_selected_flow_down if {
	report := data.supply_chain.scrm_800_161.report with input as {"scrm_800_161": {"level": "flow_down"}}
	report.selected_control_count == 69
}

test_invalid_level_is_violation if {
	report := data.supply_chain.scrm_800_161.report with input as {"scrm_800_161": {"level": "level_4"}}
	report.level == "level_3"
	some msg in report.violations
	contains(msg, "unrecognized input.scrm_800_161.level")
}

test_substrate_overlay_unchanged if {
	data.supply_chain.scrm_800_161.reuses_substrate == ["sbom", "provenance", "dependencies", "vulns"]
}
