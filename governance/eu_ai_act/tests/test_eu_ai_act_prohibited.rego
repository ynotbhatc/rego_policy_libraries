# Tests for eu_ai_act.prohibited — Reg. (EU) 2026/1744 additions.

package eu_ai_act.prohibited_test

import rego.v1

import data.eu_ai_act.prohibited

# ── Reg. (EU) 2026/1744 additions (apply 2026-12-02) ─────────────────────────

test_ncii_capability_without_safeguards_flagged if {
	inp := {"eu_ai_act": {"prohibited": {"intimate_imagery": {
		"can_generate_realistic_intimate_imagery": true,
		"effective_safeguards_prevent_output": false,
	}}}}
	v := prohibited.violations with input as inp
	count([m | some m in v; contains(m, "5(1)(ba)")]) == 1
}

test_ncii_safe_harbour_with_effective_safeguards if {
	inp := {"eu_ai_act": {"prohibited": {"intimate_imagery": {
		"can_generate_realistic_intimate_imagery": true,
		"effective_safeguards_prevent_output": true,
	}}}}
	v := prohibited.violations with input as inp
	count([m | some m in v; contains(m, "5(1)(ba)")]) == 0
}

test_ncii_actual_generation_always_flagged if {
	# Actual non-consensual generation is a violation regardless of safeguards.
	inp := {"eu_ai_act": {"prohibited": {"intimate_imagery": {
		"generated_without_consent": true,
		"effective_safeguards_prevent_output": true,
	}}}}
	v := prohibited.violations with input as inp
	count([m | some m in v; contains(m, "5(1)(ba)")]) == 1
}

test_csam_capability_without_safeguards_flagged if {
	inp := {"eu_ai_act": {"prohibited": {"csam": {
		"can_generate_csam": true,
		"effective_safeguards_prevent_output": false,
	}}}}
	v := prohibited.violations with input as inp
	count([m | some m in v; contains(m, "5(1)(bb)")]) == 1
}

test_csam_safe_harbour_with_effective_safeguards if {
	inp := {"eu_ai_act": {"prohibited": {"csam": {
		"can_generate_csam": true,
		"effective_safeguards_prevent_output": true,
	}}}}
	v := prohibited.violations with input as inp
	count([m | some m in v; contains(m, "5(1)(bb)")]) == 0
}

test_csam_actual_generation_always_flagged if {
	inp := {"eu_ai_act": {"prohibited": {"csam": {
		"generated_csam": true,
		"effective_safeguards_prevent_output": true,
	}}}}
	v := prohibited.violations with input as inp
	count([m | some m in v; contains(m, "5(1)(bb)")]) == 1
}
