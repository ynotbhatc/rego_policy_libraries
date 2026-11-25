# Locked acceptance test (round 3). Do not edit; if a test is wrong, report it.
#
# fedramp.main, the two agency selectors: input.data_residency.us_only_required (turns SA-9(5) location on
# below High) and input.personnel_requirements.us_persons_required_for_admin (turns PS-3(3) on).
# Requirement (round 3 task list item 4; evidence rule in AGENT_BRIEF.md: "'Does not apply' must be an explicit
# statement in the input, never inferred from a missing field"): a selector that is absent, null or a string
# must not pass silently. Only the boolean false states "the agency does not require it".
# This supersedes tests/test_fedramp_levels.rego `test_selector_absent_null_or_false_states_no_agency_requirement`
# as far as it lets an absent or null selector pass with nothing said (false still passes).
#
# Fixtures: data.fedramp.levels_test.all_pass_moderate / all_pass_high, by reference. Both set both selectors
# to true.

package fedramp.acceptance_r3

import rego.v1

fixtures := {
	"moderate": data.fedramp.levels_test.all_pass_moderate,
	"high": data.fedramp.levels_test.all_pass_high,
}

# [section, selector, the check it selects]
selectors := [
	["data_residency", "us_only_required", "SA-9(5)"],
	["personnel_requirements", "us_persons_required_for_admin", "PS-3(3)"],
]

rep(inp) := r if {
	r := data.fedramp.main.compliance_report with input as inp
}

strings_of(r) := {s | walk(r, [_, s]); is_string(s)}

# some text of the report, not present in the report of the unmutated fixture, names the selector
names_selector(r, base, name) if {
	some s in (strings_of(r) - strings_of(base))
	contains(s, name)
}

# "not silent": the report is not compliant, or it carries new text naming the selector
not_silent(r, _, _) if r.compliant == false

not_silent(r, base, name) if names_selector(r, base, name)

# Requirement: both level fixtures pass unmutated with nothing failed (regression guard).
test_level_fixtures_pass if {
	every _, fx in fixtures {
		r := rep(fx)
		r.compliant == true
		r.violation_count == 0
		r.failed_controls == 0
		fx.data_residency.us_only_required == true
		fx.personnel_requirements.us_persons_required_for_admin == true
	}
}

# Requirement: a selector that is ABSENT does not pass silently, at Moderate and at High.
test_absent_selector_does_not_pass_silently if {
	every _, fx in fixtures {
		base := rep(fx)
		every s in selectors {
			not_silent(rep(json.remove(fx, [[s[0], s[1]]])), base, s[1])
		}
	}
}

# Requirement: a selector sent as NULL does not pass silently, at Moderate and at High.
test_null_selector_does_not_pass_silently if {
	every _, fx in fixtures {
		base := rep(fx)
		every s in selectors {
			not_silent(rep(json.patch(fx, [{"op": "replace", "path": [s[0], s[1]], "value": null}])), base, s[1])
		}
	}
}

# Requirement: a selector sent as a STRING ("true", "false", "yes", "") is invalid evidence: the report is not
# compliant, the selected check is among the failed ones and a finding names the selector. Source: the module's
# own selector rule ("any other value is a collection error: the check it selects is applied rather than
# skipped, and the value is reported as invalid evidence"), fedramp_main.rego.
test_string_selector_fails_and_names_the_selector if {
	every _, fx in fixtures {
		base := rep(fx)
		every s in selectors {
			every text in ["true", "false", "yes", ""] {
				r := rep(json.patch(fx, [{"op": "replace", "path": [s[0], s[1]], "value": text}]))
				r.compliant == false
				s[2] in r.failed_control_ids
				names_selector(r, base, s[1])
			}
		}
	}
}

# Requirement: the explicit statement still works - the boolean false passes with nothing failed (a selector
# is optional for the agency, not for the collector).
test_explicit_false_selector_passes if {
	every _, fx in fixtures {
		every s in selectors {
			r := rep(json.patch(fx, [{"op": "replace", "path": [s[0], s[1]], "value": false}]))
			r.compliant == true
			r.failed_controls == 0
		}
	}
}

# Requirement: with us_only_required true, missing location evidence fails SA-9(5) - either list removed, or
# data_residency holding nothing but the selector. Source: task list item 4; SA-9(5) evidence rule in the module.
test_location_evidence_removed_fails_sa_9_5 if {
	every _, fx in fixtures {
		variants := [
			json.remove(fx, [["data_residency", "storage_locations"]]),
			json.remove(fx, [["data_residency", "processing_locations"]]),
			json.patch(fx, [{"op": "replace", "path": ["data_residency"], "value": {"us_only_required": true}}]),
		]
		every inp in variants {
			r := rep(inp)
			r.compliant == false
			"SA-9(5)" in r.failed_control_ids
			r.failed_controls >= 1
		}
	}
}

# Requirement: removing the whole data_residency section never passes silently. At High SA-9(5) is fixed by
# FedRAMP and fails; at Moderate the selector went with the section, so the absent-selector rule applies.
test_data_residency_section_removed_does_not_pass if {
	high := rep(json.remove(fixtures.high, [["data_residency"]]))
	high.compliant == false
	"SA-9(5)" in high.failed_control_ids
	not_silent(rep(json.remove(fixtures.moderate, [["data_residency"]])), rep(fixtures.moderate), "us_only_required")
}

# Requirement: the same for the personnel_requirements section (it holds only the PS-3(3) selector).
test_personnel_requirements_section_removed_does_not_pass_silently if {
	every _, fx in fixtures {
		not_silent(rep(json.remove(fx, [["personnel_requirements"]])), rep(fx), "us_persons_required_for_admin")
	}
}
