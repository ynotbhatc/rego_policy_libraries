# The control index is generated from data/cis_m365_v7_index.json by tools/cis_generators/gen_m365_v7_control_index.py.
# These tests hold its two tables to the benchmark's size and to each other, so a hand edit or a stale
# regeneration is caught here rather than in a report.
package cis_m365_v7.control_index_test

import rego.v1

import data.cis_m365_v7.control_index

_ids := [e.id | some e in control_index.CONTROL_INDEX]

test_one_entry_per_recommendation if {
	count(_ids) == 160
	count({id | some id in _ids}) == 160
}

test_every_entry_has_an_id_and_a_known_profile if {
	every e in control_index.CONTROL_INDEX {
		regex.match(`^[0-9]+(\.[0-9]+)+$`, e.id)
		count(e.profile) > 0
		every p in e.profile {
			p in {"E3 Level 1", "E3 Level 2", "E5 Level 1", "E5 Level 2"}
		}
	}
}

test_scope_covers_exactly_the_indexed_ids if {
	{id | some id, _ in control_index.CONTROL_SCOPE} == {id | some id in _ids}
}

test_scope_levels_are_one_or_two_and_agree_with_the_profile_tags if {
	every e in control_index.CONTROL_INDEX {
		scope := control_index.CONTROL_SCOPE[e.id]
		every tier, level in scope {
			tier in {"E3", "E5"}
			level in {1, 2}
			sprintf("%s Level %d", [tier, level]) in e.profile
		}
	}
}

# Every recommendation is in the E5 Level 2 scope; E3 is a subset.
test_e5_level_two_includes_everything if {
	every id in _ids {
		control_index.CONTROL_SCOPE[id].E5 in {1, 2}
	}
}
