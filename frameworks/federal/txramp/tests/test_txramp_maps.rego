package txramp.maps_test

import data.crosswalk.framework_maps.maps
import data.nist.sp800_53.index
import data.txramp.index as txramp_index
import data.txramp.main
import rego.v1

# The committed TX-RAMP baseline maps (scripts/gen_txramp_framework_maps.py) against what the module states and what
# the 800-53 module holds. No report is evaluated here.

_keys := ["txramp_level_1", "txramp_level_2"]

_ids(key) := {id | some id, _ in maps[key].map}

test_both_maps_exist_and_are_authoritative_identity_maps if {
	every key in _keys {
		maps[key].status == "authoritative"
		maps[key].generated_by == "scripts/gen_txramp_framework_maps.py"
		every id, ctrls in maps[key].map {
			ctrls == [id]
		}
	}
}

# Appendix A of Program Manual 4.0: 117 and 223.
test_baseline_sizes_are_the_published_counts if {
	count(maps.txramp_level_1.map) == 117
	count(maps.txramp_level_2.map) == 223
	main.baseline_sizes == {"level_1": 117, "level_2": 223}
}

test_level_1_is_inside_level_2 if {
	_ids("txramp_level_1") & _ids("txramp_level_2") == _ids("txramp_level_1")
}

# The published per-family counts (Appendix A), Level 1 then Level 2.
_families := {
	"AC": [9, 33], "AU": [10, 11], "AT": [4, 6], "CM": [9, 21], "CP": [6, 11], "IA": [10, 16], "IR": [7, 10],
	"MA": [4, 9], "MP": [4, 7], "PS": [8, 8], "PE": [9, 17], "PL": [3, 5], "RA": [6, 8], "CA": [8, 9],
	"SC": [8, 23], "SI": [6, 13], "SA": [6, 16],
}

test_family_counts_are_the_published_ones if {
	every fam, n in _families {
		count({id | some id in _ids("txramp_level_1"); startswith(id, concat("", [fam, "-"]))}) == n[0]
		count({id | some id in _ids("txramp_level_2"); startswith(id, concat("", [fam, "-"]))}) == n[1]
	}
}

test_the_index_equals_the_crosswalk_maps if {
	txramp_index.scopes.level_1 == _ids("txramp_level_1")
	txramp_index.scopes.level_2 == _ids("txramp_level_2")
}

test_control_index_lists_every_level_2_control_as_the_findings_write_it if {
	{c.id | some c in txramp_index.CONTROL_INDEX} == {concat("", ["TX-RAMP ", id]) | some id in _ids("txramp_level_2")}
	count(txramp_index.CONTROL_INDEX) == 223
}

# Every TX-RAMP control is one the 800-53 module evaluates (AC-17(9) and SA-10(1), which only Level 2 selects, were added
# to it for this framework).
test_every_control_has_an_800_53_check if {
	every id in _ids("txramp_level_2") {
		id in index.order
	}
	"AC-17(9)" in _ids("txramp_level_2")
	"SA-10(1)" in _ids("txramp_level_2")
}
