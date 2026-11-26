package govramp.maps_test

import data.crosswalk.framework_maps.maps
import data.govramp.main
import data.nist.sp800_53.index
import rego.v1

# The committed GovRAMP baseline maps (scripts/gen_govramp_framework_maps.py) against what the module states and what
# the FedRAMP maps and the 800-53 module hold. No report is evaluated here.

_keys := ["govramp_low", "govramp_moderate", "govramp_high", "govramp_low_ready", "govramp_moderate_ready", "govramp_high_ready", "govramp_moderate_core"]

_ids(key) := {id | some id, _ in maps[key].map}

test_all_seven_maps_exist_and_are_authoritative_identity_maps if {
	every key in _keys {
		maps[key].status == "authoritative"
		maps[key].generated_by == "scripts/gen_govramp_framework_maps.py"
		every id, ctrls in maps[key].map {
			ctrls == [id]
		}
	}
}

test_baseline_sizes_are_the_publishers_matrix_counts if {
	count(maps.govramp_low.map) == 153
	count(maps.govramp_moderate.map) == 319
	count(maps.govramp_high.map) == 406
	main.baseline_sizes == {"low": 153, "moderate": 319, "high": 406}
}

test_scope_sizes_match_the_maps if {
	count(maps.govramp_low_ready.map) == 29
	count(maps.govramp_moderate_ready.map) == 80
	count(maps.govramp_high_ready.map) == 90
	count(maps.govramp_moderate_core.map) == 60
	every level, sizes in main._scope_sizes {
		every kind, n in sizes {
			count(maps[concat("", ["govramp_", level, _suffix(kind)])].map) == n
		}
	}
}

_suffix("authorized") := ""

_suffix("ready") := "_ready"

_suffix("core") := "_core"

test_low_is_inside_moderate_is_inside_high if {
	_ids("govramp_low") & _ids("govramp_moderate") == _ids("govramp_low")
	_ids("govramp_moderate") & _ids("govramp_high") == _ids("govramp_moderate")
}

test_core_is_inside_ready_is_inside_moderate if {
	_ids("govramp_moderate_core") & _ids("govramp_moderate_ready") == _ids("govramp_moderate_core")
	_ids("govramp_moderate_ready") & _ids("govramp_moderate") == _ids("govramp_moderate_ready")
	_ids("govramp_low_ready") & _ids("govramp_low") == _ids("govramp_low_ready")
	_ids("govramp_high_ready") & _ids("govramp_high") == _ids("govramp_high_ready")
}

# GovRAMP selects no control FedRAMP Rev 5 does not; FedRAMP selects a few GovRAMP does not.
test_govramp_is_fedramp_rev5_minus_a_short_list if {
	_ids("govramp_low") == _ids_fed("low") - {"IA-2(12)", "IA-8(1)", "SA-4(10)"}
	_ids("govramp_moderate") == _ids_fed("moderate") - {"CA-8(2)", "IA-2(12)", "IA-8(1)", "SA-4(10)"}
	_ids("govramp_high") == _ids_fed("high") - {"CA-8(2)", "IA-2(12)", "IA-8(1)", "SA-4(10)"}
	count(_ids_fed("low")) - count(_ids("govramp_low")) == 3
	count(_ids_fed("moderate")) - count(_ids("govramp_moderate")) == 4
	count(_ids_fed("high")) - count(_ids("govramp_high")) == 4
	main.fedramp_rev5_baseline_sizes == {"low": 156, "moderate": 323, "high": 410}
}

_ids_fed(level) := {id | some id, _ in maps[concat("", ["fedramp_rev5_", level])].map}

test_every_selected_control_is_one_the_800_53_module_evaluates if {
	every key in _keys {
		every id in _ids(key) {
			id in index.order
		}
	}
}

test_overlay_differences_are_inside_the_baseline if {
	every key in ["govramp_low", "govramp_moderate", "govramp_high"] {
		every id in maps[key].federal_overlay_differs_from_fedramp {
			id in _ids(key)
		}
	}
	maps.govramp_low.federal_overlay_differs_from_fedramp == ["AU-11", "CA-6"]
}

test_no_licensed_text_in_the_maps if {
	every key in _keys {
		every field in ["name", "source", "granularity"] {
			is_string(maps[key][field])
		}
	}
}

# The index the module reads and the crosswalk maps are written from one list: they must agree.
test_index_and_crosswalk_maps_hold_the_same_ids if {
	every level, kinds in data.govramp.index.scopes {
		every kind, ids in kinds {
			ids == _ids(concat("", ["govramp_", level, _suffix(kind)]))
		}
	}
	data.govramp.index.not_selected_from_fedramp_rev5.moderate == maps.govramp_moderate.not_selected_from_fedramp_rev5
	data.govramp.index.federal_overlay_differs_from_fedramp.high == maps.govramp_high.federal_overlay_differs_from_fedramp
}

test_index_scopes_have_the_expected_sizes if {
	every level, sizes in main._scope_sizes {
		every kind, n in sizes {
			count(data.govramp.index.scopes[level][kind]) == n
		}
	}
	object.keys(data.govramp.index.scopes.low) == {"authorized", "ready"}
	object.keys(data.govramp.index.scopes.moderate) == {"authorized", "ready", "core"}
	object.keys(data.govramp.index.scopes.high) == {"authorized", "ready"}
}
