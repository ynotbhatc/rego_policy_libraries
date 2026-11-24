package tests.crosswalk_framework_maps

import rego.v1

import data.crosswalk.framework_maps
import data.nist.sp800_53.index

# The 800-53 catalog ids the crosswalk carries (crosswalk/framework_maps/data.json, catalog_800_53) against the
# library's own NIST SP 800-53 module: every id the module evaluates, and every id of every baseline it knows, is
# an active control of the Rev 5.2.0 catalog. Needs frameworks/federal/nist/sp_800_53 loaded beside crosswalk/.

_active := {id | some id in framework_maps.catalog_800_53.active}

test_every_id_the_800_53_module_evaluates_is_in_the_catalog if {
	count(index.order) > 500
	bad := {id | some id in index.order; not id in _active}
	count(bad) == 0
}

test_every_baseline_id_is_in_the_catalog if {
	bad := {id | some _, ids in index.baselines; some id in ids; not id in _active}
	count(bad) == 0
}

# how much of each NIST-published map the module can speak to with its own evidence (not benchmark results)
test_mapped_ids_the_module_evaluates if {
	evaluated := {id | some id in index.order}
	share := {key: [count(ids & evaluated), count(ids)] |
		some key in ["nist_csf_2_0", "nist_800_171_r3", "iso_27001_2022"]
		ids := {c | some _, cs in framework_maps.maps[key].map; some c in cs}
	}
	every _, s in share {
		s[0] > 0
		s[0] <= s[1]
	}
}

# The maps' framework ids are the ids the library's own modules use, so a module can look its controls up in
# data.crosswalk.framework_overlay.control_evidence without translating an id. Needs
# frameworks/federal/nist/sp_800_171 and frameworks/federal/nist/cybersecurity_framework_2.0 loaded.
test_171_map_ids_are_the_171_module_requirement_ids if {
	object.keys(framework_maps.maps.nist_800_171_r3.map) == object.keys(data.nist_800_171.main.requirements)
	count(data.nist_800_171.main.requirements) == 97
}

test_csf_map_ids_are_the_csf_module_subcategory_ids if {
	object.keys(framework_maps.maps.nist_csf_2_0.map) == object.keys(data.nist.csf.main.subcategories)
	count(data.nist.csf.main.subcategories) == 106
}
