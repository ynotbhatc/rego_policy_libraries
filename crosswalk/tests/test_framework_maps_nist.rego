package crosswalk.framework_maps_nist_test

import rego.v1

import data.crosswalk.framework_maps
import data.crosswalk.framework_overlay
import data.crosswalk.stig_800_53

# The NIST-published maps of crosswalk/framework_maps/data.json (scripts/gen_nist_framework_maps.py), tested
# against the SHIPPED data: sizes, provenance, every mapped id against the 800-53 catalog the file carries, and a
# worked example from a STIG rule result to a CSF Subcategory, a 171 requirement and an ISO control.
# Run from the repository root (the data must sit at data.crosswalk.*).

_generated := {"nist_csf_2_0", "nist_800_171_r3", "iso_27001_2022"}

_active := {id | some id in framework_maps.catalog_800_53.active}

_withdrawn := {id | some id in framework_maps.catalog_800_53.withdrawn}

_pairs(key) := sum([count(ctrls) | some _, ctrls in framework_maps.maps[key].map])

# ---- sizes, as the sources give them
test_row_counts if {
	count(framework_maps.maps.nist_csf_2_0.map) == 106
	_pairs("nist_csf_2_0") == 736
	count(framework_maps.maps.nist_800_171_r3.map) == 97
	_pairs("nist_800_171_r3") == 157
	count(framework_maps.maps.iso_27001_2022.map) == 121
	_pairs("iso_27001_2022") == 643
	count([k | some k, _ in framework_maps.maps.iso_27001_2022.map; startswith(k, "A.")]) == 91
}

test_recorded_counts_match_the_maps if {
	every key in _generated {
		c := framework_maps.maps[key].meta.counts
		c.framework_ids == count(framework_maps.maps[key].map)
		c.pairs == _pairs(key)
		c.distinct_800_53_ids == count({x | some _, xs in framework_maps.maps[key].map; some x in xs})
	}
}

test_catalog_size if {
	count(_active) == 1014
	count(_withdrawn) == 182
	count(_active & _withdrawn) == 0
	count(framework_maps.catalog_800_53.active) == 1014 # no id listed twice
	count([id | some id in _active; not contains(id, "(")]) == 300
	"SA-24" in _active # new in Rev 5.2.0
	"RA-4" in _withdrawn
}

# ---- provenance: source URL, sha256, publication date and licence on every generated map and on the catalog
test_generated_maps_cite_their_source if {
	every key in _generated {
		spec := framework_maps.maps[key]
		spec.status == "authoritative"
		spec.generated_by == "scripts/gen_nist_framework_maps.py"
		startswith(spec.meta.source_url, "https://csrc.nist.gov/")
		regex.match(`^[0-9a-f]{64}$`, spec.meta.source_sha256)
		regex.match(`^[0-9a-f]{64}$`, spec.meta.map_sha256)
		regex.match(`^20[0-9]{2}-[0-9]{2}(-[0-9]{2})?$`, spec.meta.publication_date)
		contains(spec.meta.publisher, "NIST")
		contains(spec.meta.licence, "US government")
		contains(spec.source, spec.meta.source_sha256)
	}
	cat := framework_maps.catalog_800_53
	startswith(cat.meta.source_url, "https://raw.githubusercontent.com/usnistgov/oscal-content/")
	regex.match(`^[0-9a-f]{64}$`, cat.meta.source_sha256)
}

# ---- every mapped id exists in the catalog, for every map in the file (baselines and FedRAMP included)
test_every_mapped_id_is_an_active_catalog_control if {
	bad := {sprintf("%s %s -> %s", [key, fc, c]) |
		some key, spec in framework_maps.maps
		some fc, ctrls in spec.map
		some c in ctrls
		not c in _active
	}
	count(bad) == 0
}

test_every_spine_control_is_an_active_catalog_control if {
	bad := {c | some _, ctrls in stig_800_53.map; some c in ctrls; not c in _active}
	count(bad) == 0
}

# ---- no orphans: every framework id is well formed and maps to at least one control, listed once
_id_shape := {
	"nist_csf_2_0": `^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-[0-9]{2}$`,
	"nist_800_171_r3": `^03\.[0-9]{2}\.[0-9]{2}$`,
	"iso_27001_2022": `^(A\.[5-8]\.[0-9]{1,2}|([4-9]|10)\.[0-9](\.[0-9])?)$`,
}

test_no_orphan_ids if {
	every key in _generated {
		every fc, ctrls in framework_maps.maps[key].map {
			regex.match(_id_shape[key], fc)
			count(ctrls) > 0
			count(ctrls) == count({c | some c in ctrls})
		}
	}
}

test_withdrawn_references_are_listed_not_mapped if {
	framework_maps.maps.nist_csf_2_0.meta.withdrawn_references_not_carried == ["DE.AE-06 -> RA-4"]
	not "RA-4" in framework_maps.maps.nist_csf_2_0.map["DE.AE-06"]
	framework_maps.maps.nist_800_171_r3.meta.withdrawn_references_not_carried == []
	framework_maps.maps.iso_27001_2022.meta.withdrawn_references_not_carried == []
}

# 800-171 Rev 3 has 97 requirements; the 33 withdrawn ones are not in the map
test_171_carries_the_97_current_requirements if {
	c := framework_maps.maps.nist_800_171_r3.meta.counts
	c.requirements_in_source == 130
	c.requirements_withdrawn_not_carried == 33
	framework_maps.maps.nist_800_171_r3.map["03.01.01"] == ["AC-2", "AC-2(3)", "AC-2(5)", "AC-2(13)"]
	count(framework_maps.maps.nist_800_171_r3.map["03.15.01"]) == 17 # the -1 policy control of 17 families
	not framework_maps.maps.nist_800_171_r3.map["03.01.13"] # withdrawn
}

# ---- what is not shipped stays pending, empty and unscored
test_pending_maps_stay_empty_with_the_reason if {
	every key in {"pci_dss_v4", "cis_controls_v8"} {
		framework_maps.maps[key].status == "pending"
		framework_maps.maps[key].map == {}
	}
	contains(framework_maps.maps.cis_controls_v8.source, "CC BY-NC-ND 4.0")
	contains(framework_maps.maps.cis_controls_v8.source, "--cis-file")
	s := framework_overlay.summary with input as {}
	s.frameworks_pending == ["cis_controls_v8", "pci_dss_v4"]
	every key in _generated {
		key in s.frameworks_reported
	}
}

# ---- worked example: one RHEL 9 STIG rule (account lockout) -> AC-7 -> 171 03.01.08, CSF PR.AA-03, ISO A.8.5
test_worked_example_the_maps_agree_on_the_path if {
	stig_800_53.map["RHEL-09-411075"] == ["AC-7"]
	framework_maps.maps.nist_800_171_r3.map["03.01.08"] == ["AC-7"]
	"AC-7" in framework_maps.maps.nist_csf_2_0.map["PR.AA-03"]
	framework_maps.maps.iso_27001_2022.map["A.8.5"] == ["AC-7", "AC-8", "AC-9", "IA-6"]
	framework_overlay.inherited_by.nist_800_171_r3["AC-7"] == ["03.01.08"]
	framework_overlay.inherited_by.nist_csf_2_0["AC-7"] == ["PR.AA-03"]
	framework_overlay.inherited_by.iso_27001_2022["AC-7"] == ["A.8.5"]
}

_open := {"findings": [{"stig_id": "RHEL-09-411075", "status": "Open"}]}

_pass := {"findings": [{"stig_id": "RHEL-09-411075", "status": "Not_a_Finding"}]}

test_worked_example_open_rule_is_a_gap_in_all_three if {
	ev := framework_overlay.control_evidence with input as _open
	r := ev.nist_800_171_r3["03.01.08"]
	r.status == "gap"
	r.spine == {"AC-7": {"status": "gap", "rules": ["RHEL-09-411075"], "open_rules": ["RHEL-09-411075"], "not_reviewed_rules": []}}
	r.not_evaluated == []
	ev.nist_csf_2_0["PR.AA-03"].status == "gap"
	ev.nist_csf_2_0["PR.AA-03"].spine["AC-7"].open_rules == ["RHEL-09-411075"]
	ev.iso_27001_2022["A.8.5"].status == "gap"

	# and nothing else in those frameworks is touched by this one rule
	{fc | some fc, e in ev.nist_800_171_r3; e.status != "not_covered"} == {"03.01.08"}
	{fc | some fc, e in ev.nist_csf_2_0; e.status != "not_covered"} == {"PR.AA-03"}
	{fc | some fc, e in ev.iso_27001_2022; e.status != "not_covered"} == {"A.8.5"}
}

test_worked_example_passing_rule_satisfies_only_what_it_wholly_covers if {
	ev := framework_overlay.control_evidence with input as _pass

	# 03.01.08 maps to AC-7 alone: the rule's verdict is the whole of the mapped evidence
	ev.nist_800_171_r3["03.01.08"].status == "satisfied"

	# PR.AA-03 and A.8.5 map to more controls than this rule speaks to: recorded, never a pass
	csf := ev.nist_csf_2_0["PR.AA-03"]
	csf.status == "not_covered"
	csf.spine["AC-7"].status == "satisfied"
	csf.not_evaluated == ["AC-12", "IA-10", "IA-11", "IA-2", "IA-3", "IA-5", "IA-7", "IA-8", "IA-9"]
	iso := ev.iso_27001_2022["A.8.5"]
	iso.status == "not_covered"
	iso.not_evaluated == ["AC-8", "AC-9", "IA-6"]
}

# a requirement that maps to an enhancement is never satisfied through the base-control spine
test_enhancement_keeps_a_requirement_from_satisfied if {
	all_pass := {"findings": [{"stig_id": sid, "status": "Not_a_Finding"} | some sid, _ in stig_800_53.map]}
	ev := framework_overlay.control_evidence.nist_800_171_r3["03.01.01"] with input as all_pass
	ev.status == "not_covered"
	ev.spine["AC-2"].status == "satisfied"
	ev.not_evaluated == ["AC-2(13)", "AC-2(3)", "AC-2(5)"]
}

# ---- measured reach of the shipped STIG spine (65 base controls) into each map; reach is not compliance
test_measured_reach_with_every_stig_rule_passing if {
	all_pass := {"findings": [{"stig_id": sid, "status": "Not_a_Finding"} | some sid, _ in stig_800_53.map]}
	cov := framework_overlay.coverage with input as all_pass
	reached := {key: count([fc | some fc, e in framework_overlay.control_evidence[key]; count(e.spine) > 0]) | some key in _generated} with input as all_pass
	reached == {"nist_csf_2_0": 30, "nist_800_171_r3": 42, "iso_27001_2022": 38}
	cov.nist_csf_2_0.controls_satisfied == 2
	cov.nist_800_171_r3.controls_satisfied == 26
	cov.iso_27001_2022.controls_satisfied == 11
	every key in _generated {
		c := cov[key]
		c.controls_total == (count(c.satisfied) + count(c.gaps)) + count(c.not_covered)
		count(c.gaps) == 0
	}
}

test_map_info_carries_the_citation if {
	info := framework_overlay.map_info
	not info.nist_csf_2_0.map
	info.nist_csf_2_0.meta.source_sha256 == framework_maps.maps.nist_csf_2_0.meta.source_sha256
	contains(info.iso_27001_2022.meta.relationship, "equivalency must not be assumed")
	not info.pci_dss_v4
}
