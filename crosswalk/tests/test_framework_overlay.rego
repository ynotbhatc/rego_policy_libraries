package crosswalk.framework_overlay_test

import rego.v1

import data.crosswalk.framework_overlay

# Deterministic test doubles for both the spine crosswalk and the framework
# maps, so the test is independent of shipped data volume.
sample_stig_map := {
	"RULE-A": ["AC-17", "SC-28"],
	"RULE-B": ["AC-17"],
	"RULE-C": ["AU-3"],
}

sample_fw_maps := {
	"demo_authoritative": {
		"name": "Demo FW",
		"source": "test",
		"status": "authoritative",
		"map": {
			"REQ-1": ["SC-28"], # only satisfied spine control → satisfied
			"REQ-2": ["AC-17"], # AC-17 is a gap (RULE-B open) → gap
			"REQ-3": ["CP-9"], # never evaluated → not_covered
		},
	},
	"demo_pending": {
		"name": "Pending FW",
		"source": "none yet",
		"status": "pending",
		"map": {"X": ["AC-17"]},
	},
}

findings := [
	{"stig_id": "RULE-A", "status": "Not_a_Finding"},
	{"stig_id": "RULE-B", "status": "Open"},
	{"stig_id": "RULE-C", "status": "Not_a_Finding"},
]

_with := {"input": {"findings": findings}}

test_authoritative_framework_scored if {
	cov := framework_overlay.coverage.demo_authoritative with input as {"findings": findings}
		with data.crosswalk.stig_800_53.map as sample_stig_map
		with data.crosswalk.framework_maps.maps as sample_fw_maps
	cov.satisfied == ["REQ-1"]
	cov.gaps == ["REQ-2"]
	cov.not_covered == ["REQ-3"]
	cov.controls_total == 3
	cov.controls_satisfied == 1
}

test_pending_framework_never_scored if {
	s := framework_overlay.summary with input as {"findings": findings}
		with data.crosswalk.stig_800_53.map as sample_stig_map
		with data.crosswalk.framework_maps.maps as sample_fw_maps
	s.frameworks_reported == ["demo_authoritative"]
	s.frameworks_pending == ["demo_pending"]
	not s.coverage.demo_pending
}

test_no_framework_maps_is_safe if {
	s := framework_overlay.summary with input as {"findings": findings}
		with data.crosswalk.stig_800_53.map as sample_stig_map
		with data.crosswalk.framework_maps.maps as {}
	s.frameworks_reported == []
	count(s.spine.satisfied) > 0 # spine still works with no overlays
}

# Semantic review 2026-11-13: a framework control mapped to one evaluated and one never-evaluated spine
# control must land in not_covered, so satisfied + gaps + not_covered always equals controls_total.
test_partially_evaluated_control_is_not_covered if {
	fw := {"demo_partial": {
		"name": "Partial FW",
		"source": "test",
		"status": "authoritative",
		"map": {"REQ-P": ["SC-28", "CP-9"]},
	}}
	cov := framework_overlay.coverage.demo_partial with input as {"findings": findings}
		with data.crosswalk.stig_800_53.map as sample_stig_map
		with data.crosswalk.framework_maps.maps as fw
	cov.not_covered == ["REQ-P"]
	(count(cov.satisfied) + count(cov.gaps)) + count(cov.not_covered) == cov.controls_total
}
