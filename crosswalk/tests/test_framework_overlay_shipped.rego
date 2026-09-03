package crosswalk.framework_overlay_shipped_test

import rego.v1

import data.crosswalk.framework_overlay
import data.crosswalk.stig_800_53

# End-to-end against SHIPPED data: synthesize an all-passing finding for every
# STIG rule id in the crosswalk, then confirm the authoritative 800-53B
# baselines score with real coverage and honest not_covered gaps.
_all_pass_findings := [{"stig_id": sid, "status": "Not_a_Finding"} | some sid, _ in stig_800_53.map]

test_moderate_baseline_scores_with_real_coverage if {
	cov := framework_overlay.coverage["nist_800_53b_moderate"] with input as {"findings": _all_pass_findings}
	cov.controls_satisfied > 30 # ~54 base controls of the Moderate baseline touched
	count(cov.not_covered) > 0 # honest: the STIG spine does not cover the whole baseline
	cov.controls_total > 150 # the full Moderate base-control set
}

test_all_three_baselines_reported if {
	fr := framework_overlay.frameworks_reported with input as {"findings": _all_pass_findings}
	"nist_800_53b_low" in fr
	"nist_800_53b_moderate" in fr
	"nist_800_53b_high" in fr
}

test_pending_frameworks_listed_not_scored if {
	s := framework_overlay.summary with input as {"findings": _all_pass_findings}
	"pci_dss_v4" in s.frameworks_pending
	"cis_controls_v8" in s.frameworks_pending
	not s.coverage["pci_dss_v4"]
}
