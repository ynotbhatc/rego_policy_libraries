# METADATA
# title: "Ubuntu 24.04 LTS must be a vendor-supported release. — Master Aggregator"
# custom:
#   class: security
#   framework: stig_ubuntu_24_04
#   source: disa
#   domains: [linux, ubuntu]
#   coverage:
#     checks: 2
#     cited: 2
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.ubuntu_24_04

# DISA STIG — Canonical Ubuntu 24.04 LTS Security Technical Implementation Guide — Master Aggregator
# V1R7 | Release: 7 Benchmark Date: 30 Sep 2026
# Coverage: 22 of 195 rules (15 CAT I of 17); remainder is follow-up work.
# Rule IDs verified against the October 2026 SRG-STIG library on 2026-11-10.

import rego.v1

import data.stig.ubuntu_24_04.core

all_findings := core.findings

open_findings := [f | some f in all_findings; f.status == "Open"]
cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]

default overall_compliant := false

overall_compliant if count(cat_i_open) == 0

default fully_compliant := false

fully_compliant if count(open_findings) == 0

stig_assessment := {
	"metadata": {
		"stig_title": "Canonical Ubuntu 24.04 LTS Security Technical Implementation Guide",
		"version": "V1R7",
		"release": "Release: 7 Benchmark Date: 30 Sep 2026",
		"platform": "Canonical Ubuntu 24.04 LTS",
		"assessed_host": object.get(input, ["system_info", "hostname"], "unknown"),
	},
	"summary": {
		"total_findings": count(all_findings),
		"open": count(open_findings),
		"not_a_finding": count(all_findings) - count(open_findings),
		"cat_i_open": count(cat_i_open),
		"overall_compliant": overall_compliant,
		"fully_compliant": fully_compliant,
	},
	"findings": all_findings,
}

# Uniform library entrypoint contract (consumed by the .main alias's
# fail-closed gate): total_controls + open_findings are required.
compliance_report := {
	"total_controls": count(all_findings),
	"open_findings": open_findings,
	"passed_controls": count(all_findings) - count(open_findings),
	"failed_controls": count(open_findings),
	"compliant": fully_compliant,
}
