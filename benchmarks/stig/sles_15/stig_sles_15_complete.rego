# METADATA
# title: "The SUSE operating system must not allow unattended or automatic logon via SSH. — Master Aggregator"
# custom:
#   class: security
#   framework: stig_sles_15
#   source: disa
#   domains: [linux, sles]
#   coverage:
#     checks: 2
#     cited: 2
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package stig.sles_15

# DISA STIG — SUSE Linux Enterprise Server 15 Security Technical Implementation Guide — Master Aggregator
# V2R9 | Release: 9 Benchmark Date: 30 Sep 2026
# Coverage: 27 of 220 rules (25 CAT I of 26); remainder is follow-up work.
# Rule IDs verified against the October 2026 SRG-STIG library on 2026-11-10.

import rego.v1

import data.stig.sles_15.core

all_findings := core.findings

open_findings := [f | some f in all_findings; f.status == "Open"]
cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]

default overall_compliant := false

overall_compliant if count(cat_i_open) == 0

default fully_compliant := false

fully_compliant if count(open_findings) == 0

stig_assessment := {
	"metadata": {
		"stig_title": "SUSE Linux Enterprise Server 15 Security Technical Implementation Guide",
		"version": "V2R9",
		"release": "Release: 9 Benchmark Date: 30 Sep 2026",
		"platform": "SUSE Linux Enterprise Server 15",
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
