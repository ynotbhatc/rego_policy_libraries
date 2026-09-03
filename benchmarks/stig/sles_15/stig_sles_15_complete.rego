package stig.sles_15

# DISA STIG — SUSE Linux Enterprise Server 15 Security Technical Implementation Guide — Master Aggregator
# V2R8 | Release: 8 Benchmark Date: 01 Jul 2026
# Coverage: 27 of 218 rules (25 CAT I of 26); remainder is follow-up work.
# Rule IDs verified against the July 2026 SRG-STIG library on 2026-09-03.

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
		"version": "V2R8",
		"release": "Release: 8 Benchmark Date: 01 Jul 2026",
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
