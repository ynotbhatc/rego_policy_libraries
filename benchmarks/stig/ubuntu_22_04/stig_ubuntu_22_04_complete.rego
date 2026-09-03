package stig.ubuntu_22_04

# DISA STIG — Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide — Master Aggregator
# V2R9 | Release: 9 Benchmark Date: 01 Jul 2026
# Coverage: 22 of 188 rules (15 CAT I of 15); remainder is follow-up work.
# Rule IDs verified against the July 2026 SRG-STIG library on 2026-09-03.

import rego.v1

import data.stig.ubuntu_22_04.core

all_findings := core.findings

open_findings := [f | some f in all_findings; f.status == "Open"]
cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]

default overall_compliant := false
overall_compliant if count(cat_i_open) == 0
default fully_compliant := false
fully_compliant if count(open_findings) == 0

stig_assessment := {
	"metadata": {
		"stig_title": "Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide",
		"version": "V2R9",
		"release": "Release: 9 Benchmark Date: 01 Jul 2026",
		"platform": "Canonical Ubuntu 22.04 LTS",
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
