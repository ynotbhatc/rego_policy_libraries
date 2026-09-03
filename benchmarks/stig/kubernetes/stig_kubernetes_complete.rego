package stig.kubernetes

# DISA STIG — Kubernetes Security Technical Implementation Guide — Master Aggregator
# V2R6 | Release: 6 Benchmark Date: 01 Apr 2026
# Coverage: 23 of 92 rules (18 of 18 CAT I).
# Rule IDs verified against the July 2026 SRG-STIG library on 2026-09-03.

import rego.v1

import data.stig.kubernetes.core

all_findings := core.findings

open_findings := [f | some f in all_findings; f.status == "Open"]
cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]

default overall_compliant := false
overall_compliant if count(cat_i_open) == 0
default fully_compliant := false
fully_compliant if count(open_findings) == 0

stig_assessment := {
	"metadata": {
		"stig_title": "Kubernetes Security Technical Implementation Guide",
		"version": "V2R6",
		"release": "Release: 6 Benchmark Date: 01 Apr 2026",
		"platform": "Kubernetes",
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
