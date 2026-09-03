package stig.windows_11

# DISA STIG — Microsoft Windows 11 Security Technical Implementation Guide — Master Aggregator
# V2R8 | Release: 8 Benchmark Date: 01 Jul 2026
# Coverage: 102 auto-derived registry rules across 3 generated modules; 154 rules of 256 not yet implemented (non-registry or complex).
# Rule IDs verified against the July 2026 SRG-STIG library on 2026-09-03.

import rego.v1

import data.stig.windows_11.registry_cc
import data.stig.windows_11.registry_other
import data.stig.windows_11.registry_so

_f_0 := registry_cc.findings
_f_1 := registry_other.findings
_f_2 := registry_so.findings

_acc_1 := array.concat(_f_0, _f_1)
_acc_2 := array.concat(_acc_1, _f_2)
all_findings := _acc_2

open_findings := [f | some f in all_findings; f.status == "Open"]
cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]

default overall_compliant := false
overall_compliant if count(cat_i_open) == 0
default fully_compliant := false
fully_compliant if count(open_findings) == 0

stig_assessment := {
	"metadata": {
		"stig_title": "Microsoft Windows 11 Security Technical Implementation Guide",
		"version": "V2R8",
		"release": "Release: 8 Benchmark Date: 01 Jul 2026",
		"platform": "Windows 11",
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
# fail-closed gate).
compliance_report := {
	"total_controls": count(all_findings),
	"open_findings": open_findings,
	"passed_controls": count(all_findings) - count(open_findings),
	"failed_controls": count(open_findings),
	"compliant": fully_compliant,
}
