# METADATA
# title: "DISA STIG — Oracle Database 19c Security Technical Implementation Guide — Master Aggregator"
# custom:
#   class: security
#   framework: stig_oracle_database_19c
#   source: disa
#   domains: [database, oracle]
#   coverage:
#     checks: 2
#     cited: 2
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.0
package stig.oracle_database_19c

# DISA STIG — Oracle Database 19c Security Technical Implementation Guide — Master Aggregator
# V1R6 | Release: 6 Benchmark Date: 30 Sep 2026
# Coverage: 96 of 96 rules (16 CAT I), 45 attestation-only.
# Rule IDs verified against the October 2026 SRG-STIG library on 2026-10-13.

import rego.v1

import data.stig.oracle_database_19c.core

all_findings := core.findings

open_findings := [f | some f in all_findings; f.status == "Open"]
cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]

default overall_compliant := false
overall_compliant if count(cat_i_open) == 0
default fully_compliant := false
fully_compliant if count(open_findings) == 0

stig_assessment := {
	"metadata": {
		"stig_title": "Oracle Database 19c Security Technical Implementation Guide",
		"version": "V1R6",
		"release": "Release: 6 Benchmark Date: 30 Sep 2026",
		"platform": "Oracle Database 19c",
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

# Uniform library entrypoint contract.
compliance_report := {
	"total_controls": count(all_findings),
	"open_findings": open_findings,
	"passed_controls": count(all_findings) - count(open_findings),
	"failed_controls": count(open_findings),
	"compliant": fully_compliant,
}
