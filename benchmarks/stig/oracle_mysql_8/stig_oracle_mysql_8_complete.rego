# METADATA
# title: "DISA STIG — Oracle MySQL 8.0 Security Technical Implementation Guide — Master Aggregator"
# custom:
#   class: security
#   framework: stig_oracle_mysql_8
#   source: disa
#   domains: [database, mysql]
#   coverage:
#     checks: 2
#     cited: 2
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.1
package stig.oracle_mysql_8

# DISA STIG — Oracle MySQL 8.0 Security Technical Implementation Guide — Master Aggregator
# V2R3 | Release: 3 Benchmark Date: 30 Sep 2026
# Coverage: 100 of 100 rules (12 CAT I), 35 attestation-only.
# Rule IDs verified against the October 2026 SRG-STIG library on 2026-10-13.

import rego.v1

import data.stig.oracle_mysql_8.core

all_findings := core.findings

open_findings := [f | some f in all_findings; f.status == "Open"]
cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]

default overall_compliant := false
overall_compliant if count(cat_i_open) == 0
default fully_compliant := false
fully_compliant if count(open_findings) == 0

stig_assessment := {
	"metadata": {
		"stig_title": "Oracle MySQL 8.0 Security Technical Implementation Guide",
		"version": "V2R3",
		"release": "Release: 3 Benchmark Date: 30 Sep 2026",
		"platform": "Oracle MySQL 8.0",
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
