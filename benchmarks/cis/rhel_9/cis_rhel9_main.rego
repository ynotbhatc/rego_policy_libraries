package cis_rhel9.main

# Bridge: re-export the cis_rhel9 orchestrator results under the
# /v1/data/<framework>/main/compliance_report convention used by the
# Generic Framework Assessment playbook. All other frameworks expose
# `compliance_report` at <framework>.main; this brings cis_rhel9 in line.
#
# The actual rules live in cis_rhel9_complete.rego (package cis_rhel9).

import rego.v1
import data.cis_rhel9 as cis

default compliance_report := {}

compliance_report := {
	"framework": "cis_rhel9",
	"version": "v2.0.0",
	"total_controls": 338,
	"compliant": cis.compliant,
	"passed_controls": cis.passed_controls,
	"failed_controls": cis.failed_controls,
	"compliance_percentage": cis.compliance_percentage,
	"violations": cis.violations,
	"section_results": cis.section_results,
	"extended_hardening": cis.extended_hardening_summary,
	"recommendations": cis.generate_recommendations,
} if {
	cis.compliance_percentage >= 0
}
