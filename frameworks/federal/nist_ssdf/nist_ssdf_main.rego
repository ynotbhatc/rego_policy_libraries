package nist_ssdf.main

# NIST SSDF (SP 800-218 v1.1) — Master Orchestrator
#
# Secure Software Development Framework. Aggregates the four practice groups:
#   PO — Prepare the Organization      (po_prepare_organization.rego)
#   PS — Protect the Software          (ps_protect_software.rego)
#   PW — Produce Well-Secured Software (pw_produce_secured_software.rego)
#   RV — Respond to Vulnerabilities    (rv_respond_vulnerabilities.rego)
#
# The input contract is documented per-group in each file. A single facts payload
# (organizational + CI/CD/SDLC posture) drives all four groups.
#
# OPA endpoint: POST /v1/data/nist_ssdf/main/compliance_report

import rego.v1

default compliant := false

# ── Cross-group violation aggregation (array.concat takes exactly 2 arrays) ────

_po_violations := [v | some v in data.nist_ssdf.po.violations]
_ps_violations := [v | some v in data.nist_ssdf.ps.violations]
_pw_violations := [v | some v in data.nist_ssdf.pw.violations]
_rv_violations := [v | some v in data.nist_ssdf.rv.violations]

_po_ps := array.concat(_po_violations, _ps_violations)
_pw_rv := array.concat(_pw_violations, _rv_violations)
all_violations := array.concat(_po_ps, _pw_rv)

# ── Scoring ───────────────────────────────────────────────────────────────────

total_controls := sum([
	data.nist_ssdf.po.controls_evaluated,
	data.nist_ssdf.ps.controls_evaluated,
	data.nist_ssdf.pw.controls_evaluated,
	data.nist_ssdf.rv.controls_evaluated,
])

passing_controls := total_controls - count(all_violations)

default compliance_percentage := 0

compliance_percentage := (passing_controls * 100) / total_controls if {
	total_controls > 0
}

compliant if {
	count(all_violations) == 0
}

_overall := "PASS" if compliant

_overall := "FAIL" if not compliant

# ── Compliance report ─────────────────────────────────────────────────────────

compliance_report := {
	"framework": "NIST SSDF (SP 800-218 v1.1)",
	"framework_family": "federal",
	"total_controls": total_controls,
	"passing_controls": passing_controls,
	"failing_controls": count(all_violations),
	"compliance_percentage": compliance_percentage,
	"overall_compliance": _overall,
	"compliant": compliant,
	"violations": all_violations,
	"practice_groups": {
		"PO": data.nist_ssdf.po.compliance_report,
		"PS": data.nist_ssdf.ps.compliance_report,
		"PW": data.nist_ssdf.pw.compliance_report,
		"RV": data.nist_ssdf.rv.compliance_report,
	},
}
