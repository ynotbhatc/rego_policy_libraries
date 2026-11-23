package sox.simplified_test

import rego.v1

# Audit 2026-11-23: the simplified module scored 23 checks and could raise findings for 15. The fixture `full`
# is in test_sox_simplified_missing_fields.rego.

_assessment(inp) := a if {
	a := data.sox.simplified.overall_sox_assessment with input as inp
}

_adds_up(a) if {
	(a.passed_controls + a.failed_controls) + a.not_applicable_controls == a.total_controls
	a.total_findings == a.failed_controls
	a.evidence_missing_controls <= a.failed_controls
}

test_empty_input_every_check_is_a_finding if {
	a := _assessment({})
	a.total_controls == 20
	a.failed_controls == 20
	a.evidence_missing_controls == 20
	a.passed_controls == 0
	a.compliance_score == 0
	a.compliance_status == false
	_adds_up(a)
}

test_full_input_passes_every_check if {
	a := _assessment(full)
	a.passed_controls == 20
	a.failed_controls == 0
	a.compliance_score == 100
	a.compliance_level == "FULLY_COMPLIANT"
	_adds_up(a)
}

previously_silent := [
	["/sox/section_302/quarterly_review/completed", "Quarterly Evaluation"],
	["/sox/section_302/annual_assessment/completed", "Annual Assessment"],
	["/sox/section_404/remediation_plan/implemented", "Remediation Plan"],
	["/sox/section_409/filing_deadlines/met", "Filing Deadlines"],
	["/sox/itgc/data_center_operations/controlled", "Data Center Operations"],
	["/sox/itgc/backup_recovery/tested", "Backup and Recovery"],
]

test_every_scored_check_can_raise_a_finding if {
	reported := [name |
		some [path, name] in previously_silent
		inp := json.patch(full, [{"op": "replace", "path": path, "value": false}])
		a := _assessment(inp)
		a.failed_controls == 1
		a.passed_controls == 19
		a.compliance_status == false
		a.compliance_level != "FULLY_COMPLIANT"
		_adds_up(a)
		detailed := data.sox.simplified.sox_detailed_findings with input as inp
		findings := [f | some section in detailed; some f in section]
		count(findings) == 1
		findings[0].control_name == name
		findings[0].status == "NON_COMPLIANT"
	]
	count(reported) == count(previously_silent)
}

test_wrong_typed_evidence_is_evidence_missing if {
	values := ["true", "yes", 1, null, {"provided": true}]
	flagged := [value |
		some value in values
		inp := json.patch(full, [{"op": "replace", "path": "/sox/section_302/cfo_certification/provided", "value": value}])
		a := _assessment(inp)
		a.failed_controls == 1
		a.evidence_missing_controls == 1
		f := data.sox.simplified.section_302_findings with input as inp
		f[0].status == "EVIDENCE_MISSING"
		f[0].evidence == "input.sox.section_302.cfo_certification.provided"
	]
	count(flagged) == count(values)
}

test_null_section_is_all_evidence_missing if {
	a := _assessment(json.patch(full, [{"op": "replace", "path": "/sox/section_409", "value": null}]))
	a.failed_controls == 3
	a.evidence_missing_controls == 3
	_adds_up(a)
}

# Section 409 (15 U.S.C. 78m(l)) does not require automation, real-time detection or continuous monitoring.
advisory_paths := [
	"/sox/section_409/disclosure_process/automated",
	"/sox/section_409/event_detection/real_time",
	"/sox/section_404/continuous_monitoring/active",
]

test_advisories_never_score_or_gate if {
	unaffected := [path |
		some path in advisory_paths
		not_met := json.patch(full, [{"op": "replace", "path": path, "value": false}])
		data.sox.simplified.sox_compliant with input as not_met
		a := _assessment(not_met)
		a.passed_controls == 20
		a.compliance_score == 100
		count([x | some x in a.advisories; x.status == "NOT_MET"]) == 1
		absent := _assessment(json.patch(full, [{"op": "remove", "path": path}]))
		absent.compliance_status == true
		count([x | some x in absent.advisories; x.status == "NOT_REPORTED"]) == 1
	]
	count(unaffected) == count(advisory_paths)
}

test_manual_disclosure_process_passes_section_409 if {
	inp := json.patch(full, [{"op": "replace", "path": "/sox/section_409/disclosure_process/automated", "value": false}])
	data.sox.simplified.section_409_compliant with input as inp
	count(data.sox.simplified.section_409_findings) == 0 with input as inp
}

test_missed_form_8k_deadline_fails_section_409 if {
	inp := json.patch(full, [{"op": "replace", "path": "/sox/section_409/filing_deadlines/met", "value": false}])
	not data.sox.simplified.section_409_compliant with input as inp
	f := data.sox.simplified.section_409_findings with input as inp
	contains(f[0].basis, "four business days")
}

# Section 404(c) / 404(b): exempt issuers need no auditor attestation, on an explicit statement only.
test_exempt_issuer_needs_no_attestation if {
	inp := json.patch(full, [{"op": "replace", "path": "/sox/section_404/external_auditor_attestation", "value": {
		"required": false,
		"exemption": "non_accelerated_filer",
	}}])
	a := _assessment(inp)
	a.compliance_status == true
	a.not_applicable_controls == 1
	a.passed_controls == 19
	a.compliance_score == 100
	_adds_up(a)
}

test_exemption_without_named_basis_is_a_finding if {
	statements := [{}, {"required": false}, {"required": false, "exemption": "small"}, {"required": "false", "exemption": "non_accelerated_filer"}]
	rejected := [s |
		some s in statements
		inp := json.patch(full, [{"op": "replace", "path": "/sox/section_404/external_auditor_attestation", "value": s}])
		a := _assessment(inp)
		a.compliance_status == false
		a.not_applicable_controls == 0
		a.evidence_missing_controls == 1
	]
	count(rejected) == count(statements)
}
