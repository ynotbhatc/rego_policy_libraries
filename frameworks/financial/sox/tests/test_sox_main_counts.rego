package sox.main_test

import rego.v1

# Audit 2026-11-23. Before this change the module scored 35 checks and could raise findings for 23 of them, the
# Section 409 check failed unless disclosure was automated, and the Section 404(b) attestation was demanded of
# exempt issuers. Fixtures (s302, s404, s409, mgmt, itgc_ok, app_ok) are in test_sox_main_gating.rego.

all_ok := {"s302": s302, "s404": s404, "s409": s409, "mgmt": mgmt, "itgc": itgc_ok, "app": app_ok}

_report(d) := r if {
	# regal ignore:external-reference
	r := data.sox.main.compliance_report with data.sox.section_302 as d.s302
		with data.sox.section_404 as d.s404 # regal ignore:external-reference
		with data.sox.section_409 as d.s409 # regal ignore:external-reference
		with data.sox.management as d.mgmt # regal ignore:external-reference
		with data.sox.itgc as d.itgc # regal ignore:external-reference
		with data.sox.application_controls as d.app # regal ignore:external-reference
}

# One area patched. object.union merges deeply and would put a removed key back, so the area is replaced whole.
# regal ignore:external-reference
_changed(area, patch) := object.union(object.remove(all_ok, [area]), {area: json.patch(all_ok[area], patch)})

_adds_up(r) if {
	(r.passed_controls + r.failed_controls) + r.not_applicable_controls == r.total_controls
	r.violation_count == r.failed_controls
	count(r.violations) == r.failed_controls
	r.total_findings == r.failed_controls
	r.evidence_missing_controls <= r.failed_controls
}

# Every boolean in the all-pass fixtures set to false.
all_false[area][control][field] := false if {
	some area, controls in all_ok
	some control, fields in controls
	some field, _ in fields
}

test_empty_data_every_check_is_a_finding if {
	r := data.sox.main.compliance_report
	r.total_controls == 31
	r.failed_controls == 31
	r.evidence_missing_controls == 31
	r.passed_controls == 0
	r.compliance_score == 0
	r.compliant == false
	_adds_up(r)
}

test_all_true_passes_every_check if {
	r := _report(all_ok)
	r.total_controls == 31
	r.passed_controls == 31
	r.failed_controls == 0
	r.compliance_score == 100
	r.compliant == true
	r.compliance_level == "FULLY_COMPLIANT"
	_adds_up(r)
}

test_all_false_fails_every_check_without_missing_evidence if {
	r := _report(all_false)
	r.failed_controls == 31
	r.evidence_missing_controls == 0
	r.compliance_score == 0
	_adds_up(r)
	every v in r.violations {
		v.status == "NON_COMPLIANT"
	}
}

# These ten checks were scored but could not raise a finding; each now raises exactly one and fails the verdict.
previously_silent := [
	["s302", "/quarterly_review/completed", "Quarterly Evaluation"],
	["s302", "/annual_assessment/completed", "Annual Assessment"],
	["s404", "/remediation_plan/implemented", "Remediation Plan"],
	["s409", "/filing_deadlines/met", "Filing Deadlines"],
	["mgmt", "/risk_assessment/annual", "Risk Assessment"],
	["mgmt", "/control_documentation/current", "Control Documentation"],
	["itgc", "/data_center_operations/controlled", "Data Center Operations"],
	["itgc", "/backup_recovery/tested", "Backup and Recovery"],
	["app", "/error_handling/robust", "Error Handling"],
	["app", "/transaction_logging/complete", "Transaction Logging"],
]

test_every_scored_check_can_raise_a_finding if {
	reported := [name |
		some [area, path, name] in previously_silent
		r := _report(_changed(area, [{"op": "replace", "path": path, "value": false}]))
		r.failed_controls == 1
		r.passed_controls == 30
		r.violations[0].control_name == name
		r.violations[0].status == "NON_COMPLIANT"
		r.compliant == false
		r.compliance_score < 100
		_adds_up(r)
	]
	count(reported) == count(previously_silent)
}

test_missing_and_wrong_typed_evidence_is_evidence_missing if {
	values := ["true", "yes", 1, null, {"provided": true}]
	flagged := [value |
		some value in values
		r := _report(_changed("s302", [{"op": "replace", "path": "/ceo_certification/provided", "value": value}]))
		r.failed_controls == 1
		r.evidence_missing_controls == 1
		r.violations[0].status == "EVIDENCE_MISSING"
		r.violations[0].evidence == "data.sox.section_302.ceo_certification.provided"
		_adds_up(r)
	]
	count(flagged) == count(values)
	r := _report(_changed("s302", [{"op": "remove", "path": "/ceo_certification"}]))
	r.evidence_missing_controls == 1
}

# ── Section 409: 15 U.S.C. 78m(l), Form 8-K General Instruction B.1 ─────────

advisory_facts := [
	["s409", "/disclosure_process/automated", "Automated Disclosure Process"],
	["s409", "/event_detection/real_time", "Real-Time Event Detection"],
	["s404", "/continuous_monitoring/active", "Continuous Monitoring"],
	["mgmt", "/continuous_monitoring/implemented", "Continuous Monitoring"],
]

_advisory_status(r, name, section) := status if {
	some a in r.advisories
	a.advisory == name
	a.sox_section == section
	status := a.status
}

test_manual_disclosure_process_does_not_fail_section_409 if {
	d := _changed("s409", [{"op": "replace", "path": "/disclosure_process/automated", "value": false}])
	r := _report(d)
	r.compliant == true
	r.compliance_score == 100
	r.failed_controls == 0
	r.section_scores.section_409 == 100
	_advisory_status(r, "Automated Disclosure Process", "409") == "NOT_MET"
	data.sox.main.section_409_compliant with data.sox.section_409 as d.s409
}

test_advisories_never_score_or_gate if {
	sections := {"s409": "409", "s404": "404", "mgmt": "Management"}
	unaffected := [fact |
		some fact in advisory_facts
		[area, path, name] := fact
		not_met := _report(_changed(area, [{"op": "replace", "path": path, "value": false}]))
		not_met.compliant == true
		not_met.total_controls == 31
		not_met.passed_controls == 31
		_advisory_status(not_met, name, sections[area]) == "NOT_MET"
		absent := _report(_changed(area, [{"op": "remove", "path": path}]))
		absent.compliant == true
		absent.passed_controls == 31
		_advisory_status(absent, name, sections[area]) == "NOT_REPORTED"
	]
	count(unaffected) == count(advisory_facts)
}

test_advisories_reported_as_met_when_true if {
	r := _report(all_ok)
	count(r.advisories) == 4
	every a in r.advisories {
		a.status == "MET"
		a.scored == false
	}
}

test_missed_form_8k_deadline_fails_section_409 if {
	d := _changed("s409", [{"op": "replace", "path": "/filing_deadlines/met", "value": false}])
	r := _report(d)
	r.compliant == false
	v := r.violations[0]
	v.section == "409"
	contains(v.basis, "four business days")
	not data.sox.main.section_409_compliant with data.sox.section_409 as d.s409
}

test_untimely_disclosure_fails_section_409 if {
	r := _report(_changed("s409", [{"op": "replace", "path": "/material_events/disclosed_timely", "value": false}]))
	r.compliant == false
	r.violations[0].control_name == "Timely Disclosure"
	contains(r.violations[0].basis, "78m(l)")
}

# ── Section 404(b) and (c): the attestation exemption is an explicit statement ─

_attestation(value) := _report(_changed("s404", [{"op": "replace", "path": "/external_auditor_attestation", "value": value}]))

test_exempt_issuer_needs_no_attestation if {
	exemptions := ["non_accelerated_filer", "emerging_growth_company"]
	exempt := [e |
		some e in exemptions
		r := _attestation({"required": false, "exemption": e})
		r.compliant == true
		r.not_applicable_controls == 1
		r.passed_controls == 30
		r.failed_controls == 0
		r.compliance_score == 100
		_adds_up(r)
	]
	count(exempt) == count(exemptions)
}

test_exemption_needs_both_typed_fields if {
	statements := [
		{},
		{"required": false},
		{"required": false, "exemption": "other"},
		{"required": false, "exemption": null},
		{"required": "false", "exemption": "non_accelerated_filer"},
		{"required": null, "exemption": "non_accelerated_filer"},
		{"exemption": "non_accelerated_filer"},
		{"required": true, "exemption": "non_accelerated_filer"},
	]
	rejected := [s |
		some s in statements
		r := _attestation(s)
		r.compliant == false
		r.not_applicable_controls == 0
		r.violations[0].control_name == "Auditor Attestation"
		r.violations[0].status == "EVIDENCE_MISSING"
		_adds_up(r)
	]
	count(rejected) == count(statements)
}

test_adverse_attestation_fails_when_not_exempt if {
	r := _attestation({"unqualified": false})
	r.violations[0].status == "NON_COMPLIANT"
	r.failed_controls == 1
}

test_every_finding_names_its_basis if {
	r := data.sox.main.compliance_report
	every v in r.violations {
		v.basis != ""

		# nothing posted and nothing loaded: the finding names the input document, where the fact belongs
		startswith(v.evidence, "input.sox.")
		startswith(v.detail, "evidence missing: input.sox.")
	}
}
