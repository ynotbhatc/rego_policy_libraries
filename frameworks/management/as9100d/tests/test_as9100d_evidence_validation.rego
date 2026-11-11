# Regression tests for the AS9100D evidence-validation review (2026-11-11): malformed, empty or incomplete
# evidence never counts as a pass. One test per finding and sub-case; each asserts that the row FAILS and that
# the violation names the field or path at fault.
#
#   Finding 1  calibration and corrective actions passed with missing or bad dates
#   Finding 2  KPIs with no target were skipped
#   Finding 3  empty records (blank ids/serials, validated with no id or date, empty approved_by) counted
#   Finding 4  empty lists passed the sibling rows (8.4.2/8.4.3, 7.1.5.2, 8.7.2, 10.2.2)
#   Minor      attestations: false skipped the bad-container message; as_of that does not parse
package as9100d.evidence_validation_test

import rego.v1

import data.as9100d.improvement
import data.as9100d.main
import data.as9100d.operation
import data.as9100d.performance
import data.as9100d.support
import data.as9100d_fixture_test as fx

# A violation of row id whose detail mentions text.
_names(v, id, text) if {
	some msg in v
	startswith(msg, concat("", ["AS9100D ", id, ": "]))
	contains(msg, text)
}

_ca(rec) := fx.with_patch("corrective_actions", {"records": [rec]})

_ncr(rec) := fx.with_patch("nonconformance", {"records": [rec]})

# ── Finding 1: dates and required fields ─────────────────────────────────────

test_f1_equipment_with_id_only_fails_both_calibration_rows if {
	inp := fx.with_patch("measuring_equipment", [{"id": "x"}])
	not support.passed["7.1.5.1"] with input as inp
	not support.passed["7.1.5.2"] with input as inp
	v := support.violations with input as inp
	_names(v, "7.1.5.1", "in_service must be true or false")
	_names(v, "7.1.5.1", "has no description")
	_names(v, "7.1.5.2", "no in_service status")
	r := main.compliance_report with input as inp
	r.passed == 69
	r.compliant == false
}

test_f1_calibration_due_bad_fails_both_calibration_rows if {
	inp := fx.with_patch("measuring_equipment", [{
		"id": "x",
		"description": "height gauge",
		"in_service": true,
		"calibration_due": "bad",
		"calibrated_on": "2026-01-01",
		"traceable": true,
	}])
	not support.passed["7.1.5.1"] with input as inp
	not support.passed["7.1.5.2"] with input as inp
	v := support.violations with input as inp
	_names(v, "7.1.5.1", "calibration_due: bad")
	_names(v, "7.1.5.2", "calibration_due: bad is missing or not a date")
}

test_f1_calibration_due_non_string_fails if {
	inp := fx.with_patch("measuring_equipment", [{
		"id": "x",
		"description": "height gauge",
		"in_service": true,
		"calibration_due": 20270101,
		"calibrated_on": "2026-01-01",
		"traceable": true,
	}])
	not support.passed["7.1.5.1"] with input as inp
	not support.passed["7.1.5.2"] with input as inp
	_names(support.violations, "7.1.5.1", "calibration_due: 20270101") with input as inp
}

test_f1_calibrated_on_missing_fails_register_row if {
	inp := fx.with_patch("measuring_equipment", [{
		"id": "x",
		"description": "height gauge",
		"in_service": true,
		"calibration_due": "2027-01-01",
		"traceable": true,
	}])
	not support.passed["7.1.5.1"] with input as inp
	_names(support.violations, "7.1.5.1", "calibrated_on: <missing>") with input as inp
}

test_f1_calibrated_on_in_future_fails_traceability_row if {
	inp := fx.with_patch("measuring_equipment", [{
		"id": "x",
		"description": "height gauge",
		"in_service": true,
		"calibration_due": "2027-06-01",
		"calibrated_on": "2026-12-01",
		"traceable": true,
	}])
	not support.passed["7.1.5.2"] with input as inp
	_names(support.violations, "7.1.5.2", "calibration date in the future (calibrated_on: 2026-12-01)") with input as inp
}

test_f1_open_corrective_action_without_due_on_fails if {
	inp := _ca({
		"id": "CA-1",
		"nonconformity_id": "NCR-1",
		"root_cause": "worn locator",
		"human_factors_considered": true,
		"status": "open",
	})
	not improvement.passed["10.2.1"] with input as inp
	_names(improvement.violations, "10.2.1", "no due date that parses (due_on: <missing>)") with input as inp
	r := main.compliance_report with input as inp
	r.passed == 70
	r.compliant == false
}

test_f1_open_corrective_action_with_bad_due_on_fails if {
	inp := _ca({
		"id": "CA-1",
		"nonconformity_id": "NCR-1",
		"root_cause": "worn locator",
		"human_factors_considered": true,
		"status": "open",
		"due_on": "next quarter",
	})
	not improvement.passed["10.2.1"] with input as inp
	_names(improvement.violations, "10.2.1", "due_on: next quarter") with input as inp
}

test_f1_closed_corrective_action_without_closed_on_fails if {
	inp := _ca({
		"id": "CA-1",
		"nonconformity_id": "NCR-1",
		"root_cause": "worn locator",
		"human_factors_considered": true,
		"status": "closed",
		"effectiveness_reviewed": true,
	})
	not improvement.passed["10.2.1"] with input as inp
	_names(improvement.violations, "10.2.1", "no closure date that parses (closed_on: <missing>)") with input as inp
}

# ── Finding 2: KPI targets ───────────────────────────────────────────────────

test_f2_kpi_value_zero_without_target_fails if {
	inp := fx.with_patch("kpis", {
		"on_time_delivery": {"value": 0, "period_end": "2026-10-31"},
		"conformity": {"value": 0, "period_end": "2026-10-31"},
	})
	not performance.passed["9.1.2"] with input as inp
	v := performance.violations with input as inp
	_names(v, "9.1.2", "on_time_delivery has no target (kpis.on_time_delivery.target must be a number")
	_names(v, "9.1.2", "conformity has no target (kpis.conformity.target must be a number")
	r := main.compliance_report with input as inp
	r.passed == 70
	r.compliant == false
}

test_f2_kpi_non_numeric_target_fails if {
	inp := fx.with_patch("kpis/on_time_delivery/target", "95%")
	not performance.passed["9.1.2"] with input as inp
	_names(performance.violations, "9.1.2", "kpis.on_time_delivery.target must be a number, got 95%") with input as inp
}

test_f2_kpi_period_end_bad_fails_even_when_value_meets_target if {
	inp := fx.with_patch("kpis/conformity/period_end", "Q3")
	not performance.passed["9.1.2"] with input as inp
	_names(performance.violations, "9.1.2", "kpis.conformity.period_end: Q3") with input as inp
}

# ── Finding 3: empty records ─────────────────────────────────────────────────

test_f3_traceability_blank_id_and_serial_fails if {
	inp := fx.with_patch("traceability", {"items": [{"id": "", "part_number": "", "serial": ""}]})
	not operation.passed["8.5.2"] with input as inp
	v := operation.violations with input as inp
	_names(v, "8.5.2", "id must be a non-blank string")
	_names(v, "8.5.2", "part_number must be a non-blank string")
	_names(v, "8.5.2", "serial or lot must be a non-blank string")
	r := main.compliance_report with input as inp
	r.passed == 70
	r.compliant == false
}

test_f3_traceability_whitespace_serial_fails if {
	inp := fx.with_patch("traceability", {"items": [{"id": "SN-1", "part_number": "PN-1", "serial": "   "}]})
	not operation.passed["8.5.2"] with input as inp
	_names(operation.violations, "8.5.2", "item SN-1 carries neither a serial nor a lot number") with input as inp
}

test_f3_traceability_duplicate_ids_fail if {
	inp := fx.with_patch("traceability", {"items": [
		{"id": "SN-1", "part_number": "PN-1", "serial": "1"},
		{"id": "SN-1", "part_number": "PN-1", "serial": "2"},
	]})
	not operation.passed["8.5.2"] with input as inp
	_names(operation.violations, "8.5.2", "identifier SN-1 is used by more than one traceability record") with input as inp
}

test_f3_duplicate_ids_fail_in_every_list_row if {
	dup := [{"id": "D-1"}, {"id": "D-1"}]
	_names(support.violations, "7.1.5.1", "identifier D-1 is used by more than one") with input as fx.with_patch("measuring_equipment", dup)
	_names(operation.violations, "8.1.2", "identifier D-1 is used by more than one") with input as fx.with_patch("configuration_management/baselines", dup)
	_names(operation.violations, "8.1.4", "identifier D-1 is used by more than one") with input as fx.with_patch("counterfeit_prevention/components", dup)
	_names(operation.violations, "8.4.1", "identifier D-1 is used by more than one") with input as fx.with_patch("external_providers/suppliers", dup)
	_names(operation.violations, "8.5.1.1", "identifier D-1 is used by more than one") with input as fx.with_patch("production_equipment", dup)
	_names(operation.violations, "8.5.6", "identifier D-1 is used by more than one") with input as fx.with_patch("change_control/records", dup)
	_names(operation.violations, "8.7.2", "identifier D-1 is used by more than one") with input as fx.with_patch("nonconformance/records", dup)
	_names(improvement.violations, "10.2.2", "identifier D-1 is used by more than one") with input as fx.with_patch("corrective_actions/records", dup)
}

test_f3_validated_equipment_with_no_id_or_date_fails if {
	inp := fx.with_patch("production_equipment", [{"validated": true}])
	not operation.passed["8.5.1.1"] with input as inp
	v := operation.violations with input as inp
	_names(v, "8.5.1.1", "has no identifier (id must be a non-blank string)")
	_names(v, "8.5.1.1", "no validation date that parses (validated_on: <missing>)")
	_names(v, "8.5.1.1", "type <missing>, not equipment, tool or software")
	r := main.compliance_report with input as inp
	r.passed == 70
	r.compliant == false
}

test_f3_validated_equipment_with_bad_date_fails if {
	inp := fx.with_patch("production_equipment", [{"id": "CNC-3", "type": "equipment", "validated": true, "validated_on": "last year"}])
	not operation.passed["8.5.1.1"] with input as inp
	_names(operation.violations, "8.5.1.1", "validated_on: last year") with input as inp
}

test_f3_baseline_with_empty_approved_by_fails if {
	inp := fx.with_patch("configuration_management", {
		"baselines": [{"id": "BL-1", "approved": true, "approved_by": "", "approved_on": "2026-02-10"}],
		"drift_records": [],
	})
	not operation.passed["8.1.2"] with input as inp
	_names(operation.violations, "8.1.2", "baseline BL-1 records no approving authority (approved_by must be a non-blank string)") with input as inp
	r := main.compliance_report with input as inp
	r.passed == 70
	r.compliant == false
}

test_f3_baseline_without_approved_on_fails if {
	inp := fx.with_patch("configuration_management", {
		"baselines": [{"id": "BL-1", "approved": true, "approved_by": "CCB"}],
		"drift_records": [],
	})
	not operation.passed["8.1.2"] with input as inp
	_names(operation.violations, "8.1.2", "no approval date that parses (approved_on: <missing>)") with input as inp
}

test_f3_drift_record_against_unknown_baseline_fails if {
	inp := fx.with_patch("configuration_management/drift_records", [{"baseline_id": "BL-404", "detected_on": "2026-09-14", "disposition": "corrected"}])
	not operation.passed["8.1.2"] with input as inp
	_names(operation.violations, "8.1.2", "references baseline BL-404, which is not in the baseline list") with input as inp
}

test_f3_change_record_with_blank_approver_fails if {
	inp := fx.with_patch("change_control", {"records": [{"id": "CR-1", "approved": true, "approved_by": " ", "impact_reviewed": true}]})
	not operation.passed["8.5.6"] with input as inp
	_names(operation.violations, "8.5.6", "change CR-1 records no approving authority (approved_by must be a non-blank string)") with input as inp
}

test_f3_nonconformance_with_blank_authority_fails if {
	inp := _ncr({"id": "NCR-1", "description": "crack", "disposition": "scrap", "disposition_authority": ""})
	not operation.passed["8.7.2"] with input as inp
	_names(operation.violations, "8.7.2", "disposition_authority must be a non-blank string") with input as inp
}

test_f3_corrective_action_with_blank_nonconformity_reference_fails if {
	inp := _ca({
		"id": "CA-1",
		"nonconformity_id": "",
		"root_cause": "worn locator",
		"human_factors_considered": true,
		"status": "open",
		"due_on": "2027-01-15",
	})
	not improvement.passed["10.2.2"] with input as inp
	_names(improvement.violations, "10.2.2", "nonconformity_id must be a non-blank string") with input as inp
}

# ── Finding 4: empty lists ───────────────────────────────────────────────────

test_f4_no_suppliers_fails_all_three_rows if {
	inp := fx.with_patch("external_providers", {"suppliers": []})
	not operation.passed["8.4.1"] with input as inp
	not operation.passed["8.4.2"] with input as inp
	not operation.passed["8.4.3"] with input as inp
	v := operation.violations with input as inp
	_names(v, "8.4.1", "at least one supplier is required")
	_names(v, "8.4.2", "no supplier performance has been reviewed")
	_names(v, "8.4.3", "no flow-down acknowledgement exists")
	r := main.compliance_report with input as inp
	r.passed == 68
	r.clauses["8"].gaps == ["8.4.1", "8.4.2", "8.4.3"]
}

test_f4_no_measuring_equipment_fails_both_rows if {
	inp := fx.with_patch("measuring_equipment", [])
	not support.passed["7.1.5.1"] with input as inp
	not support.passed["7.1.5.2"] with input as inp
	v := support.violations with input as inp
	_names(v, "7.1.5.1", "register is empty")
	_names(v, "7.1.5.2", "no calibration status can be confirmed")
	r := main.compliance_report with input as inp
	r.passed == 69
}

test_f4_no_nonconformances_without_declaration_fails_both_rows if {
	inp := fx.with_patch("nonconformance", {"records": []})
	not operation.passed["8.7.1"] with input as inp
	not operation.passed["8.7.2"] with input as inp
	v := operation.violations with input as inp
	_names(v, "8.7.1", "set nonconformance.none_occurred: true and attest 8.7.1")
	_names(v, "8.7.2", "set nonconformance.none_occurred: true and attest 8.7.2")
	r := main.compliance_report with input as inp
	r.passed == 69
}

test_f4_no_nonconformances_declared_but_unattested_fails if {
	inp := fx.with_patch("nonconformance", {"records": [], "none_occurred": true})
	not operation.passed["8.7.1"] with input as inp
	not operation.passed["8.7.2"] with input as inp
	v := operation.violations with input as inp
	_names(v, "8.7.1", "attestations[\"8.7.1\"] must be true")
	_names(v, "8.7.2", "attestations[\"8.7.2\"] must be true")
}

test_f4_no_nonconformances_declared_and_attested_passes if {
	base := fx.with_patch("nonconformance", {"records": [], "none_occurred": true})
	inp := json.patch(base, [
		{"op": "add", "path": "/as9100d/attestations/8.7.1", "value": true},
		{"op": "add", "path": "/as9100d/attestations/8.7.2", "value": true},
	])
	operation.passed["8.7.1"] with input as inp
	operation.passed["8.7.2"] with input as inp
	r := main.compliance_report with input as inp
	r.compliant == true
	r.passed == 71
}

test_f4_nonconformance_declaration_with_records_is_a_contradiction if {
	inp := json.patch(fx.full, [
		{"op": "add", "path": "/as9100d/nonconformance/none_occurred", "value": true},
		{"op": "add", "path": "/as9100d/attestations/8.7.1", "value": true},
		{"op": "add", "path": "/as9100d/attestations/8.7.2", "value": true},
	])
	not operation.passed["8.7.1"] with input as inp
	not operation.passed["8.7.2"] with input as inp
	_names(operation.violations, "8.7.1", "none_occurred is true but 2 records are present") with input as inp
}

test_f4_no_corrective_actions_without_declaration_fails_both_rows if {
	inp := fx.with_patch("corrective_actions", {"records": []})
	not improvement.passed["10.2.1"] with input as inp
	not improvement.passed["10.2.2"] with input as inp
	v := improvement.violations with input as inp
	_names(v, "10.2.1", "set corrective_actions.none_occurred: true and attest 10.2.1")
	_names(v, "10.2.2", "set corrective_actions.none_occurred: true and attest 10.2.2")
	r := main.compliance_report with input as inp
	r.passed == 69
}

test_f4_no_corrective_actions_declared_but_unattested_fails if {
	inp := fx.with_patch("corrective_actions", {"records": [], "none_occurred": true})
	not improvement.passed["10.2.1"] with input as inp
	not improvement.passed["10.2.2"] with input as inp
	v := improvement.violations with input as inp
	_names(v, "10.2.1", "attestations[\"10.2.1\"] must be true")
	_names(v, "10.2.2", "attestations[\"10.2.2\"] must be true")
}

test_f4_no_corrective_actions_declared_and_attested_passes if {
	base := fx.with_patch("corrective_actions", {"records": [], "none_occurred": true})
	inp := json.patch(base, [
		{"op": "add", "path": "/as9100d/attestations/10.2.1", "value": true},
		{"op": "add", "path": "/as9100d/attestations/10.2.2", "value": true},
	])
	improvement.passed["10.2.1"] with input as inp
	improvement.passed["10.2.2"] with input as inp
	r := main.compliance_report with input as inp
	r.compliant == true
	r.passed == 71
}

test_f4_corrective_action_declaration_with_records_is_a_contradiction if {
	inp := json.patch(fx.full, [
		{"op": "add", "path": "/as9100d/corrective_actions/none_occurred", "value": true},
		{"op": "add", "path": "/as9100d/attestations/10.2.1", "value": true},
		{"op": "add", "path": "/as9100d/attestations/10.2.2", "value": true},
	])
	not improvement.passed["10.2.1"] with input as inp
	not improvement.passed["10.2.2"] with input as inp
	_names(improvement.violations, "10.2.2", "none_occurred is true but 2 records are present") with input as inp
}

test_f4_none_occurred_string_true_is_not_a_declaration if {
	inp := fx.with_patch("nonconformance", {"records": [], "none_occurred": "true"})
	not operation.passed["8.7.1"] with input as inp
	_names(operation.violations, "8.7.1", "set nonconformance.none_occurred: true and attest 8.7.1") with input as inp
}

# ── Minor: contract container and as_of ──────────────────────────────────────

test_minor_attestations_false_carries_the_container_violation if {
	inp := fx.with_patch("attestations", false)
	r := main.compliance_report with input as inp
	r.compliant == false
	some msg in r.violations
	contains(msg, "input.as9100d.attestations must be an object")
	contains(msg, "got false")
	r.violation_count == 55
	r.passed == 17
}

test_minor_attestations_string_carries_the_container_violation if {
	v := main.violations with input as {"as9100d": {"attestations": "all"}}
	some msg in v
	contains(msg, "input.as9100d.attestations must be an object")
}

test_minor_as_of_that_does_not_parse_is_a_contract_violation if {
	inp := fx.with_patch("as_of", "yesterday")
	r := main.compliance_report with input as inp
	r.compliant == false
	some msg in r.violations
	contains(msg, "input.as9100d.as_of must be an RFC 3339 or YYYY-MM-DD date, got yesterday")
	not performance.passed["9.1.2"] with input as inp
}

test_past_year_is_a_calendar_year_not_365_days if {
	# as_of is 2026-11-11: the anniversary counts, the day before it does not.
	anniversary := fx.with_patch("management_review", {"reviews": [{"held_on": "2025-11-11", "outputs_recorded": true}]})
	performance.passed["9.3.1"] with input as anniversary
	day_before := fx.with_patch("management_review", {"reviews": [{"held_on": "2025-11-10", "outputs_recorded": true}]})
	not performance.passed["9.3.1"] with input as day_before

	# Across February 29 the anniversary is 366 days back; a 365-day count would fail it.
	leap := json.patch(fx.with_patch("management_review", {"reviews": [{"held_on": "2027-03-01", "outputs_recorded": true}]}), [{"op": "replace", "path": "/as9100d/as_of", "value": "2028-03-01"}])
	performance.passed["9.3.1"] with input as leap
	leap_day_before := json.patch(leap, [{"op": "replace", "path": "/as9100d/management_review/reviews/0/held_on", "value": "2027-02-28"}])
	not performance.passed["9.3.1"] with input as leap_day_before
}

# ── The two new rows ─────────────────────────────────────────────────────────

test_new_row_is_attested_and_9_1_2_keeps_its_clause_id if {
	main.items["8.3.4.1"].kind == "attestation"
	not main.items["9.1.2-feedback"]
	main.items["9.1.2"].kind == "fact"
	startswith(main.items["9.1.2"].title, "Customer satisfaction")
	count({id | some id, _ in main.items; contains(id, "-")}) == 0
	count({id | some id, it in main.items; it.kind == "fact"}) == 18
}
