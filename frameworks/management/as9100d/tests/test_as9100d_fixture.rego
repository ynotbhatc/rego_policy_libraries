# Full-pass fixture for the AS9100D tests: every attestation true, every fact-decided clause satisfied,
# as_of pinned so the past-year windows are reproducible. Shared by the per-clause and roll-up tests.
package as9100d_fixture_test

import rego.v1

full := {"as9100d": {
	"as_of": "2026-11-11",
	"attestations": {
		"4.1": true,
		"4.2": true,
		"4.3": true,
		"4.4.1": true,
		"4.4.2": true,
		"5.1.1": true,
		"5.1.2": true,
		"5.2.1": true,
		"5.2.2": true,
		"5.3": true,
		"6.1.1": true,
		"6.1.2": true,
		"6.2.1": true,
		"6.2.2": true,
		"6.3": true,
		"7.1.1": true,
		"7.1.2": true,
		"7.1.3": true,
		"7.1.4": true,
		"7.1.6": true,
		"7.2": true,
		"7.3": true,
		"7.4": true,
		"7.5.1": true,
		"7.5.2": true,
		"7.5.3": true,
		"8.1": true,
		"8.1.1": true,
		"8.1.3": true,
		"8.2.1": true,
		"8.2.2": true,
		"8.2.3": true,
		"8.2.4": true,
		"8.3.1": true,
		"8.3.2": true,
		"8.3.3": true,
		"8.3.4": true,
		"8.3.4.1": true,
		"8.3.5": true,
		"8.3.6": true,
		"8.5.1": true,
		"8.5.1.2": true,
		"8.5.1.3": true,
		"8.5.3": true,
		"8.5.4": true,
		"8.5.5": true,
		"8.6": true,
		"9.1.1": true,
		"9.1.2": true,
		"9.1.3": true,
		"9.3.2": true,
		"9.3.3": true,
		"10.1": true,
		"10.3": true,
	},
	"measuring_equipment": [
		{
			"id": "CMM-01",
			"description": "coordinate measuring machine",
			"in_service": true,
			"calibration_due": "2027-03-31",
			"calibrated_on": "2026-03-31",
			"traceable": true,
		},
		{
			"id": "GAUGE-07",
			"description": "bore gauge, withdrawn",
			"in_service": false,
			"traceable": true,
		},
	],
	"configuration_management": {
		"baselines": [{
			"id": "BL-2026-02",
			"approved": true,
			"approved_by": "Configuration Control Board",
			"approved_on": "2026-02-10",
		}],
		"drift_records": [{
			"baseline_id": "BL-2026-02",
			"detected_on": "2026-09-14",
			"disposition": "corrected",
		}],
	},
	"counterfeit_prevention": {
		"approved_sources": [
			"OEM-A",
			"DIST-B",
		],
		"components": [
			{
				"id": "PN-100",
				"source": "OEM-A",
				"provenance_documented": true,
			},
			{
				"id": "PN-200",
				"source": "DIST-B",
				"provenance_documented": true,
			},
		],
	},
	"external_providers": {"suppliers": [
		{
			"id": "SUP-1",
			"status": "approved",
			"scope": "machined parts",
			"performance_reviewed_on": "2026-09-30",
			"flow_down_acknowledged": true,
		},
		{
			"id": "SUP-2",
			"status": "conditional",
			"scope": "heat treatment",
			"performance_reviewed_on": "2026-06-30",
			"flow_down_acknowledged": true,
		},
	]},
	"production_equipment": [
		{
			"id": "CNC-3",
			"type": "equipment",
			"validated": true,
			"validated_on": "2026-01-20",
		},
		{
			"id": "NC-PROG-77",
			"type": "software",
			"validated": true,
			"validated_on": "2026-05-02",
		},
	],
	"traceability": {"items": [
		{
			"id": "SN-0001",
			"part_number": "PN-100",
			"serial": "0001",
		},
		{
			"id": "LOT-55",
			"part_number": "PN-200",
			"lot": "55",
		},
	]},
	"change_control": {"records": [{
		"id": "CR-12",
		"approved": true,
		"approved_by": "Engineering manager",
		"impact_reviewed": true,
	}]},
	"nonconformance": {"records": [
		{
			"id": "NCR-5",
			"description": "undersize bore",
			"disposition": "rework",
			"disposition_authority": "Material Review Board",
		},
		{
			"id": "NCR-6",
			"description": "surface finish out of tolerance",
			"disposition": "use_as_is",
			"disposition_authority": "Material Review Board",
			"customer_authorized": true,
		},
	]},
	"kpis": {
		"on_time_delivery": {
			"value": 96.5,
			"target": 95,
			"period_end": "2026-10-31",
		},
		"conformity": {
			"value": 99.2,
			"target": 98,
			"period_end": "2026-10-31",
		},
	},
	"internal_audit": {
		"programme": {"planned": [{
			"id": "IA-2026-1",
			"scope": "clause 8 operation",
			"scheduled_on": "2026-03-15",
		}]},
		"audits": [{
			"id": "IA-2026-1",
			"completed_on": "2026-03-20",
			"report_issued": true,
		}],
	},
	"management_review": {"reviews": [{
		"held_on": "2026-06-15",
		"outputs_recorded": true,
	}]},
	"corrective_actions": {"records": [
		{
			"id": "CA-9",
			"nonconformity_id": "NCR-5",
			"root_cause": "worn fixture locator",
			"human_factors_considered": true,
			"status": "closed",
			"closed_on": "2026-08-01",
			"effectiveness_reviewed": true,
		},
		{
			"id": "CA-10",
			"nonconformity_id": "NCR-6",
			"root_cause": "polishing wheel grade",
			"human_factors_considered": true,
			"status": "open",
			"due_on": "2027-01-15",
		},
	]},
}}

# A copy with one attestation withdrawn.
without_attestation(id) := json.remove(full, [concat("/", ["as9100d", "attestations", id])])

# A copy with one evidence root removed (the fact-decided clause under it must then FAIL-CLOSED).
without_evidence(path) := json.remove(full, [concat("/", ["as9100d", path])])

# A copy with a sub-tree replaced.
with_patch(path, value) := json.patch(full, [{"op": "replace", "path": concat("/", ["as9100d", path]), "value": value}])
