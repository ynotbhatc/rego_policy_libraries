# METADATA
# title: "CMMC 2.0 — Domain 3.9: Personnel Security"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 10
#     cited: 2
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package cmmc.personnel_security

import rego.v1

# =============================================================================
# CMMC 2.0 — Domain 3.9: Personnel Security
# NIST SP 800-171 Rev 2 — 2 Practices
# =============================================================================

# 3.9.1 — Screen individuals prior to authorizing access to organizational
#          systems containing CUI. (L2)
default compliant_3_9_1 := false

compliant_3_9_1 if {
	input.personnel.pre_employment_screening == true
	input.personnel.background_check_required == true
	input.personnel.screening_records_maintained == true
}

violation_3_9_1 contains msg if {
	not input.personnel.pre_employment_screening == true
	finding := "3.9.1: Pre-employment screening is not performed before granting CUI access"
	msg := concat("", [finding, _ev_input("personnel.pre_employment_screening")])
}

violation_3_9_1 contains msg if {
	not input.personnel.background_check_required == true
	finding := "3.9.1: Background checks are not required for personnel accessing CUI systems"
	msg := concat("", [finding, _ev_input("personnel.background_check_required")])
}

violation_3_9_1 contains msg if {
	not input.personnel.screening_records_maintained == true
	finding := "3.9.1: Personnel screening records are not maintained"
	msg := concat("", [finding, _ev_input("personnel.screening_records_maintained")])
}

# 3.9.2 — Ensure that CUI is protected during and after personnel actions
#          such as terminations and transfers. (L2)
default compliant_3_9_2 := false

compliant_3_9_2 if {
	input.personnel.termination_procedure_exists == true
	input.personnel.access_revoked_on_termination == true
	input.personnel.equipment_returned_on_termination == true
	input.personnel.transfer_access_reviewed == true
}

violation_3_9_2 contains msg if {
	not input.personnel.termination_procedure_exists == true
	finding := "3.9.2: No documented procedure for revoking CUI access upon termination"
	msg := concat("", [finding, _ev_input("personnel.termination_procedure_exists")])
}

violation_3_9_2 contains msg if {
	not input.personnel.access_revoked_on_termination == true
	finding := "3.9.2: CUI system access is not revoked immediately upon personnel termination"
	msg := concat("", [finding, _ev_input("personnel.access_revoked_on_termination")])
}

violation_3_9_2 contains msg if {
	not input.personnel.equipment_returned_on_termination == true
	finding := "3.9.2: Equipment and credentials are not retrieved upon personnel termination"
	msg := concat("", [finding, _ev_input("personnel.equipment_returned_on_termination")])
}

violation_3_9_2 contains msg if {
	not input.personnel.transfer_access_reviewed == true
	finding := "3.9.2: CUI access privileges are not reviewed when personnel transfer roles"
	msg := concat("", [finding, _ev_input("personnel.transfer_access_reviewed")])
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

base_violations := array.concat(
	[v | some v in violation_3_9_1],
	[v | some v in violation_3_9_2],
)

practices := [
	{"id": "3.9.1", "level": 2, "compliant": compliant_3_9_1},
	{"id": "3.9.2", "level": 2, "compliant": compliant_3_9_2},
]

# ---------------------------------------------------------------------------
# Unmet practices without a specific finding (fail closed)
#   A practice whose compliant_N rule is false because a required fact is
#   missing must surface a violation, so the domain verdict can never be true
#   while a practice fails.
# ---------------------------------------------------------------------------

violation_unmet contains msg if {
	some p in practices
	not p.compliant == true
	count([v | some v in base_violations; startswith(v, sprintf("%v:", [p.id]))]) == 0
	msg := sprintf("%v: evidence missing or requirement not met — all facts required by this practice must be present and passing", [p.id])
}

all_violations := array.concat(base_violations, sort(violation_unmet))

passing_count := count([p | some p in practices; p.compliant == true])

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"domain": "Personnel Security",
	"domain_id": "3.9",
	"total_practices": 2,
	"passing": passing_count,
	"failing": 2 - passing_count,
	"compliant": compliant,
	"violations": all_violations,
	"practices": practices,
}

# ---------------------------------------------------------------------------
# Evidence rule: only the boolean true passes a yes/no fact. A fact that is
# absent, null or not a boolean fails its check, and the finding names the
# evidence problem.
# ---------------------------------------------------------------------------

default _facts := {}

_facts := input

_evidence_note(value, name) := "" if {
	is_boolean(value)
} else := sprintf(" (evidence missing: %s not collected)", [name]) if {
	value == null
} else := sprintf(" (evidence invalid: %s is not a boolean, got %s)", [name, type_name(value)])

_ev_input(path) := _evidence_note(object.get(_facts, split(path, "."), null), concat(".", ["input", path]))

_ev_item(item, path) := _evidence_note(object.get(item, split(path, "."), null), path) if {
	is_object(item)
} else := sprintf(" (evidence invalid: item is not an object, got %s; %s not collected)", [type_name(item), path])
