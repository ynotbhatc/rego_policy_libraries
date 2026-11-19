# METADATA
# title: "NIST SP 800-53 Rev 5 — Supply Chain Risk Management (SR) Family"
# custom:
#   class: compliance
#   framework: nist_sp_800_53
#   source: nist
#   domains: [us-federal, security-controls]
#   coverage:
#     checks: 15
#     cited: 15
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.5.0
package nist.sp800_53.supply_chain_risk

import rego.v1

# NIST SP 800-53 Rev 5 — Supply Chain Risk Management (SR) Family: the twelve active base controls SR-1 to
# SR-12, and the Moderate-baseline enhancements SR-2(1), SR-11(1) and SR-11(2). Each enhancement is its own
# requirement with its own finding; a base control never fails on an enhancement's requirement. Facts live under
# input.sr_controls.

default compliant := false

_root := "sr_controls"

# ---------------------------------------------------------------------------------------------------------
# Evidence helpers. Every value is read with object.get(..., null), so an absent key, null, or a value of
# the wrong type ("true", "1") lands in the "missing" set and the control fails closed. Each control builds
# one set of missing paths and one set of unmet requirements and has exactly one rule, so it can produce at
# most one finding.
# ---------------------------------------------------------------------------------------------------------

_val(path) := object.get(input, array.concat([_root], path), null)

_p(path) := concat(".", array.concat(["input", _root], path))

# Booleans: reqs maps a fact key to the text reported when that fact is false. Only `true` passes.
_bool_missing(sec, reqs) := {_p(array.concat(sec, [k])) | some k, _ in reqs; not is_boolean(_val(array.concat(sec, [k])))}

_bool_unmet(sec, reqs) := {d | some k, d in reqs; _val(array.concat(sec, [k])) == false}

# Organization-defined frequency: observed <sec>.days_since_last against <sec>.odp.frequency_days.
_freq_keys := [["days_since_last"], ["odp", "frequency_days"]]

_freq_missing(sec) := {_p(array.concat(sec, k)) | some k in _freq_keys; not is_number(_val(array.concat(sec, k)))}

_freq_unmet(sec, what) := {d |
	obs := _val(array.concat(sec, ["days_since_last"]))
	odp := _val(array.concat(sec, ["odp", "frequency_days"]))
	is_number(obs)
	is_number(odp)
	obs > odp
	d := sprintf("%s last %v days ago; the organization-defined frequency is %v days", [what, obs, odp])
}

# Counts that must be zero (e.g. overdue remediations). A non-number is missing evidence.
_zero_missing(sec, k) := {_p(array.concat(sec, [k])) | not is_number(_val(array.concat(sec, [k])))}

_zero_unmet(sec, k, what) := {d |
	n := _val(array.concat(sec, [k]))
	is_number(n)
	n > 0
	d := sprintf("%v %s", [n, what])
}

# Attestation for organizational controls: {"attested": true, "by": <non-empty string>, "date": <non-empty string>}.
_att_ok(a) if {
	a.attested == true
	is_string(a.by)
	trim_space(a.by) != ""
	is_string(a.date)
	trim_space(a.date) != ""
}

_att_detail(sec, what) := d if {
	not _att_ok(_val(array.concat(sec, ["attestation"])))
	d := sprintf("evidence missing — no valid attestation at %s (needs attested: true and a non-empty by and date); this organizational control is evidenced by attestation only: %s", [_p(array.concat(sec, ["attestation"])), what])
}

# Policy and procedures (the -1 control of the family).
_pp_bools := {"documented": "policy not documented", "official_designated": "no official designated to manage the policy and procedures"}

_pp_missing := ((_bool_missing(["policy"], _pp_bools) | _bool_missing(["procedures"], {"documented": ""})) | _freq_missing(["policy"])) | _freq_missing(["procedures"])

_pp_unmet := ((_bool_unmet(["policy"], _pp_bools) | _bool_unmet(["procedures"], {"documented": "procedures not documented"})) | _freq_unmet(["policy"], "policy reviewed")) | _freq_unmet(["procedures"], "procedures reviewed")

# One finding text: the missing evidence first, then every unmet requirement.
_mpart(m) := [] if {
	count(m) == 0
} else := [sprintf("evidence missing — %s not collected", [concat(", ", sort(m))])]

_detail(m, u) := concat("; ", array.concat(_mpart(m), sort(u)))

# ---------------------------------------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------------------------------------

# SR-1 Policy and Procedures: input.sr_controls.policy.{documented, official_designated, days_since_last,
# odp.frequency_days} and input.sr_controls.procedures.{documented, days_since_last, odp.frequency_days}.
violation contains msg if {
	count(_pp_missing) + count(_pp_unmet) > 0
	msg := sprintf("NIST SR-1: supply chain risk management policy and procedures: %s", [_detail(_pp_missing, _pp_unmet)])
}

# SR-2 Supply Chain Risk Management Plan: input.sr_controls.scrm_plan.{documented, protected, days_since_last,
# odp.frequency_days}; days_since_last is the age of the plan's last review and update.
_sr2 := {
	"documented": "no plan for managing supply chain risks across the life cycle of the organization-defined systems, components or services",
	"protected": "the supply chain risk management plan is not protected from unauthorized disclosure and modification",
}

violation contains msg if {
	sec := ["scrm_plan"]
	m := _bool_missing(sec, _sr2) | _freq_missing(sec)
	u := _bool_unmet(sec, _sr2) | _freq_unmet(sec, "supply chain risk management plan reviewed and updated")
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-2: %s", [_detail(m, u)])
}

# SR-3 Supply Chain Controls and Processes: input.sr_controls.supply_chain_controls.{weakness_process_established,
# controls_employed, documented}.
_sr3 := {
	"weakness_process_established": "no process to identify and address weaknesses or deficiencies in supply chain elements and processes",
	"controls_employed": "the organization-defined supply chain controls are not employed",
	"documented": "the selected and implemented supply chain processes and controls are not documented",
}

violation contains msg if {
	m := _bool_missing(["supply_chain_controls"], _sr3)
	u := _bool_unmet(["supply_chain_controls"], _sr3)
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-3: %s", [_detail(m, u)])
}

# SR-4 Provenance: input.sr_controls.provenance.{monitored, components_without_provenance}.
# components_without_provenance counts organization-defined systems, components and associated data with no valid,
# documented provenance (for example an SBOM or a signed build attestation).
violation contains msg if {
	sec := ["provenance"]
	b := {"monitored": "provenance is not monitored and maintained"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "components_without_provenance")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "components_without_provenance", "systems, components or associated data have no valid documented provenance")
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-4: %s", [_detail(m, u)])
}

# SR-5 Acquisition Strategies, Tools, and Methods: input.sr_controls.acquisition_strategies.attestation
# (organizational).
violation contains msg if {
	d := _att_detail(["acquisition_strategies"], "the organization-defined acquisition strategies, contract tools and procurement methods are employed against supply chain risks")
	msg := sprintf("NIST SR-5: %s", [d])
}

# SR-6 Supplier Assessments and Reviews: input.sr_controls.supplier_assessments.{days_since_last,
# odp.frequency_days}.
violation contains msg if {
	sec := ["supplier_assessments"]
	m := _freq_missing(sec)
	u := _freq_unmet(sec, "supplier supply chain risks assessed and reviewed")
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-6: %s", [_detail(m, u)])
}

# SR-7 Supply Chain Operations Security: input.sr_controls.supply_chain_opsec.attestation (organizational).
violation contains msg if {
	d := _att_detail(["supply_chain_opsec"], "the organization-defined OPSEC controls protect supply chain-related information")
	msg := sprintf("NIST SR-7: %s", [d])
}

# SR-8 Notification Agreements: input.sr_controls.notification_agreements.entities_without_agreement, the number of
# supply chain entities with no agreement and procedures for the organization-defined notifications.
violation contains msg if {
	sec := ["notification_agreements"]
	m := _zero_missing(sec, "entities_without_agreement")
	u := _zero_unmet(sec, "entities_without_agreement", "supply chain entities have no notification agreement and procedures")
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-8: %s", [_detail(m, u)])
}

# SR-9 Tamper Resistance and Detection: input.sr_controls.tamper_protection.program_implemented.
violation contains msg if {
	b := {"program_implemented": "no tamper protection program implemented for the system, component or service"}
	m := _bool_missing(["tamper_protection"], b)
	u := _bool_unmet(["tamper_protection"], b)
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-9: %s", [_detail(m, u)])
}

# SR-10 Inspection of Systems or Components: input.sr_controls.inspection.{days_since_last, odp.frequency_days};
# days_since_last is the age of the last tamper inspection of the organization-defined systems or components.
violation contains msg if {
	sec := ["inspection"]
	m := _freq_missing(sec)
	u := _freq_unmet(sec, "systems or components inspected for tampering")
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-10: %s", [_detail(m, u)])
}

# SR-11 Component Authenticity: input.sr_controls.anti_counterfeit.{policy_procedures_implemented,
# detection_prevention, reporting_defined}.
_sr11 := {
	"policy_procedures_implemented": "no anti-counterfeit policy and procedures developed and implemented",
	"detection_prevention": "no means to detect and prevent counterfeit components from entering the system",
	"reporting_defined": "counterfeit components are not reported to the organization-defined parties",
}

violation contains msg if {
	m := _bool_missing(["anti_counterfeit"], _sr11)
	u := _bool_unmet(["anti_counterfeit"], _sr11)
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-11: %s", [_detail(m, u)])
}

# SR-12 Component Disposal: input.sr_controls.component_disposal.{methods_defined, disposals_without_approved_method};
# disposals_without_approved_method counts disposals of the organization-defined data, documentation, tools or
# components not done with the organization-defined techniques and methods.
violation contains msg if {
	sec := ["component_disposal"]
	b := {"methods_defined": "no disposal techniques and methods defined"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "disposals_without_approved_method")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "disposals_without_approved_method", "disposals did not use the organization-defined techniques and methods")
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-12: %s", [_detail(m, u)])
}

# ---------------------------------------------------------------------------------------------------------
# Moderate-baseline enhancements (SP 800-53B). Facts nest under the base control's object.
# ---------------------------------------------------------------------------------------------------------

# SR-2(1) Establish SCRM Team: input.sr_controls.scrm_plan.team.{established, unfilled_roles}. established is
# true when a supply chain risk management team is chartered to lead and support the organization-defined SCRM
# activities; unfilled_roles counts the organization-defined team roles with no assigned member.
violation contains msg if {
	sec := ["scrm_plan", "team"]
	b := {"established": "no supply chain risk management team established to lead and support the organization-defined SCRM activities"}
	m := _bool_missing(sec, b) | _zero_missing(sec, "unfilled_roles")
	u := _bool_unmet(sec, b) | _zero_unmet(sec, "unfilled_roles", "organization-defined SCRM team roles have no assigned member")
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-2(1): %s", [_detail(m, u)])
}

# SR-11(1) Anti-counterfeit Training: input.sr_controls.anti_counterfeit.training.untrained_personnel, the number
# of people in the organization-defined personnel or roles with no completed training in detecting counterfeit
# hardware, software and firmware components (from the training record).
violation contains msg if {
	sec := ["anti_counterfeit", "training"]
	m := _zero_missing(sec, "untrained_personnel")
	u := _zero_unmet(sec, "untrained_personnel", "organization-defined personnel are not trained to detect counterfeit system components")
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-11(1): %s", [_detail(m, u)])
}

# SR-11(2) Configuration Control for Component Service and Repair: input.sr_controls.anti_counterfeit.
# service_repair.components_without_configuration_control, the number of organization-defined components
# awaiting service or repair, or repaired and awaiting return to service, that are not under configuration
# control (no tracked custody and configuration record).
violation contains msg if {
	sec := ["anti_counterfeit", "service_repair"]
	m := _zero_missing(sec, "components_without_configuration_control")
	u := _zero_unmet(sec, "components_without_configuration_control", "components awaiting or returning from service or repair are not under configuration control")
	count(m) + count(u) > 0
	msg := sprintf("NIST SR-11(2): %s", [_detail(m, u)])
}

compliant if count(violation) == 0

# The control and enhancement ids this family evaluates; each has exactly one finding when it fails.
evaluated_controls := {
	"SR-1", "SR-2", "SR-2(1)", "SR-3", "SR-4", "SR-5", "SR-6", "SR-7",
	"SR-8", "SR-9", "SR-10", "SR-11", "SR-11(1)", "SR-11(2)", "SR-12",
}

compliance_report := {
	"family": "SR",
	"name": "Supply Chain Risk Management",
	"controls_evaluated": count(evaluated_controls),
	"violations": violation,
	"violation_count": count(violation),
	"compliant": compliant,
}
