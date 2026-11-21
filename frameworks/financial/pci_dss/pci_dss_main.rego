# PCI DSS v4.0.1 - Main Aggregation Policy (All 12 Requirements)
# Comprehensive PCI DSS compliance assessment for payment card industry

# METADATA
# title: "PCI DSS v4.0.1 - Main Aggregation Policy (All 12 Requirements)"
# custom:
#   class: compliance
#   framework: pci_dss
#   source: pci-ssc
#   domains: [financial, payment-cards]
#   coverage:
#     checks: 17
#     cited: 4
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package pci_dss.main

import rego.v1

import data.pci_dss.access_control.requirement_7
import data.pci_dss.access_control.requirement_8
import data.pci_dss.data_protection.requirement_3
import data.pci_dss.data_protection.requirement_4
import data.pci_dss.governance.requirement_12
import data.pci_dss.logging_monitoring.requirement_10
import data.pci_dss.malware_protection.requirement_5
import data.pci_dss.network_security.requirement_1
import data.pci_dss.physical_security.requirement_9
import data.pci_dss.secure_development.requirement_6
import data.pci_dss.security_testing.requirement_11
import data.pci_dss.system_hardening.requirement_2

# =================================================================
# ALL 12 PCI DSS REQUIREMENTS
# =================================================================

default requirement_1_compliant := false

requirement_1_compliant if requirement_1.pci_requirement_1_compliant # Network Security Controls

default requirement_2_compliant := false

requirement_2_compliant if requirement_2.pci_requirement_2_compliant # Secure Configurations

default requirement_3_compliant := false

requirement_3_compliant if requirement_3.pci_requirement_3_compliant # Protect Stored CHD

default requirement_4_compliant := false

requirement_4_compliant if requirement_4.pci_requirement_4_compliant # Protect CHD in Transit

default requirement_5_compliant := false

requirement_5_compliant if requirement_5.pci_requirement_5_compliant # Malware Protection

default requirement_6_compliant := false

requirement_6_compliant if requirement_6.pci_requirement_6_compliant # Secure Development

default requirement_7_compliant := false

requirement_7_compliant if requirement_7.pci_requirement_7_compliant # Restrict Access

default requirement_8_compliant := false

requirement_8_compliant if requirement_8.pci_requirement_8_compliant # User Authentication

default requirement_9_compliant := false

requirement_9_compliant if requirement_9.pci_requirement_9_compliant # Physical Access

default requirement_10_compliant := false

requirement_10_compliant if requirement_10.pci_requirement_10_compliant # Logging & Monitoring

default requirement_11_compliant := false

requirement_11_compliant if requirement_11.pci_requirement_11_compliant # Security Testing

default requirement_12_compliant := false

requirement_12_compliant if requirement_12.pci_requirement_12_compliant # Governance & Policy

# =================================================================
# PCI DSS LEVEL DETERMINATION
# =================================================================

# Card-brand merchant levels (not a PCI DSS requirement). A non-numeric volume gives "Unknown".
_vol := v if {
	v := input.pci.transaction_volume.annual
	is_number(v)
}

pci_validation_level := level if {
	is_number(_vol)
	_vol >= 6000000
	level := "Level 1"
} else := level if {
	is_number(_vol)
	_vol >= 1000000
	level := "Level 2"
} else := level if {
	is_number(_vol)
	_vol >= 20000
	level := "Level 3"
} else := level if {
	is_number(_vol)
	_vol < 20000
	level := "Level 4"
} else := "Unknown"

# Cardholder Data Environment (CDE) scope validation
default cde_scope_defined := false

cde_scope_defined if {
	input.pci.cde.boundaries.documented == true
	input.pci.cde.systems.inventoried == true
	input.pci.cde.data_flows.mapped == true
	input.pci.cde.network_diagram.current == true
}

# =================================================================
# OVERALL COMPLIANCE
# =================================================================

default all_requirements_compliant := false

all_requirements_compliant if {
	requirement_1_compliant
	requirement_2_compliant
	requirement_3_compliant
	requirement_4_compliant
	requirement_5_compliant
	requirement_6_compliant
	requirement_7_compliant
	requirement_8_compliant
	requirement_9_compliant
	requirement_10_compliant
	requirement_11_compliant
	requirement_12_compliant
}

default pci_program_management := false

pci_program_management if {
	input.pci.program.policies.established == true
	input.pci.program.roles.defined == true
	input.pci.program.training.conducted == true
	input.pci.program.documentation.maintained == true
	input.pci.program.risk_assessment.performed_annually == true
}

default overall_pci_dss_compliant := false

overall_pci_dss_compliant if {
	all_requirements_compliant
	cde_scope_defined
	pci_program_management
}

# Count of passing requirements (out of 12)
requirements_passing := count([r |
	some r in [
		requirement_1_compliant,
		requirement_2_compliant,
		requirement_3_compliant,
		requirement_4_compliant,
		requirement_5_compliant,
		requirement_6_compliant,
		requirement_7_compliant,
		requirement_8_compliant,
		requirement_9_compliant,
		requirement_10_compliant,
		requirement_11_compliant,
		requirement_12_compliant,
	]
	r == true
])

# =================================================================
# SCORING (weighted — data protection and access control weighted highest)
# =================================================================

requirement_scores := {
	"req_1_network_security": requirement_1.pci_requirement_1_score,
	"req_2_system_hardening": requirement_2.pci_requirement_2_score,
	"req_3_stored_data": requirement_3.pci_requirement_3_score,
	"req_4_transmission_security": requirement_4.pci_requirement_4_score,
	"req_5_malware_protection": requirement_5.pci_requirement_5_score,
	"req_6_secure_development": requirement_6.pci_requirement_6_score,
	"req_7_access_restriction": requirement_7.pci_requirement_7_score,
	"req_8_authentication": requirement_8.pci_requirement_8_score,
	"req_9_physical_access": requirement_9.pci_requirement_9_score,
	"req_10_logging_monitoring": requirement_10.pci_requirement_10_score,
	"req_11_security_testing": requirement_11.pci_requirement_11_score,
	"req_12_governance": requirement_12.pci_requirement_12_score,
}

pci_dss_compliance_score := score if {
	score := (((((((((((requirement_1.pci_requirement_1_score * 0.08) + (requirement_2.pci_requirement_2_score * 0.08)) + (requirement_3.pci_requirement_3_score * 0.12)) + (requirement_4.pci_requirement_4_score * 0.10)) + (requirement_5.pci_requirement_5_score * 0.07)) + (requirement_6.pci_requirement_6_score * 0.08)) + (requirement_7.pci_requirement_7_score * 0.10)) + (requirement_8.pci_requirement_8_score * 0.12)) + (requirement_9.pci_requirement_9_score * 0.05)) + (requirement_10.pci_requirement_10_score * 0.08)) + (requirement_11.pci_requirement_11_score * 0.07)) + (requirement_12.pci_requirement_12_score * 0.05)
}

# =================================================================
# DETAILED FINDINGS REPORT
# =================================================================

pci_dss_detailed_findings := {
	"standard": "PCI DSS v4.0.1",
	"validation_level": pci_validation_level,
	"requirements_passing": requirements_passing,
	"requirements_total": 12,
	"compliance_status": {
		"req_1_network_security": requirement_1_compliant,
		"req_2_system_hardening": requirement_2_compliant,
		"req_3_stored_data": requirement_3_compliant,
		"req_4_transmission_security": requirement_4_compliant,
		"req_5_malware_protection": requirement_5_compliant,
		"req_6_secure_development": requirement_6_compliant,
		"req_7_access_restriction": requirement_7_compliant,
		"req_8_authentication": requirement_8_compliant,
		"req_9_physical_access": requirement_9_compliant,
		"req_10_logging_monitoring": requirement_10_compliant,
		"req_11_security_testing": requirement_11_compliant,
		"req_12_governance": requirement_12_compliant,
		"all_requirements_compliant": all_requirements_compliant,
		"cde_scope_defined": cde_scope_defined,
		"overall_pci_dss_compliant": overall_pci_dss_compliant,
	},
	"scores": {
		"by_requirement": requirement_scores,
		"overall_weighted": pci_dss_compliance_score,
	},
	"requirement_details": {
		"requirement_1": requirement_1.pci_requirement_1_findings,
		"requirement_2": requirement_2.pci_requirement_2_findings,
		"requirement_3": requirement_3.pci_requirement_3_findings,
		"requirement_4": requirement_4.pci_requirement_4_findings,
		"requirement_5": requirement_5.pci_requirement_5_findings,
		"requirement_6": requirement_6.pci_requirement_6_findings,
		"requirement_7": requirement_7.pci_requirement_7_findings,
		"requirement_8": requirement_8.pci_requirement_8_findings,
		"requirement_9": requirement_9.pci_requirement_9_findings,
		"requirement_10": requirement_10.pci_requirement_10_findings,
		"requirement_11": requirement_11.pci_requirement_11_findings,
		"requirement_12": requirement_12.pci_requirement_12_findings,
	},
}

# Framework-key entrypoint: the product reads /v1/data/pci_dss/main/compliance_report. This package
# names its report `pci_dss_detailed_findings`; expose it under the shared name with an explicit `compliant` and a
# fail-closed default so the entrypoint is never undefined.
default compliance_report := {
	"framework_key": "pci_dss",
	"compliant": false,
	"fail_closed": true,
	"violations": [{"control": "FAIL-CLOSED", "title": "no report produced for pci_dss; this is not a passing result"}],
	"violation_count": 1,
	"failed_controls": 1,
	"total_controls": 1,
}

# =================================================================
# EVIDENCE MISSING vs FAIL
# =================================================================

# A failing check is a real failure when one of its alternatives holds a fact that is present and
# non-compliant; otherwise, when a fact it reads is absent or of the wrong type (a boolean not a boolean, a
# number not a number), it is "evidence missing" and the finding names the input paths. "false" terms are
# applicability gates (in_scope == false and the like): a gate that does not exempt is not itself a failure.
# Each requirement module's evidence_spec (scripts/gen_pci_dss_evidence_spec.py) lists its gating checks.
_value(path) := object.get(input, split(path, "."), null)

_typed(test, v) if {
	test in {"true", "false"}
	is_boolean(v)
}

_typed(test, v) if {
	test in {"ge", "le", "within"}
	is_number(v)
}

_typed("str_ge", v) if is_string(v)

_term_paths(t) := [t[0], t[2]] if {
	t[1] == "within"
} else := [t[0]]

_term_missing(t) := {concat(".", ["input", p]) | some p in _term_paths(t); not _typed(t[1], _value(p))}

_term_bad(t) if {
	t[1] == "true"
	_value(t[0]) == false
}

_term_bad(t) if {
	t[1] == "ge"
	v := _value(t[0])
	is_number(v)
	v < t[2]
}

_term_bad(t) if {
	t[1] == "le"
	v := _value(t[0])
	is_number(v)
	v > t[2]
}

_term_bad(t) if {
	t[1] == "within"
	a := _value(t[0])
	d := _value(t[2])
	is_number(a)
	is_number(d)
	not _within(a, d)
}

_term_bad(t) if {
	t[1] == "str_ge"
	v := _value(t[0])
	is_string(v)
	v < t[2]
}

_within(a, d) if {
	is_number(a)
	is_number(d)
	d > 0
	a <= d
}

# A gate that does not exempt (in_scope true where the alternative needs false) closes that alternative.
_gate_closed(t) if {
	t[1] == "false"
	_value(t[0]) == true
}

_alt_closed(alt) if {
	some t in alt
	_term_bad(t)
}

_alt_closed(alt) if {
	some t in alt
	_gate_closed(t)
}

_alt_missing(alt) := {p | some t in alt; some p in _term_missing(t)}

# The facts to collect: those missing from the alternatives still open (no fact present and wrong) that
# need the fewest of them, so another route's facts are not demanded once one route is nearly evidenced.
_check_missing(spec) := sort(union({m | some m in open; count(m) == least})) if {
	open := [_alt_missing(alt) | some alt in spec.alternatives; not _alt_closed(alt)]
	count(open) > 0
	least := min({count(m) | some m in open})
} else := sort({p | some alt in spec.alternatives; some p in _alt_missing(alt)})

_check_status(spec) := "fail" if {
	some alt in spec.alternatives
	some t in alt
	_term_bad(t)
} else := "evidence_missing" if {
	count(_check_missing(spec)) > 0
} else := "fail"

# Failing gating checks of one requirement: {"check", "status", "evidence_missing" (input paths)}.
_failing_checks(specs) := [{"check": name, "status": st, "evidence_missing": missing} |
	some name, spec in specs
	spec.passed != true
	st := _check_status(spec)
	missing := [p | st == "evidence_missing"; some p in _check_missing(spec)]
]

_requirements := [
	{"id": "req_1_network_security", "requirement": 1, "compliant": requirement_1_compliant, "specs": requirement_1.evidence_spec},
	{"id": "req_2_system_hardening", "requirement": 2, "compliant": requirement_2_compliant, "specs": requirement_2.evidence_spec},
	{"id": "req_3_stored_data", "requirement": 3, "compliant": requirement_3_compliant, "specs": requirement_3.evidence_spec},
	{"id": "req_4_transmission_security", "requirement": 4, "compliant": requirement_4_compliant, "specs": requirement_4.evidence_spec},
	{"id": "req_5_malware_protection", "requirement": 5, "compliant": requirement_5_compliant, "specs": requirement_5.evidence_spec},
	{"id": "req_6_secure_development", "requirement": 6, "compliant": requirement_6_compliant, "specs": requirement_6.evidence_spec},
	{"id": "req_7_access_restriction", "requirement": 7, "compliant": requirement_7_compliant, "specs": requirement_7.evidence_spec},
	{"id": "req_8_authentication", "requirement": 8, "compliant": requirement_8_compliant, "specs": requirement_8.evidence_spec},
	{"id": "req_9_physical_access", "requirement": 9, "compliant": requirement_9_compliant, "specs": requirement_9.evidence_spec},
	{"id": "req_10_logging_monitoring", "requirement": 10, "compliant": requirement_10_compliant, "specs": requirement_10.evidence_spec},
	{"id": "req_11_security_testing", "requirement": 11, "compliant": requirement_11_compliant, "specs": requirement_11.evidence_spec},
	{"id": "req_12_governance", "requirement": 12, "compliant": requirement_12_compliant, "specs": requirement_12.evidence_spec},
]

# A requirement fails when any failing check is a real failure (or none is listed, e.g. a mocked roll-up);
# it is evidence_missing when every failing check lacks evidence.
_requirement_status(r, checks) := "pass" if {
	r.compliant == true
} else := "fail" if {
	some c in checks
	c.status == "fail"
} else := "evidence_missing" if {
	count(checks) > 0
} else := "fail"

_names_with(checks, st) := [c.check | some c in checks; c.status == st]

_paths_of(checks) := sort({p | some c in checks; some p in c.evidence_missing})

# A finding names at most ten paths (an empty collection would otherwise give a title of several KB); the
# full list is requirement_results[_].evidence_missing.
_path_list(paths) := concat(", ", paths) if {
	count(paths) <= 10
} else := sprintf("%v and %d more (requirement_results lists them all)", [
	concat(", ", array.slice(paths, 0, 10)),
	count(paths) - 10,
])

# Finding text keeps the literal "PCI DSS v4.0.1 <requirement id>" prefix.
_requirement_title(id, "evidence_missing", checks) := sprintf(
	"PCI DSS v4.0.1 %v: evidence missing for %v — not collected or not of the expected type: %v",
	[id, concat(", ", _names_with(checks, "evidence_missing")), _path_list(_paths_of(checks))],
)

_requirement_title(id, "fail", checks) := sprintf("PCI DSS v4.0.1 %v is not compliant", [id]) if {
	count(checks) == 0
}

_requirement_title(id, "fail", checks) := sprintf("PCI DSS v4.0.1 %v is not compliant (failing checks: %v)", [
	id,
	concat(", ", _names_with(checks, "fail")),
]) if {
	count(checks) > 0
	count(_names_with(checks, "evidence_missing")) == 0
}

_requirement_title(id, "fail", checks) := sprintf(
	"PCI DSS v4.0.1 %v is not compliant (failing checks: %v); evidence missing for %v: %v",
	[
		id,
		concat(", ", _names_with(checks, "fail")),
		concat(", ", _names_with(checks, "evidence_missing")),
		_path_list(_paths_of(checks)),
	],
) if {
	count(_names_with(checks, "evidence_missing")) > 0
}

# Per-requirement results, passes included, in requirement order (the NIST control_results model):
#   pass              the requirement's gating checks all pass
#   fail              at least one failing check has a present, non-compliant fact
#   evidence_missing  every failing check lacks a fact it reads (evidence_missing lists the input paths)
requirement_results := [res |
	some r in _requirements
	checks := _failing_checks(r.specs)
	st := _requirement_status(r, checks)
	res := {
		"id": r.id,
		"requirement": r.requirement,
		"status": st,
		"failing_checks": _names_with(checks, "fail"),
		"evidence_missing_checks": _names_with(checks, "evidence_missing"),
		"evidence_missing": _paths_of(checks),
	}
]

requirement_result_counts := {s: count([r | some r in requirement_results; r.status == s]) |
	some s in ["pass", "fail", "evidence_missing"]
}

# The product reads violations, violation_count and total_controls: the twelve requirements are the units this
# aggregator decides on, so a failing requirement is one finding and total_controls is 12.
_requirement_violations := [v |
	some r in _requirements
	r.compliant != true
	checks := _failing_checks(r.specs)
	st := _requirement_status(r, checks)
	v := {"control": r.id, "status": st, "title": _requirement_title(r.id, st, checks)}
]

# CDE scope and program management gate overall_pci_dss_compliant, so a gap there is listed too (control ids stay
# literal), with the same evidence-missing distinction.
_scope_program_specs := {
	"cde_scope": {
		"passed": cde_scope_defined,
		"alternatives": [[
			["pci.cde.boundaries.documented", "true"],
			["pci.cde.systems.inventoried", "true"],
			["pci.cde.data_flows.mapped", "true"],
			["pci.cde.network_diagram.current", "true"],
		]],
		"failure": "PCI DSS v4.0.1 CDE scope is not defined and documented (cde_scope)",
	},
	"program_management": {
		"passed": pci_program_management,
		"alternatives": [[
			["pci.program.policies.established", "true"],
			["pci.program.roles.defined", "true"],
			["pci.program.training.conducted", "true"],
			["pci.program.documentation.maintained", "true"],
			["pci.program.risk_assessment.performed_annually", "true"],
		]],
		"failure": "PCI DSS v4.0.1 program management is not established (program_management)",
	},
}

_scope_program_title(spec, "evidence_missing") := sprintf("%v: evidence missing — not collected or not of the expected type: %v", [
	spec.failure,
	_path_list(_check_missing(spec)),
])

_scope_program_title(spec, "fail") := spec.failure

_scope_program_violations := [v |
	some id in ["cde_scope", "program_management"]
	spec := _scope_program_specs[id]
	spec.passed != true
	st := _check_status(spec)
	v := {"control": id, "status": st, "title": _scope_program_title(spec, st)}
]

_all_violations := array.concat(_requirement_violations, _scope_program_violations)

compliance_report := object.union(pci_dss_detailed_findings, {
	"framework_key": "pci_dss",
	"compliant": _entrypoint_compliant,
	"violations": _all_violations,
	"requirement_results": requirement_results,
	"requirement_result_counts": requirement_result_counts,
	"violation_count": count(_all_violations),
	"failed_controls": min([_declared_controls, count(_all_violations)]),
	"total_controls": _declared_controls,
})

_declared_controls := 12

default _entrypoint_compliant := false

_entrypoint_compliant if {
	pci_dss_detailed_findings.requirements_passing == pci_dss_detailed_findings.requirements_total
	overall_pci_dss_compliant
}
