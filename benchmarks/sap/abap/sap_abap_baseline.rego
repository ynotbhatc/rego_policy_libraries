# METADATA
# title: "SAP Security Baseline Template v2.6 — ABAP stack, host-collectable checks"
# custom:
#   class: security
#   framework: sap_abap_baseline
#   source: sap
#   domains: [sap, erp, linux]
#   coverage:
#     checks: 2
#     cited: 1
#     density: stub
#     basis: size
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
package sap_abap_baseline.main

import rego.v1

import data.sap_abap_baseline.mappings
import data.sap_abap_baseline.registry

# SAP Security Baseline Template v2.6 (ABAP) — one canonical catalog, several framework views.
#
# What this is
#   SAP publishes its Baseline Template checks as Focused Run CSA policies (Apache-2.0):
#   https://github.com/SAP-samples/frun-csa-policies-best-practices, BaselinePolicies/SOS/v2.6/ABAP_ALL.
#   scripts/import_sap_baseline.py reads them and writes the registry (every check SAP publishes, 355 for the
#   ABAP stack) and one Rego rule per check whose condition is decidable from facts a collector can read on the
#   SAP host as <sid>adm without RFC or database access: profile parameters, transport-tool parameters, the
#   kernel banner and the CommonCryptoLib version. Gateway / message-server ACL files and the date-based
#   checks are hand-written in sap_abap_baseline_manual.rego. Everything else (user tables, authorizations,
#   audit slots, RFC destinations, clients ...) stays in the registry as not assessable, with the store named,
#   so no projection ever overstates coverage.
#
#   The canonical control id IS SAP's check id (PWDPOL-A_a.1, RFCGW-A_a secinfo.2 ...): it is public, stable
#   across Template versions and what an SAP auditor recognises. A synthetic SAP-ABAP-0001 layer would add a
#   lookup for nothing.
#
# Query
#   POST /v1/data/sap_abap_baseline/main/compliance_report
#
# Input contract — input.sap.abap.*   (every value a STRING as the host presents it; the collector never
# interprets)
#
#   profile              "critical" | "standard" | "extended"   (default "extended" = every check;
#                        SAP's priorities p1-CRITICAL / p2-STANDARD / p3-EXTENDED; "standard" = p1+p2)
#   profile_parameters   { "<name>": "<value>", ... }  the EFFECTIVE profile parameters of the assessed
#                        instance (sappfpar / RZ11 view: DEFAULT.PFL overlaid by the instance profile, kernel
#                        defaults included when the collector can resolve them). A parameter that is absent
#                        is reported as "not set in the collected facts" and FAILS its check — fail-closed,
#                        the kernel default is not evidence.
#   transport_parameters { "TLOGOCHECK": "1", "RECCLIENT": "ALL", "TP_RELEASE": "380.44.90", ... }
#                        from TP_DOMAIN_<SID>.PFL / tp parameters
#   kernel               { "KERN_REL": "793_REL", "KERN_PATCHLEVEL": "150", "KERN_COMP_TIME": "Jan 15 2026" }
#                        from `disp+work -version` (names follow SAP's SAP_KERNEL store)
#   cryptolib            { "CCL": "8.5.50", "CCL_DATE": "2025-11-03" }  CommonCryptoLib version and build date
#   gateway              { "secinfo":  { "present": true, "lines": ["P TP=* USER=* HOST=* USER-HOST=*", ...] },
#                          "reginfo":  { "present": true, "lines": [...] },
#                          "prxyinfo": { "present": false, "lines": [] } }
#   message_server       { "acl": { "present": true, "lines": ["HOST=*", ...] } }
#   collected_at         "YYYY-MM-DD" (or RFC 3339) — the date the facts were read; date-based checks measure
#                        against it so a stored result stays reproducible. Absent: OPA's clock.
#
# Report
#   controls_evaluated   assessable checks in the selected profile
#   violations           "<check id>: <SAP requirement text> (<state>)"
#   violation_details    [{id, level, severity, requirement, message}] — the same, with the registry's severity
#   not_assessable       every check the library does not evaluate, with the reason
#   results              {check id: compliant | violation | not_assessable | out_of_profile}
#   projections          per-framework views (Baseline requirements, DSAG S/4HANA audit guide sections,
#                        NIST CSF 2.0 subcategories) derived from the same results through the mapping tables
#
# Fail-closed: empty input yields every in-profile check as a violation (nothing is set).

# ---------------------------------------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------------------------------------
_levels := {
	"critical": {"critical"},
	"standard": {"critical", "standard"},
	"extended": {"critical", "standard", "extended"},
}

default profile := "extended"

profile := p if {
	p := input.sap.abap.profile
	_levels[p]
}

level_in_profile(level) if level in _levels[profile]

violations contains msg if {
	p := input.sap.abap.profile
	not _levels[p]
	msg := sprintf("SAP-INPUT: unrecognized profile %v — must be one of critical, standard, extended (evaluated as extended)", [p])
}

# ---------------------------------------------------------------------------------------------------------
# Fact access helpers (used by the generated and the manual rules)
# ---------------------------------------------------------------------------------------------------------
has(key, name) if {
	_ = input.sap.abap[key][name]
}

# The value as a string, whatever the collector sent (numbers are tolerated, booleans are not evidence).
fact(key, name) := v if {
	raw := input.sap.abap[key][name]
	is_string(raw)
	v := raw
}

fact(key, name) := v if {
	raw := input.sap.abap[key][name]
	is_number(raw)
	v := sprintf("%v", [raw])
}

state(key, name) := s if {
	v := fact(key, name)
	s := sprintf("is %q", [v])
}

state(key, name) := "not set in the collected facts" if not fact(key, name)

facts_matching(key, pattern) := [v |
	some name, raw in input.sap.abap[key]
	regex.match(pattern, name)
	v := fact(key, name)
]

pattern_state(key, pattern) := s if {
	ms := facts_matching(key, pattern)
	count(ms) > 0
	s := sprintf("%d matching parameter(s): %v", [count(ms), ms])
}

pattern_state(key, pattern) := "no matching parameter in the collected facts" if {
	count(facts_matching(key, pattern)) == 0
}

# Numeric comparisons on string values — only a value that is a number can satisfy one.
_numeric(v) if regex.match(`^-?[0-9]+$`, trim_space(v))

num_ge(v, n) if {
	_numeric(v)
	to_number(trim_space(v)) >= n
}

num_gt(v, n) if {
	_numeric(v)
	to_number(trim_space(v)) > n
}

num_le(v, n) if {
	_numeric(v)
	to_number(trim_space(v)) <= n
}

num_lt(v, n) if {
	_numeric(v)
	to_number(trim_space(v)) < n
}

num_eq(v, n) if {
	_numeric(v)
	to_number(trim_space(v)) == n
}

num_ne(v, n) if {
	_numeric(v)
	to_number(trim_space(v)) != n
}

num_between(v, lo, hi) if {
	_numeric(v)
	x := to_number(trim_space(v))
	x >= lo
	x <= hi
}

# Dotted version comparison ("380.44.90"): each component zero-padded, then compared as strings. A value with
# trailing text ("380.44.90 (Unicode)") is compared on its leading dotted-number prefix.
_ver_key(v) := k if {
	m := regex.find_n(`^[0-9]+(\.[0-9]+)*`, trim_space(v), 1)
	count(m) == 1
	k := concat(".", [sprintf("%08d", [to_number(p)]) | some p in split(m[0], ".")])
}

ver_ge(v, w) if _ver_key(v) >= _ver_key(w)

ver_gt(v, w) if _ver_key(v) > _ver_key(w)

ver_le(v, w) if _ver_key(v) <= _ver_key(w)

ver_lt(v, w) if _ver_key(v) < _ver_key(w)

# ---------------------------------------------------------------------------------------------------------
# Results — materialised once as complete values (object/set comprehensions), so the projections' thousands
# of lookups are hash lookups, not rule re-evaluations.
# ---------------------------------------------------------------------------------------------------------
default compliant := false

compliant if count(violations) == 0

_assessable_ids := {id | some id, c in registry.checks; c.assessable}

_evaluated_ids := {id | some id in _assessable_ids; level_in_profile(registry.checks[id].level)}

# The check id is everything before the first ": " of a violation message.
_violated_ids := {id |
	some msg in violations
	i := indexof(msg, ": ")
	i > 0
	id := substring(msg, 0, i)
}

results := {id: status |
	some id, c in registry.checks
	status := _status(id, c)
}

_status(id, c) := "not_assessable" if {
	not c.assessable
} else := "out_of_profile" if {
	not id in _evaluated_ids
} else := "violation" if {
	id in _violated_ids
} else := "compliant"

# One row per violation with the registry's level and severity, for consumers that store evidence rows
# (the message alone carries only the id).
violation_details := [{"id": id, "level": c.level, "severity": c.severity, "requirement": c.requirement, "message": msg} |
	some msg in violations
	i := indexof(msg, ": ")
	i > 0
	id := substring(msg, 0, i)
	c := registry.checks[id]
]

not_assessable := [{"id": id, "level": c.level, "reason": c.reason, "stores": c.stores} |
	some id, c in registry.checks
	not c.assessable
]

# ---------------------------------------------------------------------------------------------------------
# Framework projections: the same results, viewed through a mapping table. A reference whose canonical ids
# are all unassessed (or that has none) is listed as not_assessable — never dropped.
# ---------------------------------------------------------------------------------------------------------
_projection(m) := {
	"framework": m.framework,
	"references": rows,
	"summary": {
		"references": count(rows),
		"compliant": count([r | some r in rows; r.status == "compliant"]),
		"violation": count([r | some r in rows; r.status == "violation"]),
		"not_assessable": count([r | some r in rows; r.status == "not_assessable"]),
	},
} if {
	rows := [row | some ref in m.references; row := _projection_row(ref)]
}

_projection_row(ref) := {
	"ref": ref.ref,
	"title": ref.title,
	"status": _row_status(vio, comp),
	"canonical": ref.canonical,
	"violations": vio,
	"compliant": comp,
	"not_assessable": [id | some id in ref.canonical; results[id] == "not_assessable"],
	"out_of_profile": [id | some id in ref.canonical; results[id] == "out_of_profile"],
} if {
	vio := [id | some id in ref.canonical; results[id] == "violation"]
	comp := [id | some id in ref.canonical; results[id] == "compliant"]
}

_row_status(vio, comp) := "violation" if {
	count(vio) > 0
} else := "compliant" if {
	count(comp) > 0
} else := "not_assessable"

projections := {
	"baseline": _projection(mappings.baseline),
	"dsag_s4hana": _projection(mappings.dsag),
	"nist_csf_2_0": _projection(mappings.nist_csf_2_0),
}

# ---------------------------------------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------------------------------------
compliance_report := {
	"benchmark": registry.benchmark,
	"version": "2.6.0",
	"source": sprintf("SAP-samples/frun-csa-policies-best-practices @ %s (Apache-2.0)", [registry.source_commit]),
	"profile": profile,
	"controls_evaluated": count(_evaluated_ids),
	"registry_total": count(registry.checks),
	"assessable_total": count(_assessable_ids),
	"not_assessable_count": count(not_assessable),
	"not_assessable": not_assessable,
	"results": results,
	"violations": violations,
	"violation_details": violation_details,
	"violation_count": count(violations),
	"compliant": compliant,
	"projections": projections,
}
