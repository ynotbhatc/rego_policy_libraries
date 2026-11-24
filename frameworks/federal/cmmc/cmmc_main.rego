# METADATA
# title: "CMMC (32 CFR Part 170) — Level 1 / Level 2 practice scoring over the fourteen domain modules"
# custom:
#   class: compliance
#   framework: cmmc
#   source: dod
#   domains: [us-federal, defense]
#   coverage:
#     checks: 50
#     cited: 17
#     density: orchestrator
#     basis: role
#     tested: true
#     entrypoint: none
#     guard: self
#     as_of: v2.5.0
package cmmc

import rego.v1

# =============================================================================
# CMMC Program — 32 CFR Part 170 (final rule, effective 2024-12-16)
#
# What a level is (32 CFR 170.14(c), eCFR, read 2026-11-17):
#   Level 1  the 15 basic safeguarding requirements of FAR 52.204-21(b)(1)(i)-(xv)
#   Level 2  the 110 security requirements of NIST SP 800-171 Rev 2
#   Level 3  24 selected NIST SP 800-172 requirements (170.14(c)(4) Table 1),
#            assessed on top of a Final Level 2 (C3PAO) status
#
# Requirement ids (170.14(c)(1)): DD.L#-REQ, where REQ is the FAR 52.204-21
# paragraph number at Level 1 (AC.L1-b.1.i ... SI.L1-b.1.xv), the NIST SP
# 800-171 R2 requirement number at Level 2 (AC.L2-3.1.1 ... SI.L2-3.14.7) and the
# NIST SP 800-172 number at Level 3 (AC.L3-3.1.2e ...). The DoD CIO assessment
# guides (Level 1 and Level 2, version 2.13, September 2024) use the same ids.
# The CMMC 2.0 model documents of 2021 numbered Level 1 as 17 practices with
# 800-171 numbers (AC.L1-3.1.1, PE.L1-3.10.3 ...); those ids are superseded and
# are not used here.
#
# Source of truth for counting: the three registries below. The domain modules
# evaluate NIST SP 800-171 R2 requirements (their findings start with the
# requirement number, "3.5.1: ..." or "CMMC AC.L2-3.1.3: ..."); this package
# maps them to the practices of the assessed level:
#   - a Level 2 practice is satisfied when its domain reports the requirement
#     compliant and no finding names it;
#   - a Level 1 requirement is satisfied when every 800-171 R2 requirement that
#     carries the same safeguard is satisfied (b.1.ix = 3.10.3 + 3.10.4 + 3.10.5);
#   - failed practices are counted once per practice, however many findings
#     name it, so failed <= total by construction;
#   - total = the practices of the assessed level that this package evaluates
#     (15 at Level 1, 110 at Level 2; Level 3 evaluates the 110 Level 2
#     practices and reports the 24 Level 3 requirements as not evaluated).
# Fail-closed: a missing or invalid input.cmmc_level, Level 3, or a domain
# finding that names no requirement is an input-contract finding and the report
# is non-compliant; with no valid level every practice is reported failed.
# =============================================================================

# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------

# Domain abbreviation of each NIST SP 800-171 R2 family (32 CFR 170.14(b)).
families := {
	"3.1": "AC", "3.2": "AT", "3.3": "AU", "3.4": "CM", "3.5": "IA", "3.6": "IR", "3.7": "MA",
	"3.8": "MP", "3.9": "PS", "3.10": "PE", "3.11": "RA", "3.12": "CA", "3.13": "SC", "3.14": "SI",
}

# Level 2: the 110 NIST SP 800-171 R2 requirement numbers (generated from
# frameworks/federal/nist/sp_800_171_r2, the NIST CPRT export).
level_2_requirements := [
	"3.1.1", "3.1.2", "3.1.3", "3.1.4", "3.1.5", "3.1.6", "3.1.7", "3.1.8", "3.1.9", "3.1.10", "3.1.11", "3.1.12", "3.1.13", "3.1.14", "3.1.15", "3.1.16", "3.1.17", "3.1.18", "3.1.19", "3.1.20", "3.1.21", "3.1.22",
	"3.2.1", "3.2.2", "3.2.3",
	"3.3.1", "3.3.2", "3.3.3", "3.3.4", "3.3.5", "3.3.6", "3.3.7", "3.3.8", "3.3.9",
	"3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5", "3.4.6", "3.4.7", "3.4.8", "3.4.9",
	"3.5.1", "3.5.2", "3.5.3", "3.5.4", "3.5.5", "3.5.6", "3.5.7", "3.5.8", "3.5.9", "3.5.10", "3.5.11",
	"3.6.1", "3.6.2", "3.6.3",
	"3.7.1", "3.7.2", "3.7.3", "3.7.4", "3.7.5", "3.7.6",
	"3.8.1", "3.8.2", "3.8.3", "3.8.4", "3.8.5", "3.8.6", "3.8.7", "3.8.8", "3.8.9",
	"3.9.1", "3.9.2",
	"3.10.1", "3.10.2", "3.10.3", "3.10.4", "3.10.5", "3.10.6",
	"3.11.1", "3.11.2", "3.11.3",
	"3.12.1", "3.12.2", "3.12.3", "3.12.4",
	"3.13.1", "3.13.2", "3.13.3", "3.13.4", "3.13.5", "3.13.6", "3.13.7", "3.13.8", "3.13.9", "3.13.10", "3.13.11", "3.13.12", "3.13.13", "3.13.14", "3.13.15", "3.13.16",
	"3.14.1", "3.14.2", "3.14.3", "3.14.4", "3.14.5", "3.14.6", "3.14.7",
]

# Level 1: FAR 52.204-21(b)(1) paragraphs and the NIST SP 800-171 R2 requirements
# that state the same safeguard (the R2 text matches the FAR text paragraph for
# paragraph; (ix) is split over three R2 requirements).
level_1_requirements := [
	{"id": "AC.L1-b.1.i", "nist": ["3.1.1"]},
	{"id": "AC.L1-b.1.ii", "nist": ["3.1.2"]},
	{"id": "AC.L1-b.1.iii", "nist": ["3.1.20"]},
	{"id": "AC.L1-b.1.iv", "nist": ["3.1.22"]},
	{"id": "IA.L1-b.1.v", "nist": ["3.5.1"]},
	{"id": "IA.L1-b.1.vi", "nist": ["3.5.2"]},
	{"id": "MP.L1-b.1.vii", "nist": ["3.8.3"]},
	{"id": "PE.L1-b.1.viii", "nist": ["3.10.1"]},
	{"id": "PE.L1-b.1.ix", "nist": ["3.10.3", "3.10.4", "3.10.5"]},
	{"id": "SC.L1-b.1.x", "nist": ["3.13.1"]},
	{"id": "SC.L1-b.1.xi", "nist": ["3.13.5"]},
	{"id": "SI.L1-b.1.xii", "nist": ["3.14.1"]},
	{"id": "SI.L1-b.1.xiii", "nist": ["3.14.2"]},
	{"id": "SI.L1-b.1.xiv", "nist": ["3.14.4"]},
	{"id": "SI.L1-b.1.xv", "nist": ["3.14.5"]},
]

# Level 3: 32 CFR 170.14(c)(4) Table 1. Listed so the report can name them; no
# fact model exists for them in this library, so they are never scored as met.
level_3_requirements := [
	"AC.L3-3.1.2e", "AC.L3-3.1.3e", "AT.L3-3.2.1e", "AT.L3-3.2.2e", "CM.L3-3.4.1e", "CM.L3-3.4.2e",
	"CM.L3-3.4.3e", "IA.L3-3.5.1e", "IA.L3-3.5.3e", "IR.L3-3.6.1e", "IR.L3-3.6.2e", "PS.L3-3.9.2e",
	"RA.L3-3.11.1e", "RA.L3-3.11.2e", "RA.L3-3.11.3e", "RA.L3-3.11.4e", "RA.L3-3.11.5e", "RA.L3-3.11.6e",
	"RA.L3-3.11.7e", "CA.L3-3.12.1e", "SC.L3-3.13.4e", "SI.L3-3.14.1e", "SI.L3-3.14.3e", "SI.L3-3.14.6e",
]

# Sizes of each level in the regulation (not the evaluated counts; see report).
standard_sizes := {"level_1": 15, "level_2": 110, "level_3": 24}

# ---------------------------------------------------------------------------
# Domain reports (delegated to submodules)
# ---------------------------------------------------------------------------

# Default-safe: on empty input a submodule report may be undefined; the stub
# carries the fields read here and decides nothing as met.
default ac_report := {"compliant": false, "level_1_passing": false, "passing": 0, "violations": [], "practices": []}

ac_report := data.cmmc.access_control.compliance_report

default at_report := {"compliant": false, "passing": 0, "violations": [], "practices": []}

at_report := data.cmmc.awareness_training.compliance_report

default au_report := {"compliant": false, "passing": 0, "violations": [], "practices": []}

au_report := data.cmmc.audit_accountability.compliance_report

default cm_report := {"compliant": false, "passing": 0, "violations": [], "practices": []}

cm_report := data.cmmc.configuration_management.compliance_report

default ia_report := {"compliant": false, "level_1_passing": false, "passing": 0, "violations": [], "practices": []}

ia_report := data.cmmc.identification_authentication.compliance_report

default ir_report := {"compliant": false, "passing": 0, "violations": [], "practices": []}

ir_report := data.cmmc.incident_response.compliance_report

default ma_report := {"compliant": false, "passing": 0, "violations": [], "practices": []}

ma_report := data.cmmc.maintenance.compliance_report

default mp_report := {"compliant": false, "level_1_passing": false, "passing": 0, "violations": [], "practices": []}

mp_report := data.cmmc.media_protection.compliance_report

default ps_report := {"compliant": false, "passing": 0, "violations": [], "practices": []}

ps_report := data.cmmc.personnel_security.compliance_report

default pe_report := {"compliant": false, "level_1_passing": false, "passing": 0, "violations": [], "practices": []}

pe_report := data.cmmc.physical_protection.compliance_report

default rm_report := {"compliant": false, "passing": 0, "violations": [], "practices": []}

rm_report := data.cmmc.risk_assessment.compliance_report

default ca_report := {"compliant": false, "passing": 0, "violations": [], "practices": []}

ca_report := data.cmmc.security_assessment.compliance_report

default sc_report := {"compliant": false, "level_1_passing": false, "passing": 0, "violations": [], "practices": []}

sc_report := data.cmmc.system_communications_protection.compliance_report

default si_report := {"compliant": false, "level_1_passing": false, "passing": 0, "violations": [], "practices": []}

si_report := data.cmmc.system_information_integrity.compliance_report

# Family -> domain report.
domain_reports := {
	"3.1": ac_report, "3.2": at_report, "3.3": au_report, "3.4": cm_report, "3.5": ia_report,
	"3.6": ir_report, "3.7": ma_report, "3.8": mp_report, "3.9": ps_report, "3.10": pe_report,
	"3.11": rm_report, "3.12": ca_report, "3.13": sc_report, "3.14": si_report,
}

# Every domain finding, in family order (domain modules expose sets or arrays).
all_violations := [m | some f in _family_order; some m in domain_reports[f].violations]

_family_order := ["3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"]

# ---------------------------------------------------------------------------
# Assessed level
# ---------------------------------------------------------------------------

# A number 1, 2 or 3; "2" (string), 0, 4 or absent is not a level.
assessed_level := input.cmmc_level if {
	is_number(input.cmmc_level)
	input.cmmc_level in {1, 2, 3}
}

# The level as supplied (null when absent, or when OPA received no input document at all).
default _stated_level := null

_stated_level := input.cmmc_level

default level_valid := false

level_valid if assessed_level

# ---------------------------------------------------------------------------
# Requirement status (NIST SP 800-171 R2 numbers)
# ---------------------------------------------------------------------------

# Written with intermediate bindings: OPA 1.22.0 fails with eval_internal_error ("split called with operand that
# requires evaluation") when the nested call is inlined into the comprehension that indexes domain_reports.
_family(r) := fam if {
	parts := split(r, ".")
	head := array.slice(parts, 0, 2)
	fam := concat(".", head)
}

# The requirement number a domain finding names: "3.5.1: ...", "CMMC AC.L2-3.1.3: ..."
# or "CMMC AC.L1-b.1.i / AC.L2-3.1.1: ...".
finding_requirement(m) := x[0][1] if {
	is_string(m)
	x := regex.find_all_string_submatch_n(`^(?:CMMC [A-Z]{2}\.L[12]-(?:b\.1\.[ivx]+ / [A-Z]{2}\.L2-)?)?(3\.[0-9]{1,2}\.[0-9]{1,2}):`, m, 1)
	count(x) == 1
}

_requirement_findings(r) := found if {
	fam := _family(r)
	found := [m | some m in domain_reports[fam].violations; finding_requirement(m) == r]
}

_domain_reports_compliant(r) if {
	some p in domain_reports[_family(r)].practices
	p.id == r
	p.compliant == true
}

# Satisfied only on positive evidence: a valid level, the domain's own verdict
# for the requirement, and no finding naming it.
requirement_satisfied(r) if {
	level_valid
	_domain_reports_compliant(r)
	count(_requirement_findings(r)) == 0
}

_all_satisfied(rs) if {
	every r in rs {
		requirement_satisfied(r)
	}
}

level_2_id(r) := sprintf("%s.L2-%s", [families[_family(r)], r])

# ---------------------------------------------------------------------------
# Practices of the assessed level
# ---------------------------------------------------------------------------

_level_1_scope := [{"id": x.id, "nist": x.nist} | some x in level_1_requirements]

_level_2_scope := [{"id": level_2_id(r), "nist": [r]} | some r in level_2_requirements]

# Without a valid level the Level 2 set is reported (all failed): it contains
# every Level 1 safeguard, so nothing a Level 1 assessment needs is hidden.
practice_scope := _level_1_scope if assessed_level == 1

else := _level_2_scope

practice_status[x.id] := {"nist_sp_800_171_r2": x.nist, "satisfied": _satisfied_bool(x.nist)} if {
	some x in practice_scope
}

_satisfied_bool(rs) if _all_satisfied(rs)

else := false

failed_practices := {x.id | some x in practice_scope; not _all_satisfied(x.nist)}

practices_evaluated := count(practice_scope)

practices_failed := count(failed_practices)

practices_passing := practices_evaluated - practices_failed

# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

_strip(m) := regex.replace(m, `^[^:]+:\s*`, "")

# Domain findings restated under the practice id of the assessed level.
practice_findings contains msg if {
	some x in practice_scope
	some r in x.nist
	some m in _requirement_findings(r)
	msg := sprintf("CMMC %s: %s", [x.id, _strip(m)])
}

# A requirement the domain does not report compliant but names in no finding.
practice_findings contains msg if {
	level_valid
	some x in practice_scope
	some r in x.nist
	not requirement_satisfied(r)
	count(_requirement_findings(r)) == 0
	msg := sprintf("CMMC %s: evidence missing or requirement not met - NIST SP 800-171 R2 %s is not shown satisfied by the collected facts", [x.id, r])
}

# Without a valid level a practice that no domain finding names is still failed; say why.
practice_findings contains msg if {
	not level_valid
	some x in practice_scope
	every r in x.nist {
		count(_requirement_findings(r)) == 0
	}
	msg := sprintf("CMMC %s: not decided - the assessed level is unknown (input.cmmc_level), so the practice is reported failed", [x.id])
}

# One row per failed practice: a practice with several findings (one per user,
# one per system ...) is still one failed practice, so the rows of a report never
# outnumber the practices it declares. Every finding stays in practice_findings.
practice_rows := [row |
	some x in practice_scope
	x.id in failed_practices
	prefix := sprintf("CMMC %s: ", [x.id])
	found := sort([m | some m in practice_findings; startswith(m, prefix)])
	row := _practice_row(prefix, found)
]

_practice_row(_, found) := found[0] if count(found) == 1

_practice_row(prefix, found) := row if {
	count(found) != 1
	numbered := [sprintf("(%d) %s", [i + 1, trim_prefix(m, prefix)]) | some i, m in found]
	row := sprintf("%s%d findings - %s", [prefix, count(found), concat(" ", numbered)])
}

input_contract_findings contains "CMMC input contract: FAIL-CLOSED - input.cmmc_level was not supplied or is not the number 1, 2 or 3; the assessed level is unknown, so no practice is decided and every practice is reported failed" if {
	not level_valid
}

input_contract_findings contains msg if {
	assessed_level == 3
	msg := sprintf("CMMC Level 3: not evaluated - the %d NIST SP 800-172 requirements of 32 CFR 170.14(c)(4) (%s) have no fact model in this library; the 110 Level 2 practices were evaluated and Level 3 cannot be reported compliant", [count(level_3_requirements), concat(", ", level_3_requirements)])
}

# A finding that names no NIST SP 800-171 R2 requirement cannot be scored; it
# still blocks compliance.
input_contract_findings contains msg if {
	level_valid
	some m in all_violations
	not finding_requirement(m)
	msg := sprintf("CMMC unscored finding (names no practice): %v", [m])
}

violations := array.concat(sort(input_contract_findings), sort(practice_findings))

# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------

default compliant := false

compliant if {
	level_valid
	assessed_level != 3
	practices_failed == 0
	count(input_contract_findings) == 0
}

# Level 1 and Level 2 verdicts on the same facts, independent of the level
# assessed (a valid level is still required: see requirement_satisfied).
default cmmc_level_1_compliant := false

cmmc_level_1_compliant if {
	every x in level_1_requirements {
		_all_satisfied(x.nist)
	}
}

default cmmc_level_2_compliant := false

cmmc_level_2_compliant if {
	is_number(assessed_level)
	assessed_level >= 2
	_all_satisfied(level_2_requirements)
}

# ---------------------------------------------------------------------------
# Domain booleans (informational; a domain module judges all of its
# requirements, Level 1 and Level 2 alike)
# ---------------------------------------------------------------------------

domain_results := [_domain_ok(f) | some f in _family_order]

_domain_ok(f) if domain_reports[f].compliant == true

else := false

passing_domains := count([d | some d in domain_results; d == true])

total_domains := 14

compliance_score := round((practices_passing / practices_evaluated) * 100)

# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------

cmmc_compliance_report := {
	"standard": "CMMC Program (32 CFR Part 170)",
	"regulation": "32 CFR Part 170 / DFARS 252.204-7021",
	"level_1_source": "FAR 52.204-21(b)(1)",
	"nist_sp": "NIST SP 800-171 Rev 2",
	"assessed_level": _stated_level,
	"level_valid": level_valid,
	"compliant": compliant,
	"level_1_compliant": cmmc_level_1_compliant,
	"level_2_compliant": cmmc_level_2_compliant,
	"level_3_evaluated": false,
	"standard_sizes": standard_sizes,
	"compliance_score": compliance_score,
	"total_domains": total_domains,
	"domains_passing": passing_domains,
	"domains_failing": total_domains - passing_domains,
	"total_practices": practices_evaluated,
	"practices_passing": practices_passing,
	"practices_failing": practices_failed,
	"failed_practices": sort(failed_practices),
	"practices": practice_status,
	"total_violations": count(violations),
	"violations": violations,
	"domains": {
		"3.1_access_control": ac_report,
		"3.2_awareness_training": at_report,
		"3.3_audit_accountability": au_report,
		"3.4_configuration_management": cm_report,
		"3.5_identification_authentication": ia_report,
		"3.6_incident_response": ir_report,
		"3.7_maintenance": ma_report,
		"3.8_media_protection": mp_report,
		"3.9_personnel_security": ps_report,
		"3.10_physical_protection": pe_report,
		"3.11_risk_assessment": rm_report,
		"3.12_security_assessment": ca_report,
		"3.13_system_communications": sc_report,
		"3.14_system_information_integrity": si_report,
	},
}
