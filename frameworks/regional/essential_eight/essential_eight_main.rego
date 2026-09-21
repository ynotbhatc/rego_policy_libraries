# ACSC Essential Eight Maturity Model (Nov 2023) — master orchestrator
#
# Aggregates the 8 mitigation strategies and applies the ACSC maturity rule:
# an organisation is at Maturity Level N only if EVERY strategy meets all of its
# requirements up to and including level N, so the overall maturity level is the
# LOWEST strategy's achieved level. Fail-closed: an unattested requirement is a gap.
#
# Entry point: data.essential_eight.main.compliance_report

package essential_eight.main

import rego.v1

import data.essential_eight.application_control
import data.essential_eight.multi_factor_authentication
import data.essential_eight.office_macros
import data.essential_eight.patch_applications
import data.essential_eight.patch_operating_systems
import data.essential_eight.regular_backups
import data.essential_eight.restrict_admin_privileges
import data.essential_eight.user_application_hardening

strategy_reports := [
	application_control.compliance_report,
	patch_applications.compliance_report,
	office_macros.compliance_report,
	user_application_hardening.compliance_report,
	restrict_admin_privileges.compliance_report,
	patch_operating_systems.compliance_report,
	multi_factor_authentication.compliance_report,
	regular_backups.compliance_report,
]

all_violations := [v | some r in strategy_reports; some v in r.violations]

# Attestation object for a strategy, defaulted to {} so the report is robust to
# entirely-absent input (the standard bare `opa eval` verify command).
default _attest(_) := {}

_attest(strat) := input.essential_eight[strat].requirements

_specs := [
	{"key": "application_control", "req": application_control.requirements},
	{"key": "patch_applications", "req": patch_applications.requirements},
	{"key": "office_macros", "req": office_macros.requirements},
	{"key": "user_application_hardening", "req": user_application_hardening.requirements},
	{"key": "restrict_admin_privileges", "req": restrict_admin_privileges.requirements},
	{"key": "patch_operating_systems", "req": patch_operating_systems.requirements},
	{"key": "multi_factor_authentication", "req": multi_factor_authentication.requirements},
	{"key": "regular_backups", "req": regular_backups.requirements},
]

# id -> {strategy, level, met}. Requirement ids are unique across strategies (distinct prefixes).
_all[id] := {"strategy": spec.key, "level": m.level, "met": object.get(_attest(spec.key), id, false) == true} if {
	some spec in _specs
	some id, m in spec.req
}

total_requirements := count(_all)

requirements_met := count([id | some id, c in _all; c.met])

# Coverage per maturity level.
maturity_by_level[lvl] := {"total": total, "met": met} if {
	some lvl in {c.level | some _, c in _all}
	total := count([id | some id, c in _all; c.level == lvl])
	met := count([id | some id, c in _all; c.level == lvl; c.met])
}

# A strategy meets level n if every requirement at level <= n is met (cumulative).
_meets(strat, n) if {
	reqs := {id | some id, c in _all; c.strategy == strat; c.level <= n}
	count(reqs) > 0
	every id in reqs { _all[id].met }
}

# Achieved level per strategy = count of satisfied cumulative levels (monotonic 1..3).
strategy_maturity_level[strat] := lvl if {
	some spec in _specs
	strat := spec.key
	lvl := count([n | some n in [1, 2, 3]; _meets(strat, n)])
}

# ACSC rule: overall maturity = the lowest strategy's achieved level.
overall_maturity_level := min([lvl | some _, lvl in strategy_maturity_level])

# Per-strategy rollup, keyed by strategy name.
strategies[name] := {"requirements": r.requirements_evaluated, "gaps": r.violation_count, "compliant": r.compliant} if {
	some r in strategy_reports
	name := r.strategy
}

default compliant := false

compliant if count(all_violations) == 0

compliance_report := {
	"framework": "ACSC Essential Eight Maturity Model (Nov 2023)",
	"strategies_evaluated": count(strategy_reports),
	"total_requirements": total_requirements,
	"requirements_met": requirements_met,
	"overall_maturity_level": overall_maturity_level,
	"maturity_by_level": maturity_by_level,
	"strategy_maturity_level": strategy_maturity_level,
	"strategies": strategies,
	"violations": all_violations,
	"violation_count": count(all_violations),
	"compliant": compliant,
}
