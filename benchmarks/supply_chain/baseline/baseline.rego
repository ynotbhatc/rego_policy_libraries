# AAC Supply-Chain Baseline — the default check (the supply-chain spine)
#
# Evaluates the seven invariant substrate themes directly. This is the "default
# check" any software-supply-chain effort runs: one assessment against the
# spine, which each framework (SLSA, SSDF, ...) then projects from.
package supply_chain.baseline

import rego.v1

import data.supply_chain.substrate

total_controls := count(substrate.themes)

passed_controls := count(substrate.satisfied)

failed_controls := count(substrate.unsatisfied)

violations contains msg if {
	some k in substrate.unsatisfied
	t := substrate.themes[k]
	msg := sprintf("Supply-chain baseline: '%s' not satisfied (800-53 %v)", [t.title, t.families])
}

default compliant := false

compliant if count(violations) == 0

# Structured report — every field sourced through a defaulted helper so one
# undefined value cannot collapse the whole object to {} (library rule #5).
compliance_report := {
	"benchmark": "AAC Supply-Chain Baseline (spine)",
	"total_controls": total_controls,
	"passed_controls": passed_controls,
	"failed_controls": failed_controls,
	"compliance_percentage": pct,
	"violations": violations,
	"compliant": compliant,
}

default pct := 0.0

pct := round((passed_controls / total_controls) * 1000) / 10 if total_controls > 0
