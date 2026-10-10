# METADATA
# title: "Applicable modules based on risk tier"
# custom:
#   class: governance
#   framework: eu_ai_act
#   source: eu
#   domains: [ai, eu]
package eu_ai_act.main

import rego.v1

import data.eu_ai_act.governance
import data.eu_ai_act.gpai
import data.eu_ai_act.high_risk
import data.eu_ai_act.prohibited
import data.eu_ai_act.transparency

# =============================================================================
# Applicable modules based on risk tier
# =============================================================================

applicable_modules := modules if {
	input.eu_ai_act.system_classification.risk_tier == "prohibited"
	modules := ["prohibited_practices"]
}

applicable_modules := modules if {
	input.eu_ai_act.system_classification.risk_tier == "high_risk"
	modules := ["prohibited_practices", "high_risk_requirements", "transparency_obligations", "governance_deployer"]
}

applicable_modules := modules if {
	input.eu_ai_act.system_classification.risk_tier == "limited_risk"
	modules := ["prohibited_practices", "transparency_obligations"]
}

applicable_modules := modules if {
	input.eu_ai_act.system_classification.risk_tier == "minimal_risk"
	modules := ["prohibited_practices"]
}

applicable_modules := modules if {
	input.eu_ai_act.system_classification.risk_tier == "gpai"
	modules := ["prohibited_practices", "gpai_obligations", "governance_deployer"]
}

default applicable_modules := ["prohibited_practices"]

# =============================================================================
# Per-module compliance results
# =============================================================================

default prohibited_compliant := false

prohibited_compliant if {
	prohibited.compliant
}

default high_risk_compliant := false

high_risk_compliant if {
	high_risk.compliant
}

default transparency_compliant := false

transparency_compliant if {
	transparency.compliant
}

default gpai_compliant := false

gpai_compliant if {
	gpai.compliant
}

default governance_compliant := false

governance_compliant if {
	governance.compliant
}

# =============================================================================
# Modules passing — count only applicable modules
# =============================================================================

modules_passing := count([1 |
	some module_name in applicable_modules
	module_compliant_map[module_name] == true
])

module_compliant_map := {
	"prohibited_practices": prohibited_compliant,
	"high_risk_requirements": high_risk_compliant,
	"transparency_obligations": transparency_compliant,
	"gpai_obligations": gpai_compliant,
	"governance_deployer": governance_compliant,
}

# =============================================================================
# Overall compliance — only applicable modules count
# =============================================================================

# ---------------------------------------------------------------------------
# FAIL-CLOSED GATE (rego_policy_libraries#186)
#
# Every prohibited-practice rule fires on a fact being true. With NO facts
# nothing fires, the prohibited module reports zero violations, and before
# this gate an assessment that collected nothing was stored as a pass
# (overall_compliant: true on {}). A missing classification already gets the
# strictest tier; it must also be judged on the absence of evidence.
#
# Two conditions, both required before anything can pass:
#   _facts_supplied  input.eu_ai_act is a non-empty object
#   _classified      system_classification.risk_tier is one of the five tiers
# Each failure adds an explicit violation so the consumer sees why.
# ---------------------------------------------------------------------------

default _facts_supplied := false

_facts_supplied if {
	is_object(input.eu_ai_act)
	count(object.keys(input.eu_ai_act)) > 0
}

default _classified := false

_classified if {
	input.eu_ai_act.system_classification.risk_tier in {"prohibited", "high_risk", "limited_risk", "minimal_risk", "gpai"}
}

_no_facts_msg := "FAIL-CLOSED: no eu_ai_act facts supplied — the assessment could not be evaluated. This is NOT a passing result; supply input.eu_ai_act with system_classification.risk_tier and the per-module facts."

_unclassified_msg := "FAIL-CLOSED: input.eu_ai_act.system_classification.risk_tier is missing or not one of prohibited | high_risk | limited_risk | minimal_risk | gpai — the system is assessed at the prohibited tier and is non-compliant until it is classified."

gate_violations := [_no_facts_msg] if not _facts_supplied

gate_violations := [_unclassified_msg] if {
	_facts_supplied
	not _classified
}

gate_violations := [] if {
	_facts_supplied
	_classified
}

default overall_compliant := false

overall_compliant if {
	_facts_supplied
	_classified
	modules_passing == count(applicable_modules)
	count(applicable_modules) > 0
}

default compliant := false

compliant if {
	overall_compliant
}

# =============================================================================
# Risk tier label
# =============================================================================

# Most-conservative default: treat unknown/missing classification as "prohibited"
default risk_tier := "prohibited"

risk_tier := input.eu_ai_act.system_classification.risk_tier

# =============================================================================
# Aggregate violations — only modules applicable to the risk tier
# =============================================================================

violations_prohibited := [v |
	"prohibited_practices" in applicable_modules
	some v in prohibited.violations
]

violations_high_risk := [v |
	"high_risk_requirements" in applicable_modules
	some v in high_risk.violations
]

violations_transparency := [v |
	"transparency_obligations" in applicable_modules
	some v in transparency.violations
]

violations_gpai := [v |
	"gpai_obligations" in applicable_modules
	some v in gpai.violations
]

violations_governance := [v |
	"governance_deployer" in applicable_modules
	some v in governance.violations
]

all_violations_1 := array.concat(
	violations_prohibited,
	violations_transparency,
)

all_violations_2 := array.concat(
	violations_high_risk,
	violations_gpai,
)

all_violations := array.concat(
	array.concat(all_violations_1, all_violations_2),
	violations_governance,
)

# Gate messages first: when they are present they explain every other number.
violations := array.concat(gate_violations, all_violations)

# =============================================================================
# Top-level compliance report
# =============================================================================

compliance_report := {
	"framework": "EU Artificial Intelligence Act",
	"total_controls": 5,
	"violations": violations,
	"violation_count": count(violations),
	"standard": "EU Artificial Intelligence Act — Regulation (EU) 2024/1689",
	"compliant": compliant,
	"overall_compliant": overall_compliant,
	"facts_supplied": _facts_supplied,
	"classified": _classified,
	"risk_tier": risk_tier,
	"applicable_modules": applicable_modules,
	"modules_passing": modules_passing,
	"modules_total": 5,
	"total_violations": count(violations),
	"modules": {
		"prohibited_practices": {
			"compliant": prohibited_compliant,
			"applicable": "prohibited_practices" in applicable_modules,
			"details": prohibited.compliance_report,
		},
		"high_risk_requirements": {
			"compliant": high_risk_compliant,
			"applicable": "high_risk_requirements" in applicable_modules,
			"details": high_risk.compliance_report,
		},
		"transparency_obligations": {
			"compliant": transparency_compliant,
			"applicable": "transparency_obligations" in applicable_modules,
			"details": transparency.compliance_report,
		},
		"gpai_obligations": {
			"compliant": gpai_compliant,
			"applicable": "gpai_obligations" in applicable_modules,
			"details": gpai.compliance_report,
		},
		"governance_deployer": {
			"compliant": governance_compliant,
			"applicable": "governance_deployer" in applicable_modules,
			"details": governance.compliance_report,
		},
	},
}
