package eu_ai_act.main

import rego.v1

import data.eu_ai_act.prohibited
import data.eu_ai_act.high_risk
import data.eu_ai_act.transparency
import data.eu_ai_act.gpai
import data.eu_ai_act.governance

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

default overall_compliant := false

overall_compliant if {
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

# =============================================================================
# Top-level compliance report
# =============================================================================

compliance_report := {
	"standard": "EU Artificial Intelligence Act — Regulation (EU) 2024/1689",
	"overall_compliant": overall_compliant,
	"risk_tier": risk_tier,
	"applicable_modules": applicable_modules,
	"modules_passing": modules_passing,
	"modules_total": 5,
	"total_violations": count(all_violations),
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
