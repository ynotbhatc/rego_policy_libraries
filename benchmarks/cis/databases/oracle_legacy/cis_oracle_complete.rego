package cis_oracle

# CIS Oracle Database 19c Benchmark - Complete Validation
# Master policy that aggregates all module validations
# Coverage: Key security controls from CIS Oracle 19c Benchmark

import rego.v1

import data.cis_oracle.database_parameters
import data.cis_oracle.installation_patches
import data.cis_oracle.listener_configuration
import data.cis_oracle.user_account_management

# =============================================================================
# MAIN COMPLIANCE RULE
# =============================================================================

compliant if {
	installation_patches.compliant
	listener_configuration.compliant
	database_parameters.compliant
	user_account_management.compliant
}

# =============================================================================
# AGGREGATE VIOLATIONS
# =============================================================================

all_violations := array.concat(
	array.concat(
		installation_patches.violations,
		listener_configuration.violations,
	),
	array.concat(
		database_parameters.violations,
		user_account_management.violations,
	),
)

# =============================================================================
# SECTION-LEVEL COMPLIANCE
# =============================================================================

section_compliance := {
	"section_1_installation_patches": {
		"compliant": installation_patches.compliant,
		"description": "Installation and Patches",
		"violation_count": count(installation_patches.violations),
	},
	"section_2_1_listener_configuration": {
		"compliant": listener_configuration.compliant,
		"description": "Listener Configuration",
		"violation_count": count(listener_configuration.violations),
	},
	"section_2_2_database_parameters": {
		"compliant": database_parameters.compliant,
		"description": "Database Parameters",
		"violation_count": count(database_parameters.violations),
	},
	"section_3_user_account_management": {
		"compliant": user_account_management.compliant,
		"description": "User Account Management",
		"violation_count": count(user_account_management.violations),
	},
}

# =============================================================================
# COMPLIANCE SUMMARY
# =============================================================================

# =============================================================================
# RISK ASSESSMENT
# =============================================================================

critical_risks := array.concat(
	[v |
		some v in installation_patches.violations
		contains(v, "CRITICAL")
	],
	array.concat(
		[v |
			some v in listener_configuration.violations
			contains(v, "CRITICAL")
		],
		array.concat(
			[v |
				some v in database_parameters.violations
				contains(v, "CRITICAL")
			],
			[v |
				some v in user_account_management.violations
				contains(v, "CRITICAL")
			],
		),
	),
)

high_risks := [v |
	some v in all_violations
	contains(lower(v), "high")
	not contains(v, "CRITICAL")
]

overall_risk_level := "critical" if {
	count(critical_risks) > 0
} else := "critical" if {
	listener_configuration.risk_level == "critical"
} else := "critical" if {
	database_parameters.risk_level == "critical"
} else := "critical" if {
	user_account_management.risk_level == "critical"
} else := "high" if {
	count(high_risks) > 5
} else := "high" if {
	database_parameters.risk_level == "high"
} else := "medium" if {
	count(all_violations) > 10
} else := "low"


# =============================================================================
# ACTIONABLE RECOMMENDATIONS
# =============================================================================

generate_recommendations contains recommendation if {
	not installation_patches.compliant
	recommendation := {
		"priority": installation_patches.risk_level,
		"section": "Installation and Patches",
		"issue": sprintf("%d installation/patch violations found", [count(installation_patches.violations)]),
		"action": "Apply latest Oracle Critical Patch Updates (CPU)",
		"controls": "CIS 1.1",
	}
}

generate_recommendations contains recommendation if {
	not listener_configuration.compliant
	listener_configuration.risk_level == "critical"
	recommendation := {
		"priority": "critical",
		"section": "Listener Configuration",
		"issue": "Critical listener security issues detected",
		"action": "Remove EXTPROC, enable ADMIN_RESTRICTIONS, configure logging",
		"controls": "CIS 2.1.x",
	}
}

generate_recommendations contains recommendation if {
	not database_parameters.compliant
	database_parameters.risk_level == "critical"
	recommendation := {
		"priority": "critical",
		"section": "Database Parameters",
		"issue": "Critical database parameter misconfigurations",
		"action": "Set REMOTE_OS_AUTHENT=FALSE, enable auditing, configure security parameters",
		"controls": "CIS 2.2.x",
	}
}

generate_recommendations contains recommendation if {
	not user_account_management.compliant
	count([a | some a in input.default_accounts; a.status == "OPEN"]) > 2
	recommendation := {
		"priority": "high",
		"section": "User Account Management",
		"issue": sprintf("%d default accounts are open", [count([a | some a in input.default_accounts; a.status == "OPEN"])]),
		"action": "Lock or drop unnecessary default Oracle accounts",
		"controls": "CIS 3.1",
	}
}

generate_recommendations contains recommendation if {
	input.parameters.AUDIT_TRAIL == "NONE"
	recommendation := {
		"priority": "critical",
		"section": "Auditing",
		"issue": "Database auditing is completely disabled",
		"action": "Enable AUDIT_TRAIL (set to DB, XML, or OS)",
		"controls": "CIS 2.2.2",
	}
}
