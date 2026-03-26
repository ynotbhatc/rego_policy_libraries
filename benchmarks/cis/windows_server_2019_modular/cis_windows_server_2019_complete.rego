package cis_windows_server_2019

# CIS Microsoft Windows Server 2022 Benchmark v1.0.0 - Complete Validation
# MODULAR architecture with validation modules
# Coverage: ~400+ controls

import rego.v1

# Import all validation modules
import data.cis_windows_server_2019.account_policies
import data.cis_windows_server_2019.local_policies
import data.cis_windows_server_2019.event_log
import data.cis_windows_server_2019.system_services
import data.cis_windows_server_2019.registry
import data.cis_windows_server_2019.security_options
import data.cis_windows_server_2019.advanced_audit
import data.cis_windows_server_2019.windows_defender
import data.cis_windows_server_2019.bitlocker

# =============================================================================
# MAIN COMPLIANCE RULE
# =============================================================================

compliant if {
	account_policies.compliant
	local_policies.compliant
	event_log.compliant
	system_services.compliant
	registry.compliant
	security_options.compliant
	advanced_audit.compliant
	windows_defender.compliant
	bitlocker.compliant
}

# =============================================================================
# AGGREGATE VIOLATIONS
# =============================================================================

violations_array_1 := array.concat(
	[v | some v in account_policies.violations],
	[v | some v in local_policies.violations],
)

violations_array_2 := array.concat(
	[v | some v in event_log.violations],
	[v | some v in system_services.violations],
)

violations_array_3 := array.concat(
	array.concat([v | some v in registry.violations], [v | some v in security_options.violations]),
	array.concat([v | some v in advanced_audit.violations], [v | some v in windows_defender.violations]),
)

all_violations := array.concat(
	array.concat(violations_array_1, violations_array_2),
	array.concat(violations_array_3, [v | some v in bitlocker.violations]),
)

# =============================================================================
# SECTION-LEVEL COMPLIANCE
# =============================================================================

section_compliance := {
	"section_1_account_policies": {
		"compliant": account_policies.compliant,
		"violation_count": count(account_policies.violations),
	},
	"section_2_local_policies": {
		"compliant": local_policies.compliant,
		"violation_count": count(local_policies.violations),
	},
	"section_3_event_log": {
		"compliant": event_log.compliant,
		"violation_count": count(event_log.violations),
	},
	"section_5_system_services": {
		"compliant": system_services.compliant,
		"violation_count": count(system_services.violations),
	},
	"section_6_registry": {
		"compliant": registry.compliant,
		"violation_count": count(registry.violations),
	},
	"section_7_security_options": {
		"compliant": security_options.compliant,
		"violation_count": count(security_options.violations),
	},
	"section_8_advanced_audit": {
		"compliant": advanced_audit.compliant,
		"violation_count": count(advanced_audit.violations),
	},
	"section_9_windows_defender": {
		"compliant": windows_defender.compliant,
		"violation_count": count(windows_defender.violations),
	},
	"section_10_bitlocker": {
		"compliant": bitlocker.compliant,
		"violation_count": count(bitlocker.violations),
	},
}

# =============================================================================
# COMPLIANCE SUMMARY
# =============================================================================

total_violations := count(all_violations)

compliant_sections := [name |
	some name, section in section_compliance
	section.compliant == true
]

total_sections := count(section_compliance)

compliance_percentage := (count(compliant_sections) / total_sections) * 100

overall_status := "compliant" if {
	compliance_percentage == 100
} else := "non_compliant" if {
	compliance_percentage >= 80
} else := "critical"

# Risk levels
critical_risks := [v |
	some v in all_violations
	contains(lower(v), "critical")
]

high_risks := [v |
	some v in all_violations
	contains(lower(v), "high")
]

overall_risk_level := "critical" if {
	count(critical_risks) > 0
} else := "high" if {
	count(high_risks) > 5
} else := "medium" if {
	count(high_risks) > 0
} else := "low"

# =============================================================================
# EXECUTIVE SUMMARY
# =============================================================================

executive_summary := {
	"overall_compliance": overall_status,
	"compliance_percentage": compliance_percentage,
	"total_violations": total_violations,
	"risk_level": overall_risk_level,
	"critical_issues": count(critical_risks),
	"high_issues": count(high_risks),
	"sections_compliant": count(compliant_sections),
	"sections_total": total_sections,
}

# =============================================================================
# COMPLIANCE ASSESSMENT (Main Entry Point)
# =============================================================================

compliance_assessment := {
	"summary": executive_summary,
	"section_compliance": section_compliance,
	"violations": all_violations,
	"risk_breakdown": {
		"critical": critical_risks,
		"high": high_risks,
	},
}

# =============================================================================
# RECOMMENDATIONS
# =============================================================================

generate_recommendations := [recommendation |
	some violation in all_violations
	recommendation := {
		"violation": violation,
		"remediation": sprintf("Review and implement CIS Windows Server 2022 control: %s", [violation]),
	}
]
