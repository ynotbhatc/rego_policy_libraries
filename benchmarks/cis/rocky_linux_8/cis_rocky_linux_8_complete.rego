package cis_rocky_linux_8

# CIS Rocky Linux 8 Benchmark v2.0.0 - Complete Validation
# MODULAR architecture with validation modules
# Coverage: ~300+ controls

import rego.v1

# Import all validation modules (will be created)
import data.cis_rocky_linux_8.filesystem
import data.cis_rocky_linux_8.initial_setup
import data.cis_rocky_linux_8.services
import data.cis_rocky_linux_8.network
import data.cis_rocky_linux_8.logging
import data.cis_rocky_linux_8.auditd
import data.cis_rocky_linux_8.ssh
import data.cis_rocky_linux_8.pam
import data.cis_rocky_linux_8.sudo
import data.cis_rocky_linux_8.selinux
import data.cis_rocky_linux_8.user_group
import data.cis_rocky_linux_8.cron
import data.cis_rocky_linux_8.file_permissions

# =============================================================================
# MAIN COMPLIANCE RULE
# =============================================================================

compliant if {
	filesystem.compliant
	initial_setup.compliant
	services.compliant
	network.compliant
	logging.compliant
	auditd.compliant
	ssh.compliant
	pam.compliant
	sudo.compliant
	selinux.compliant
	user_group.compliant
	cron.compliant
	file_permissions.compliant
}

# =============================================================================
# AGGREGATE VIOLATIONS
# =============================================================================

# Convert violation sets to arrays and concatenate
violations_array_1 := array.concat(
	array.concat([v | some v in filesystem.violations], [v | some v in initial_setup.violations]),
	[v | some v in services.violations],
)

violations_array_2 := array.concat(
	array.concat([v | some v in network.violations], [v | some v in logging.violations]),
	array.concat([v | some v in auditd.violations], [v | some v in ssh.violations]),
)

violations_array_3 := array.concat(
	array.concat([v | some v in pam.violations], [v | some v in sudo.violations]),
	array.concat([v | some v in selinux.violations], [v | some v in user_group.violations]),
)

violations_array_4 := array.concat(
	[v | some v in cron.violations],
	[v | some v in file_permissions.violations],
)

all_violations := array.concat(
	array.concat(violations_array_1, violations_array_2),
	array.concat(violations_array_3, violations_array_4),
)

# =============================================================================
# SECTION-LEVEL COMPLIANCE
# =============================================================================

section_compliance := {
	"section_1_1_filesystem": {
		"compliant": filesystem.compliant,
		"violation_count": count(filesystem.violations),
	},
	"section_1_initial_setup": {
		"compliant": initial_setup.compliant,
		"violation_count": count(initial_setup.violations),
	},
	"section_2_services": {
		"compliant": services.compliant,
		"violation_count": count(services.violations),
	},
	"section_3_network": {
		"compliant": network.compliant,
		"violation_count": count(network.violations),
	},
	"section_4_logging": {
		"compliant": logging.compliant,
		"violation_count": count(logging.violations),
	},
	"section_4_1_auditd": {
		"compliant": auditd.compliant,
		"violation_count": count(auditd.violations),
	},
	"section_5_2_ssh": {
		"compliant": ssh.compliant,
		"violation_count": count(ssh.violations),
	},
	"section_5_pam": {
		"compliant": pam.compliant,
		"violation_count": count(pam.violations),
	},
	"section_5_3_sudo": {
		"compliant": sudo.compliant,
		"violation_count": count(sudo.violations),
	},
	"section_1_6_selinux": {
		"compliant": selinux.compliant,
		"violation_count": count(selinux.violations),
	},
	"section_6_2_user_group": {
		"compliant": user_group.compliant,
		"violation_count": count(user_group.violations),
	},
	"section_5_1_cron": {
		"compliant": cron.compliant,
		"violation_count": count(cron.violations),
	},
	"section_6_1_file_permissions": {
		"compliant": file_permissions.compliant,
		"violation_count": count(file_permissions.violations),
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
	v.severity == "critical"
]

high_risks := [v |
	some v in all_violations
	v.severity == "high"
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
		"control": violation.control,
		"title": violation.title,
		"severity": violation.severity,
		"remediation": sprintf("Review and implement CIS Rocky Linux 8 control %s: %s", [violation.control, violation.title]),
	}
]
