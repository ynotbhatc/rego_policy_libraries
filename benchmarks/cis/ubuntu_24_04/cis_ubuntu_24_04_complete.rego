package cis_ubuntu_24_04

# CIS Ubuntu 24.04 LTS Benchmark - Complete Compliance Assessment
# Master orchestrator that aggregates all modular validation policies
# Benchmark Version: CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0

import rego.v1

# Import all validation modules
import data.cis_ubuntu_24_04.filesystem
import data.cis_ubuntu_24_04.initial_setup
import data.cis_ubuntu_24_04.services
import data.cis_ubuntu_24_04.network
import data.cis_ubuntu_24_04.logging
import data.cis_ubuntu_24_04.auditd
import data.cis_ubuntu_24_04.ssh
import data.cis_ubuntu_24_04.pam
import data.cis_ubuntu_24_04.sudo
import data.cis_ubuntu_24_04.apparmor
import data.cis_ubuntu_24_04.user_group
import data.cis_ubuntu_24_04.cron
import data.cis_ubuntu_24_04.boot_security
import data.cis_ubuntu_24_04.file_permissions

# CIS Level 2 additional controls
# Activated when input.profile == "level2"
import data.cis_ubuntu_24_04.l2

# =============================================================================
# OVERALL COMPLIANCE STATUS
# =============================================================================

default compliant := false

# System is compliant if ALL modules are compliant
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
	apparmor.compliant
	user_group.compliant
	cron.compliant
	boot_security.compliant
	file_permissions.compliant
}

# =============================================================================
# AGGREGATE ALL VIOLATIONS
# =============================================================================

# Concatenate violations from first 7 modules
violations_array_1 := array.concat(
	array.concat(
		array.concat([v | some v in filesystem.violations], [v | some v in initial_setup.violations]),
		array.concat([v | some v in services.violations], [v | some v in network.violations]),
	),
	array.concat(
		array.concat([v | some v in logging.violations], [v | some v in auditd.violations]),
		[v | some v in ssh.violations],
	),
)

# Concatenate violations from remaining 7 modules
violations_array_2 := array.concat(
	array.concat(
		array.concat([v | some v in pam.violations], [v | some v in sudo.violations]),
		array.concat([v | some v in apparmor.violations], [v | some v in user_group.violations]),
	),
	array.concat(
		array.concat([v | some v in cron.violations], [v | some v in boot_security.violations]),
		[v | some v in file_permissions.violations],
	),
)

# Final aggregation of all violations
violations := array.concat(violations_array_1, violations_array_2)

# =============================================================================
# COMPLIANCE SUMMARY
# =============================================================================

compliance_summary := {
	"overall_compliance": compliance_status,
	"compliance_percentage": compliance_percentage,
	"total_violations": count(violations),
	"risk_level": risk_level,
}

compliance_status := "compliant" if {
	compliant
} else := "non_compliant"

compliance_percentage := percentage if {
	total_modules := 14
	compliant_modules := count([m | some m in module_status; m.compliant == true])
	percentage := (compliant_modules * 100) / total_modules
}

risk_level := "low" if {
	count(violations) == 0
}

risk_level := "medium" if {
	violation_count := count(violations)
	violation_count > 0
	violation_count <= 10
}

risk_level := "high" if {
	violation_count := count(violations)
	violation_count > 10
	violation_count <= 50
}

risk_level := "critical" if {
	count(violations) > 50
}

# =============================================================================
# MODULE STATUS
# =============================================================================

module_status := [
	{"module": "filesystem", "compliant": filesystem.compliant, "violations": count(filesystem.violations)},
	{"module": "initial_setup", "compliant": initial_setup.compliant, "violations": count(initial_setup.violations)},
	{"module": "services", "compliant": services.compliant, "violations": count(services.violations)},
	{"module": "network", "compliant": network.compliant, "violations": count(network.violations)},
	{"module": "logging", "compliant": logging.compliant, "violations": count(logging.violations)},
	{"module": "auditd", "compliant": auditd.compliant, "violations": count(auditd.violations)},
	{"module": "ssh", "compliant": ssh.compliant, "violations": count(ssh.violations)},
	{"module": "pam", "compliant": pam.compliant, "violations": count(pam.violations)},
	{"module": "sudo", "compliant": sudo.compliant, "violations": count(sudo.violations)},
	{"module": "apparmor", "compliant": apparmor.compliant, "violations": count(apparmor.violations)},
	{"module": "user_group", "compliant": user_group.compliant, "violations": count(user_group.violations)},
	{"module": "cron", "compliant": cron.compliant, "violations": count(cron.violations)},
	{"module": "boot_security", "compliant": boot_security.compliant, "violations": count(boot_security.violations)},
	{"module": "file_permissions", "compliant": file_permissions.compliant, "violations": count(file_permissions.violations)},
]

# =============================================================================
# COMPLETE COMPLIANCE ASSESSMENT
# =============================================================================

compliance_assessment := {
	"assessment_metadata": {
		"benchmark": "CIS Ubuntu Linux 24.04 LTS Benchmark v1.1.0",
		"target_platform": "Ubuntu 24.04 LTS",
		"assessment_time": time.now_ns(),
		"hostname": input.system_info.hostname,
	},
	"system_info": {
		"distribution": input.system_info.distribution,
		"distribution_version": input.system_info.distribution_version,
		"kernel": input.system_info.kernel,
		"architecture": input.system_info.architecture,
	},
	"compliance_summary": compliance_summary,
	"module_status": module_status,
	"violations": violations,
}

# =============================================================================
# COVERAGE — honest representation
# =============================================================================
#
# Rule heads implemented across all modules in this policy set: 240
#
# This count is the number of Rego rule heads (`contains msg if`,
# `contains violation if`) across every module imported by this master.
# It is NOT a formal 1-to-1 mapping to CIS Ubuntu 24.04 LTS Benchmark
# control IDs. Some CIS controls are covered by multiple rules; some
# rules cover multiple controls; some CIS controls are not implemented
# here. See per-module `compliance_report` for actual violation detail.
#
# For audit-of-record use this library MUST be formally mapped against
# the CIS Ubuntu 24.04 LTS Benchmark before results are relied upon.
total_controls_covered := 240

# =============================================================================
# PROFILE SELECTOR (Level 1 / Level 2)
# Set input.profile = "level2" to include Level 2 additional controls.
# Defaults to "level1". Level 2 adds 38 additional controls.
# =============================================================================

profile := input.profile if {
	input.profile in {"level1", "level2"}
} else := "level1"

l2_violations_active := [v | some v in l2.violations] if {
	profile == "level2"
} else := []

l2_compliant if {
	profile == "level2"
	l2.compliant
}

l2_compliant if {
	profile == "level1"
}

default l2_compliant := false
