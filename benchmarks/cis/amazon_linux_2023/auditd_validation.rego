package cis_amazon_linux_2023.auditd

# CIS Amazon Linux 2023 Section 4.1.x - Configure System Accounting (auditd)
# Validates auditd service, configuration, and audit rules

import rego.v1

# =============================================================================
# MAIN COMPLIANCE RULES
# =============================================================================

default compliant := false

compliant if {
	count(violations) == 0
}

# Aggregate all violations
violations := array.concat(
	array.concat([v | some v in service_violations], [v | some v in config_violations]),
	array.concat([v | some v in rules_violations], [v | some v in permission_violations]),
)

# =============================================================================
# CIS 4.1.1.1 - AUDITD INSTALLED
# =============================================================================

service_violations contains "CIS 4.1.1.1: audit package not installed" if {
	not input.packages["audit"]
}

# =============================================================================
# CIS 4.1.1.2 - AUDITD SERVICE ENABLED AND RUNNING
# =============================================================================

service_violations contains "CIS 4.1.1.2: auditd service not enabled" if {
	service := input.services["auditd.service"]
	service.status != "enabled"
}

service_violations contains "CIS 4.1.1.2: auditd service not running" if {
	service := input.services["auditd.service"]
	service.state != "running"
}

# =============================================================================
# CIS 4.1.1.3 - AUDITING FOR PROCESSES PRIOR TO AUDITD
# =============================================================================

config_violations contains "CIS 4.1.1.3: audit=1 not set in bootloader configuration" if {
	not contains(input.bootloader.grub_config, "audit=1")
}

# =============================================================================
# CIS 4.1.1.4 - AUDIT BACKLOG LIMIT
# =============================================================================

config_violations contains "CIS 4.1.1.4: audit_backlog_limit not sufficient (should be 8192 or higher)" if {
	not contains(input.bootloader.grub_config, "audit_backlog_limit")
}

# =============================================================================
# CIS 4.1.2.1 - AUDIT LOG STORAGE SIZE
# =============================================================================

config_violations contains "CIS 4.1.2.1: max_log_file not configured in auditd.conf" if {
	not contains(input.auditd.config, "max_log_file")
}

# =============================================================================
# CIS 4.1.2.2 - AUDIT LOGS NOT DELETED
# =============================================================================

config_violations contains "CIS 4.1.2.2: max_log_file_action set to delete (logs will be deleted)" if {
	contains(input.auditd.config, "max_log_file_action = delete")
}

config_violations contains "CIS 4.1.2.2: max_log_file_action set to ignore (no action on full logs)" if {
	contains(input.auditd.config, "max_log_file_action = ignore")
}

# =============================================================================
# CIS 4.1.2.3 - SYSTEM DISABLED WHEN AUDIT LOGS FULL
# =============================================================================

config_violations contains "CIS 4.1.2.3: space_left_action not appropriate (should be email, exec, single, or halt)" if {
	not contains(input.auditd.config, "space_left_action = email")
	not contains(input.auditd.config, "space_left_action = exec")
	not contains(input.auditd.config, "space_left_action = single")
	not contains(input.auditd.config, "space_left_action = halt")
}

config_violations contains "CIS 4.1.2.3: admin_space_left_action not appropriate" if {
	not contains(input.auditd.config, "admin_space_left_action = single")
	not contains(input.auditd.config, "admin_space_left_action = halt")
}

# =============================================================================
# CIS 4.1.3.X - AUDIT RULES - TIME CHANGES
# =============================================================================

# Required audit rules for comprehensive coverage
required_rules := [
	# Time changes (4.1.3.1)
	"-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change",
	"-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change",
	"-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change",
	"-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change",
	"-w /etc/localtime -p wa -k time-change",

	# User/Group changes (4.1.3.2)
	"-w /etc/group -p wa -k identity",
	"-w /etc/passwd -p wa -k identity",
	"-w /etc/gshadow -p wa -k identity",
	"-w /etc/shadow -p wa -k identity",
	"-w /etc/security/opasswd -p wa -k identity",

	# System network environment (4.1.3.3)
	"-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale",
	"-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale",
	"-w /etc/issue -p wa -k system-locale",
	"-w /etc/issue.net -p wa -k system-locale",
	"-w /etc/hosts -p wa -k system-locale",

	# MAC policy (4.1.3.4)
	"-w /etc/selinux -p wa -k MAC-policy",
	"-w /usr/share/selinux -p wa -k MAC-policy",

	# Login/logout events (4.1.3.5)
	"-w /var/log/lastlog -p wa -k logins",
	"-w /var/run/faillock -p wa -k logins",

	# Session initiation (4.1.3.6)
	"-w /var/run/utmp -p wa -k session",
	"-w /var/log/wtmp -p wa -k logins",
	"-w /var/log/btmp -p wa -k logins",

	# Discretionary Access Control (DAC) permission changes (4.1.3.7)
	"-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
	"-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
	"-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod",
	"-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod",
	"-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod",
	"-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -k perm_mod",

	# Unauthorized access attempts (4.1.3.8)
	"-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
	"-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
	"-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access",
	"-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access",

	# Privileged commands monitoring (4.1.3.9) - simplified check
	# Note: Full implementation requires discovering all SUID/SGID binaries

	# Successful file system mounts (4.1.3.10)
	"-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts",
	"-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts",

	# File deletion events (4.1.3.11)
	"-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete",
	"-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete",

	# sudoers changes (4.1.3.12)
	"-w /etc/sudoers -p wa -k scope",
	"-w /etc/sudoers.d -p wa -k scope",

	# sudo log file (4.1.3.13)
	"-w /var/log/sudo.log -p wa -k actions",

	# Kernel modules (4.1.3.14)
	"-w /sbin/insmod -p x -k modules",
	"-w /sbin/rmmod -p x -k modules",
	"-w /sbin/modprobe -p x -k modules",
	"-a always,exit -F arch=b64 -S init_module,delete_module -k modules",
]

# Check for missing audit rules with flexible matching
rules_violations contains sprintf("CIS 4.1.3.x: Missing or incomplete audit rule for: %s", [rule_desc]) if {
	some required_rule in required_rules
	rule_desc := extract_rule_description(required_rule)
	not rule_exists(required_rule)
}

# Helper: Check if a rule exists (with some flexibility for formatting)
rule_exists(required_rule) if {
	some active_rule in input.auditd.active_rules
	# Normalize spaces and compare
	normalized_required := regex.replace(required_rule, `\s+`, " ")
	normalized_active := regex.replace(active_rule, `\s+`, " ")
	contains(normalized_active, normalized_required)
}

# Helper: Extract rule description
extract_rule_description(rule) := desc if {
	contains(rule, "-w")
	parts := split(rule, " ")
	desc := parts[1]
} else := desc if {
	contains(rule, "-S")
	desc := "system call monitoring"
}

# =============================================================================
# CIS 4.1.3.21 - AUDIT CONFIGURATION IMMUTABLE
# =============================================================================

rules_violations contains "CIS 4.1.3.21: Audit configuration not set to immutable (missing '-e 2')" if {
	not "-e 2" in input.auditd.active_rules
}

# =============================================================================
# CIS 4.1.4.1 - AUDIT LOG FILES PERMISSIONS
# =============================================================================

permission_violations contains sprintf("CIS 4.1.4.1: Audit log permissions too permissive (mode: %s, should be 0640 or less)", [mode]) if {
	mode := input.auditd.log_permissions.mode
	mode_num := to_number(mode)
	mode_num > 640
}

# =============================================================================
# CIS 4.1.4.2 - AUDIT LOG FILES OWNERSHIP
# =============================================================================

permission_violations contains sprintf("CIS 4.1.4.2: Audit log not owned by root (owner: %s)", [owner]) if {
	owner := input.auditd.log_permissions.pw_name
	owner != "root"
}

permission_violations contains sprintf("CIS 4.1.4.2: Audit log group not root or adm (group: %s)", [group]) if {
	group := input.auditd.log_permissions.gr_name
	not group in ["root", "adm"]
}

# =============================================================================
# CIS 4.1.4.3 - AUDIT LOG DIRECTORY PERMISSIONS
# =============================================================================

permission_violations contains sprintf("CIS 4.1.4.3: Audit log directory permissions too permissive (mode: %s)", [mode]) if {
	mode := input.auditd.log_dir_permissions.mode
	mode_num := to_number(mode)
	mode_num > 750
}

# =============================================================================
# CIS 4.1.4.4 - AUDIT CONFIGURATION FILES PERMISSIONS
# =============================================================================

permission_violations contains sprintf("CIS 4.1.4.4: Audit config file %s has incorrect permissions (mode: %s, should be 0640)", [file, mode]) if {
	some config_file in input.auditd.config_permissions
	file := config_file.stat.path
	mode := config_file.stat.mode
	mode != "0640"
}

permission_violations contains sprintf("CIS 4.1.4.4: Audit config file %s not owned by root (owner: %s)", [file, owner]) if {
	some config_file in input.auditd.config_permissions
	file := config_file.stat.path
	owner := config_file.stat.pw_name
	owner != "root"
}

# =============================================================================
# SUMMARY REPORT
# =============================================================================

report := {
	"compliant": compliant,
	"violations": violations,
	"total_violations": count(violations),
	"service_violations": count(service_violations),
	"config_violations": count(config_violations),
	"rules_violations": count(rules_violations),
	"permission_violations": count(permission_violations),
	"controls_checked": 40,
	"section": "4.1 Configure System Accounting (auditd)",
	"rules_checked": count(required_rules),
}
