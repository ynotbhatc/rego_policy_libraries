package cis_debian_11.auditd

# CIS Debian Linux 11 Benchmark v1.0.0 - Section 4.1: Configure System Accounting (auditd)

import rego.v1

default compliant := false

compliant if {
	count(violations) == 0
}

violations := array.concat(
	array.concat([v | some v in service_violations], [v | some v in config_violations]),
	array.concat([v | some v in rules_violations], [v | some v in permission_violations]),
)

# CIS 4.1.1.1: Ensure audit is installed
service_violations contains msg if {
	not input.packages["auditd"]
	not input.packages["audit"]
	msg := "CIS 4.1.1.1: auditd package not installed"
}

# CIS 4.1.1.2: Ensure auditd service is enabled and running
service_violations contains msg if {
	service := input.services["auditd.service"]
	service.status != "enabled"
	msg := "CIS 4.1.1.2: auditd service not enabled"
}

service_violations contains msg if {
	service := input.services["auditd.service"]
	service.state != "running"
	msg := "CIS 4.1.1.2: auditd service not running"
}

# CIS 4.1.1.3: Ensure auditing for processes prior to auditd
config_violations contains msg if {
	not contains(input.bootloader.grub_config, "audit=1")
	msg := "CIS 4.1.1.3: audit=1 not set in bootloader configuration"
}

# CIS 4.1.1.4: Ensure audit_backlog_limit is sufficient
config_violations contains msg if {
	not contains(input.bootloader.grub_config, "audit_backlog_limit")
	msg := "CIS 4.1.1.4: audit_backlog_limit not configured (should be 8192 or higher)"
}

# CIS 4.1.2.1: Ensure audit log storage size is configured
config_violations contains msg if {
	not contains(input.auditd.config, "max_log_file")
	msg := "CIS 4.1.2.1: max_log_file not configured in auditd.conf"
}

# CIS 4.1.2.2: Ensure audit logs are not automatically deleted
config_violations contains msg if {
	contains(input.auditd.config, "max_log_file_action = delete")
	msg := "CIS 4.1.2.2: max_log_file_action set to delete (logs will be deleted)"
}

config_violations contains msg if {
	contains(input.auditd.config, "max_log_file_action = ignore")
	msg := "CIS 4.1.2.2: max_log_file_action set to ignore (no action on full logs)"
}

# CIS 4.1.2.3: Ensure system is disabled when audit logs are full
config_violations contains msg if {
	not contains(input.auditd.config, "space_left_action = email")
	not contains(input.auditd.config, "space_left_action = exec")
	not contains(input.auditd.config, "space_left_action = single")
	not contains(input.auditd.config, "space_left_action = halt")
	msg := "CIS 4.1.2.3: space_left_action not appropriate (should be email, exec, single, or halt)"
}

config_violations contains msg if {
	not contains(input.auditd.config, "admin_space_left_action = single")
	not contains(input.auditd.config, "admin_space_left_action = halt")
	msg := "CIS 4.1.2.3: admin_space_left_action not appropriate (should be single or halt)"
}

# Required audit rules (CIS 4.1.3.x)
required_rules := [
	# Time changes (4.1.3.1)
	"-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change",
	"-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change",
	"-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change",
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
	"-w /etc/apparmor -p wa -k MAC-policy",
	"-w /etc/apparmor.d -p wa -k MAC-policy",
	# Login/logout events (4.1.3.5)
	"-w /var/log/lastlog -p wa -k logins",
	"-w /var/run/faillock -p wa -k logins",
	# Session initiation (4.1.3.6)
	"-w /var/run/utmp -p wa -k session",
	"-w /var/log/wtmp -p wa -k logins",
	"-w /var/log/btmp -p wa -k logins",
	# DAC permission changes (4.1.3.7)
	"-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
	"-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
	"-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod",
	"-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod",
	# Unauthorized access attempts (4.1.3.8)
	"-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
	"-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
	"-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access",
	# Successful mounts (4.1.3.10)
	"-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts",
	"-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts",
	# File deletion events (4.1.3.11)
	"-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete",
	"-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete",
	# sudoers changes (4.1.3.12)
	"-w /etc/sudoers -p wa -k scope",
	"-w /etc/sudoers.d -p wa -k scope",
	# sudo log (4.1.3.13)
	"-w /var/log/sudo.log -p wa -k actions",
	# Kernel modules (4.1.3.14)
	"-w /sbin/insmod -p x -k modules",
	"-w /sbin/rmmod -p x -k modules",
	"-w /sbin/modprobe -p x -k modules",
	"-a always,exit -F arch=b64 -S init_module,delete_module -k modules",
]

rule_exists(required_rule) if {
	some active_rule in input.auditd.active_rules
	normalized_required := regex.replace(required_rule, `\s+`, " ")
	normalized_active := regex.replace(active_rule, `\s+`, " ")
	contains(normalized_active, normalized_required)
}

extract_rule_description(rule) := desc if {
	contains(rule, "-w")
	parts := split(rule, " ")
	desc := parts[1]
} else := "system call monitoring"

rules_violations contains msg if {
	some required_rule in required_rules
	rule_desc := extract_rule_description(required_rule)
	not rule_exists(required_rule)
	msg := sprintf("CIS 4.1.3.x: Missing audit rule for: %s", [rule_desc])
}

# CIS 4.1.3.21: Audit configuration immutable
rules_violations contains msg if {
	not "-e 2" in input.auditd.active_rules
	msg := "CIS 4.1.3.21: Audit configuration not set to immutable (missing '-e 2')"
}

# CIS 4.1.4.1: Audit log file permissions
permission_violations contains msg if {
	mode := input.auditd.log_permissions.mode
	to_number(mode) > 640
	msg := sprintf("CIS 4.1.4.1: Audit log permissions too permissive (mode: %s, should be 0640 or less)", [mode])
}

# CIS 4.1.4.2: Audit log file ownership
permission_violations contains msg if {
	owner := input.auditd.log_permissions.pw_name
	owner != "root"
	msg := sprintf("CIS 4.1.4.2: Audit log not owned by root (owner: %s)", [owner])
}

permission_violations contains msg if {
	group := input.auditd.log_permissions.gr_name
	not group in ["root", "adm"]
	msg := sprintf("CIS 4.1.4.2: Audit log group not root or adm (group: %s)", [group])
}

report := {
	"compliant": compliant,
	"violations": violations,
	"total_violations": count(violations),
	"service_violations": count(service_violations),
	"config_violations": count(config_violations),
	"rules_violations": count(rules_violations),
	"permission_violations": count(permission_violations),
	"controls_checked": 38,
	"rules_checked": count(required_rules),
	"section": "4.1 Configure System Accounting (auditd)",
	"benchmark": "CIS Debian 11 v1.0.0",
}
