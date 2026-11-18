package stig.oracle_linux_9.audit_logging_test

import rego.v1

import data.stig.oracle_linux_9.audit_logging

# Validation 2026-10-17: audit rules match on token boundaries.

test_execveat_does_not_satisfy_execve if {
	not audit_logging.audit_execve_b64 with input as {"audit_rules": ["-a always,exit -F arch=b64 -S execveat"]}
}

test_sudoers_d_does_not_satisfy_sudoers if {
	not audit_logging.audit_sudoers with input as {"audit_rules": ["-w /etc/sudoers.d/ -p wa -k sudoers"]}
	audit_logging.audit_sudoers with input as {"audit_rules": ["-w /etc/sudoers -p wa -k sudoers"]}
}

test_passwd_dash_does_not_satisfy_passwd if {
	not audit_logging.audit_passwd_file with input as {"audit_rules": ["-w /etc/passwd- -p wa"]}
	audit_logging.audit_passwd_file with input as {"audit_rules": ["-w /etc/passwd -p wa -k usermod"]}
}

test_sudoedit_does_not_satisfy_sudo_path if {
	not audit_logging.audit_privileged_cmds with input as {"audit_rules": ["-a always,exit -F path=/usr/bin/sudoedit -F perm=x -k x"]}
}
