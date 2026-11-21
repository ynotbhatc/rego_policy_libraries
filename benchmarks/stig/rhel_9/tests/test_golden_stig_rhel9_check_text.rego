# Golden cases for the DISA STIG for RHEL 9 (V2R10), built from each rule's check text (a US Government work).
# Every case gives the rule the evidence the check text shows: the expected command output is Not_a_Finding,
# the condition after "If ... this is a finding" is Open, and where the check text names one, the Not
# Applicable case or the SA / ISSO evidence that clears the finding. Each block cites the rule and vulnerability
# id and quotes one short phrase of the check text. Values are the strings the commands print.
#
# Issue #305. Hand-written: tools/stig_generators/gen_rhel9.py writes test_<section>_rules.rego and
# test_rhel9_green.rego, never this file.
package stig.rhel_9.golden_test

import rego.v1

# RHEL-09-255065 (V-257989): "any ciphers other than"
test_golden_rhel_09_255065_listed_ciphers_passes if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255065 == "Not_a_Finding" with input as {"opensshserver_config": {"Ciphers": "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"}}
}

test_golden_rhel_09_255065_extra_cipher_is_a_finding if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255065 == "Open" with input as {"opensshserver_config": {"Ciphers": "aes256-gcm@openssh.com,aes256-ctr,chacha20-poly1305@openssh.com"}}
}

# RHEL-09-255075 (V-257991): "any hashes other than"
test_golden_rhel_09_255075_listed_macs_passes if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255075 == "Not_a_Finding" with input as {"opensshserver_config": {"MACs": "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"}}
}

test_golden_rhel_09_255075_sha1_mac_is_a_finding if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255075 == "Open" with input as {"opensshserver_config": {"MACs": "hmac-sha2-256,hmac-sha1"}}
}

# RHEL-09-255040 (V-257984): "set to "yes""
test_golden_rhel_09_255040_no_passes if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255040 == "Not_a_Finding" with input as {"ssh_config": {"PermitEmptyPasswords": "no"}}
}

test_golden_rhel_09_255040_yes_is_a_finding if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255040 == "Open" with input as {"ssh_config": {"PermitEmptyPasswords": "yes"}}
}

# RHEL-09-255045 (V-257985): "any value other than "no""
test_golden_rhel_09_255045_no_passes if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255045 == "Not_a_Finding" with input as {"ssh_config": {"PermitRootLogin": "no"}}
}

test_golden_rhel_09_255045_prohibit_password_is_a_finding if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255045 == "Open" with input as {"ssh_config": {"PermitRootLogin": "prohibit-password"}}
}

# RHEL-09-255050 (V-257986): "set to "no""
test_golden_rhel_09_255050_yes_passes if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255050 == "Not_a_Finding" with input as {"ssh_config": {"UsePAM": "yes"}}
}

test_golden_rhel_09_255050_no_is_a_finding if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255050 == "Open" with input as {"ssh_config": {"UsePAM": "no"}}
}

# RHEL-09-255100 (V-257996): "a value of "600" or less"
test_golden_rhel_09_255100_600_passes if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255100 == "Not_a_Finding" with input as {"ssh_config": {"ClientAliveInterval": "600"}}
}

test_golden_rhel_09_255100_300_passes if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255100 == "Not_a_Finding" with input as {"ssh_config": {"ClientAliveInterval": "300"}}
}

test_golden_rhel_09_255100_1_passes if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255100 == "Not_a_Finding" with input as {"ssh_config": {"ClientAliveInterval": "1"}}
}

test_golden_rhel_09_255100_601_is_a_finding if {
	data.stig.rhel_9.ssh_config.status_rhel_09_255100 == "Open" with input as {"ssh_config": {"ClientAliveInterval": "601"}}
}

# RHEL-09-411075 (V-258054): ""3" or less (but not "0")"
test_golden_rhel_09_411075_deny_3_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_411075 == "Not_a_Finding" with input as {"faillock_conf": {"deny": "3"}}
}

test_golden_rhel_09_411075_deny_1_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_411075 == "Not_a_Finding" with input as {"faillock_conf": {"deny": "1"}}
}

test_golden_rhel_09_411075_deny_4_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_411075 == "Open" with input as {"faillock_conf": {"deny": "4"}}
}

test_golden_rhel_09_411075_deny_0_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_411075 == "Open" with input as {"faillock_conf": {"deny": "0"}}
}

# RHEL-09-411085 (V-258056): ""900" or less (but not "0")"
test_golden_rhel_09_411085_900_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_411085 == "Not_a_Finding" with input as {"faillock_conf": {"fail_interval": "900"}}
}

test_golden_rhel_09_411085_901_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_411085 == "Open" with input as {"faillock_conf": {"fail_interval": "901"}}
}

test_golden_rhel_09_411085_1_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_411085 == "Not_a_Finding" with input as {"faillock_conf": {"fail_interval": "1"}}
}

test_golden_rhel_09_411085_0_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_411085 == "Open" with input as {"faillock_conf": {"fail_interval": "0"}}
}

# RHEL-09-611090 (V-258107): ""15" or greater"
test_golden_rhel_09_611090_15_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_611090 == "Not_a_Finding" with input as {"password_policy": {"minlen": "15"}}
}

test_golden_rhel_09_611090_20_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_611090 == "Not_a_Finding" with input as {"password_policy": {"minlen": "20"}}
}

test_golden_rhel_09_611090_14_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_611090 == "Open" with input as {"password_policy": {"minlen": "14"}}
}

# RHEL-09-611110 (V-258111): "a positive number"
test_golden_rhel_09_611110_minus_1_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_611110 == "Not_a_Finding" with input as {"password_policy": {"ucredit": "-1"}}
}

test_golden_rhel_09_611110_plus_1_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_611110 == "Open" with input as {"password_policy": {"ucredit": "1"}}
}

# RHEL-09-611065 (V-258102): "a positive number"
test_golden_rhel_09_611065_minus_1_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_611065 == "Not_a_Finding" with input as {"password_policy": {"lcredit": "-1"}}
}

test_golden_rhel_09_611065_plus_1_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_611065 == "Open" with input as {"password_policy": {"lcredit": "1"}}
}

# RHEL-09-411010 (V-258041): "greater than "180""
test_golden_rhel_09_411010_180_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_411010 == "Not_a_Finding" with input as {"password_policy": {"maxdays": "180"}}
}

test_golden_rhel_09_411010_181_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_411010 == "Open" with input as {"password_policy": {"maxdays": "181"}}
}

test_golden_rhel_09_411010_1_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_411010 == "Not_a_Finding" with input as {"password_policy": {"maxdays": "1"}}
}

# RHEL-09-611075 (V-258104): ""1" or greater"
test_golden_rhel_09_611075_1_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_611075 == "Not_a_Finding" with input as {"password_policy": {"mindays": "1"}}
}

test_golden_rhel_09_611075_0_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_611075 == "Open" with input as {"password_policy": {"mindays": "0"}}
}

# RHEL-09-411050 (V-258049): "set to "-1", a value greater than "35""
test_golden_rhel_09_411050_35_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_411050 == "Not_a_Finding" with input as {"password_policy": {"inactive_days": "35"}}
}

test_golden_rhel_09_411050_0_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_411050 == "Not_a_Finding" with input as {"password_policy": {"inactive_days": "0"}}
}

test_golden_rhel_09_411050_minus_1_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_411050 == "Open" with input as {"password_policy": {"inactive_days": "-1"}}
}

test_golden_rhel_09_411050_36_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_411050 == "Open" with input as {"password_policy": {"inactive_days": "36"}}
}

# RHEL-09-611140 (V-258117): "a value of "SHA512""
test_golden_rhel_09_611140_sha512_passes if {
	data.stig.rhel_9.account_auth.status_rhel_09_611140 == "Not_a_Finding" with input as {"login_defs": {"ENCRYPT_METHOD": "SHA512"}}
}

test_golden_rhel_09_611140_md5_is_a_finding if {
	data.stig.rhel_9.account_auth.status_rhel_09_611140 == "Open" with input as {"login_defs": {"ENCRYPT_METHOD": "MD5"}}
}

# RHEL-09-431010 (V-258078): "not set to "Enforcing""
test_golden_rhel_09_431010_enforcing_passes if {
	data.stig.rhel_9.configuration_management.status_rhel_09_431010 == "Not_a_Finding" with input as {"selinux": {"getenforce": "Enforcing", "config_selinux": "enforcing"}}
}

test_golden_rhel_09_431010_runtime_permissive_is_a_finding if {
	data.stig.rhel_9.configuration_management.status_rhel_09_431010 == "Open" with input as {"selinux": {"getenforce": "Permissive", "config_selinux": "enforcing"}}
}

test_golden_rhel_09_431010_boot_permissive_is_a_finding if {
	data.stig.rhel_9.configuration_management.status_rhel_09_431010 == "Open" with input as {"selinux": {"getenforce": "Enforcing", "config_selinux": "permissive"}}
}

# RHEL-09-671010 (V-258230): "does not return "1""
test_golden_rhel_09_671010_1_passes if {
	data.stig.rhel_9.configuration_management.status_rhel_09_671010 == "Not_a_Finding" with input as {"fips": {"fips_enabled": "1"}}
}

test_golden_rhel_09_671010_0_is_a_finding if {
	data.stig.rhel_9.configuration_management.status_rhel_09_671010 == "Open" with input as {"fips": {"fips_enabled": "0"}}
}

# RHEL-09-213070 (V-257809): "conflicting results"
test_golden_rhel_09_213070_2_everywhere_passes if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213070 == "Not_a_Finding" with input as {"kernel_params": {"kernel.randomize_va_space": "2"}, "sysctl_config": {"kernel.randomize_va_space": ["2"]}}
}

test_golden_rhel_09_213070_runtime_0_is_a_finding if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213070 == "Open" with input as {"kernel_params": {"kernel.randomize_va_space": "0"}, "sysctl_config": {"kernel.randomize_va_space": ["2"]}}
}

test_golden_rhel_09_213070_conflicting_files_is_a_finding if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213070 == "Open" with input as {"kernel_params": {"kernel.randomize_va_space": "2"}, "sysctl_config": {"kernel.randomize_va_space": ["2", "0"]}}
}

test_golden_rhel_09_213070_not_in_files_is_a_finding if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213070 == "Open" with input as {"kernel_params": {"kernel.randomize_va_space": "2"}, "sysctl_config": {"kernel.randomize_va_space": []}}
}

# RHEL-09-654010 (V-258176): "-S execve -C uid!=euid -F euid=0"
test_golden_rhel_09_654010_four_rules_passes if {
	data.stig.rhel_9.audit_logging.status_rhel_09_654010 == "Not_a_Finding" with input as {"audit_rules": ["-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv", "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv", "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv", "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv"]}
}

test_golden_rhel_09_654010_b32_uid_rule_missing_is_a_finding if {
	data.stig.rhel_9.audit_logging.status_rhel_09_654010 == "Open" with input as {"audit_rules": ["-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv", "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv", "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv"]}
}

test_golden_rhel_09_654010_b32_gid_rule_missing_is_a_finding if {
	data.stig.rhel_9.audit_logging.status_rhel_09_654010 == "Open" with input as {"audit_rules": ["-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv", "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k execpriv", "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv"]}
}

test_golden_rhel_09_654010_b64_uid_rule_missing_is_a_finding if {
	data.stig.rhel_9.audit_logging.status_rhel_09_654010 == "Open" with input as {"audit_rules": ["-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k execpriv", "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k execpriv", "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k execpriv"]}
}

# RHEL-09-213010 (V-257797): "not set to "1""
test_golden_rhel_09_213010_1_passes if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213010 == "Not_a_Finding" with input as {"kernel_params": {"kernel.dmesg_restrict": "1"}}
}

test_golden_rhel_09_213010_0_is_a_finding if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213010 == "Open" with input as {"kernel_params": {"kernel.dmesg_restrict": "0"}}
}

# RHEL-09-213015 (V-257798): "not set to "2""
test_golden_rhel_09_213015_2_passes if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213015 == "Not_a_Finding" with input as {"kernel_params": {"kernel.perf_event_paranoid": "2"}}
}

test_golden_rhel_09_213015_1_is_a_finding if {
	data.stig.rhel_9.configuration_management.status_rhel_09_213015 == "Open" with input as {"kernel_params": {"kernel.perf_event_paranoid": "1"}}
}

# RHEL-09-211050 (V-257785): "loaded and not masked"
test_golden_rhel_09_211050_masked_passes if {
	data.stig.rhel_9.configuration_management.status_rhel_09_211050 == "Not_a_Finding" with input as {"systemd_units": {"ctrl-alt-del.target": {"load_state": "masked"}}}
}

test_golden_rhel_09_211050_loaded_is_a_finding if {
	data.stig.rhel_9.configuration_management.status_rhel_09_211050 == "Open" with input as {"systemd_units": {"ctrl-alt-del.target": {"load_state": "loaded"}}}
}

# RHEL-09-232270 (V-257934): "a value of "0""
test_golden_rhel_09_232270_0_passes if {
	data.stig.rhel_9.file_permissions.status_rhel_09_232270 == "Not_a_Finding" with input as {"file_permissions": {"etc_shadow": {"mode": "0"}}}
}

test_golden_rhel_09_232270_640_is_a_finding if {
	data.stig.rhel_9.file_permissions.status_rhel_09_232270 == "Open" with input as {"file_permissions": {"etc_shadow": {"mode": "640"}}}
}

# RHEL-09-232075 (V-257895): ""0644" or less permissive"
test_golden_rhel_09_232075_644_passes if {
	data.stig.rhel_9.file_permissions.status_rhel_09_232075 == "Not_a_Finding" with input as {"file_permissions": {"etc_passwd": {"mode": "644"}}}
}

test_golden_rhel_09_232075_600_passes if {
	data.stig.rhel_9.file_permissions.status_rhel_09_232075 == "Not_a_Finding" with input as {"file_permissions": {"etc_passwd": {"mode": "600"}}}
}

test_golden_rhel_09_232075_664_is_a_finding if {
	data.stig.rhel_9.file_permissions.status_rhel_09_232075 == "Open" with input as {"file_permissions": {"etc_passwd": {"mode": "664"}}}
}

# RHEL-09-653025 (V-258154): ""SYSLOG", "SINGLE", or "HALT""
test_golden_rhel_09_653025_halt_passes if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653025 == "Not_a_Finding" with input as {"auditd_config": {"disk_full_action": "HALT"}}
}

test_golden_rhel_09_653025_syslog_passes if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653025 == "Not_a_Finding" with input as {"auditd_config": {"disk_full_action": "SYSLOG"}}
}

test_golden_rhel_09_653025_single_passes if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653025 == "Not_a_Finding" with input as {"auditd_config": {"disk_full_action": "SINGLE"}}
}

test_golden_rhel_09_653025_suspend_is_a_finding if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653025 == "Open" with input as {"auditd_config": {"disk_full_action": "SUSPEND"}}
}

test_golden_rhel_09_653025_suspend_sa_evidence_passes if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653025 == "Not_a_Finding" with input as {"auditd_config": {"disk_full_action": "SUSPEND"}, "attest": {"rhel_09_653025_disk_full_action": true}}
}

# RHEL-09-653040 (V-258157): "not set to "email""
test_golden_rhel_09_653040_email_passes if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653040 == "Not_a_Finding" with input as {"auditd_config": {"space_left_action": "email"}}
}

test_golden_rhel_09_653040_syslog_is_a_finding if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653040 == "Open" with input as {"auditd_config": {"space_left_action": "SYSLOG"}}
}

test_golden_rhel_09_653040_syslog_sa_evidence_passes if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653040 == "Not_a_Finding" with input as {"auditd_config": {"space_left_action": "SYSLOG"}, "attest": {"rhel_09_653040_realtime_alerts": true}}
}

# RHEL-09-653055 (V-258160): "not "ROTATE", "SINGLE""
test_golden_rhel_09_653055_rotate_passes if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653055 == "Not_a_Finding" with input as {"auditd_config": {"max_log_file_action": "ROTATE"}}
}

test_golden_rhel_09_653055_single_passes if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653055 == "Not_a_Finding" with input as {"auditd_config": {"max_log_file_action": "SINGLE"}}
}

test_golden_rhel_09_653055_ignore_is_a_finding if {
	data.stig.rhel_9.audit_logging.status_rhel_09_653055 == "Open" with input as {"auditd_config": {"max_log_file_action": "IGNORE"}}
}

# RHEL-09-215060 (V-257835): "this rule is not applicable"
test_golden_rhel_09_215060_not_installed_is_not_applicable if {
	data.stig.rhel_9.services.status_rhel_09_215060 == "Not_Applicable" with input as {"packages": {"tftp-server": false}}
}

test_golden_rhel_09_215060_secure_mode_passes if {
	data.stig.rhel_9.services.status_rhel_09_215060 == "Not_a_Finding" with input as {"packages": {"tftp-server": true}, "tftp": {"execstart": "/usr/sbin/in.tftpd -s /var/lib/tftpboot"}}
}

test_golden_rhel_09_215060_without_s_is_a_finding if {
	data.stig.rhel_9.services.status_rhel_09_215060 == "Open" with input as {"packages": {"tftp-server": true}, "tftp": {"execstart": "/usr/sbin/in.tftpd /var/lib/tftpboot"}}
}

# RHEL-09-215040 (V-257831): "package is installed"
test_golden_rhel_09_215040_absent_passes if {
	data.stig.rhel_9.services.status_rhel_09_215040 == "Not_a_Finding" with input as {"packages": {"telnet-server": false}}
}

test_golden_rhel_09_215040_installed_is_a_finding if {
	data.stig.rhel_9.services.status_rhel_09_215040 == "Open" with input as {"packages": {"telnet-server": true}}
}

# RHEL-09-253075 (V-257970): "documented with the information system security officer"
test_golden_rhel_09_253075_0_passes if {
	data.stig.rhel_9.network.status_rhel_09_253075 == "Not_a_Finding" with input as {"kernel_params": {"net.ipv4.conf.all.forwarding": "0"}}
}

test_golden_rhel_09_253075_1_is_a_finding if {
	data.stig.rhel_9.network.status_rhel_09_253075 == "Open" with input as {"kernel_params": {"net.ipv4.conf.all.forwarding": "1"}}
}

test_golden_rhel_09_253075_1_documented_router_passes if {
	data.stig.rhel_9.network.status_rhel_09_253075 == "Not_a_Finding" with input as {"kernel_params": {"net.ipv4.conf.all.forwarding": "1"}, "attest": {"rhel_09_253075_router_documented": true}}
}

# RHEL-09-253015 (V-257958): "not set to "0""
test_golden_rhel_09_253015_0_passes if {
	data.stig.rhel_9.network.status_rhel_09_253015 == "Not_a_Finding" with input as {"kernel_params": {"net.ipv4.conf.all.accept_redirects": "0"}}
}

test_golden_rhel_09_253015_1_is_a_finding if {
	data.stig.rhel_9.network.status_rhel_09_253015 == "Open" with input as {"kernel_params": {"net.ipv4.conf.all.accept_redirects": "1"}}
}

# RHEL-09-253010 (V-257957): "not equal to "1""
test_golden_rhel_09_253010_1_passes if {
	data.stig.rhel_9.network.status_rhel_09_253010 == "Not_a_Finding" with input as {"kernel_params": {"net.ipv4.tcp_syncookies": "1"}}
}

test_golden_rhel_09_253010_0_is_a_finding if {
	data.stig.rhel_9.network.status_rhel_09_253010 == "Open" with input as {"kernel_params": {"net.ipv4.tcp_syncookies": "0"}}
}
