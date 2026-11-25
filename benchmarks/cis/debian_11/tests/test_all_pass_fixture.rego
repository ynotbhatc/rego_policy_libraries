package cis_debian_11.all_pass_fixture_test

import rego.v1

# One complete, compliant host: every fact the policy set reads, with every gate open where a compliant
# host allows it (AIDE, rsyslog and GDM installed, remote logging and IPv6-off required), so that each
# yes/no fact and each number is actually judged. scripts/check_bad_input_fails.py finds this object by
# evaluation and mutates it leaf by leaf; tests/test_bad_input_types.rego does the same for every leaf.
fixture_compliant := {
	"require_remote_logging": true,
	"require_ipv6_disabled": true,
	"apparmor": {
		"installed": true, "utils_installed": true, "bootloader_enabled": true,
		"grub_cmdline": "quiet apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192",
		"service_active": true, "service_enabled": true,
		"unloaded_profiles": 0, "complain_profiles": 0,
		"profiles": [{"name": "usr.sbin.sshd", "mode": "enforce"}],
	},
	"aide": {"installed": true, "cron_configured": true, "database_exists": true},
	"grub": {"password_configured": true, "config_mode": "0600", "config_owner": "root", "sulogin_configured": true},
	"process_hardening": {
		"core_dumps_enabled": false, "fs_suid_dumpable": "0", "aslr_enabled": true,
		"prelink_installed": false, "ptrace_scope_restricted": true,
	},
	"packages": {"auditd": true},
	"services": {"auditd.service": {"status": "enabled", "state": "running"}},
	"bootloader": {"grub_config": "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"},
	"auditd": {
		"config": "max_log_file = 8\nmax_log_file_action = keep_logs\nspace_left_action = email\nadmin_space_left_action = halt\n",
		"log_permissions": {"mode": "0640", "pw_name": "root", "gr_name": "adm"},
		"active_rules": [
			"-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change",
			"-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change",
			"-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change",
			"-w /etc/localtime -p wa -k time-change",
			"-w /etc/group -p wa -k identity",
			"-w /etc/passwd -p wa -k identity",
			"-w /etc/gshadow -p wa -k identity",
			"-w /etc/shadow -p wa -k identity",
			"-w /etc/security/opasswd -p wa -k identity",
			"-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale",
			"-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale",
			"-w /etc/issue -p wa -k system-locale",
			"-w /etc/issue.net -p wa -k system-locale",
			"-w /etc/hosts -p wa -k system-locale",
			"-w /etc/apparmor -p wa -k MAC-policy",
			"-w /etc/apparmor.d -p wa -k MAC-policy",
			"-w /var/log/lastlog -p wa -k logins",
			"-w /var/run/faillock -p wa -k logins",
			"-w /var/run/utmp -p wa -k session",
			"-w /var/log/wtmp -p wa -k logins",
			"-w /var/log/btmp -p wa -k logins",
			"-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
			"-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod",
			"-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod",
			"-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -k perm_mod",
			"-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
			"-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
			"-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access",
			"-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts",
			"-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts",
			"-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete",
			"-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete",
			"-w /etc/sudoers -p wa -k scope",
			"-w /etc/sudoers.d -p wa -k scope",
			"-w /var/log/sudo.log -p wa -k actions",
			"-w /sbin/insmod -p x -k modules",
			"-w /sbin/rmmod -p x -k modules",
			"-w /sbin/modprobe -p x -k modules",
			"-a always,exit -F arch=b64 -S init_module,delete_module -k modules",
			"-e 2",
		],
	},
	"cron": {
		"crond_enabled": true, "crond_running": true,
		"crontab_mode": "0600", "crontab_owner": "root", "crontab_group": "root",
		"cron_hourly_mode": "0700", "cron_hourly_owner": "root",
		"cron_daily_mode": "0700", "cron_daily_owner": "root",
		"cron_weekly_mode": "0700", "cron_weekly_owner": "root",
		"cron_monthly_mode": "0700", "cron_monthly_owner": "root",
		"cron_d_mode": "0700", "cron_d_owner": "root",
		"cron_deny_exists": false, "cron_allow_exists": true, "cron_allow_mode": "0600",
		"at_deny_exists": false, "at_allow_exists": true, "at_allow_mode": "0600",
	},
	"critical_files": {"analysis": [
		{"file": "/etc/passwd", "exists": true, "fully_compliant": true, "mode_compliant": true},
		{"file": "/etc/group", "exists": true, "fully_compliant": true, "mode_compliant": true},
		{"file": "/etc/shadow", "exists": true, "fully_compliant": true, "mode_compliant": true},
		{"file": "/etc/gshadow", "exists": true, "fully_compliant": true, "mode_compliant": true},
	]},
	"ssh_private_keys": {"all_compliant": true, "analysis": [{"path": "/etc/ssh/ssh_host_ed25519_key", "fully_compliant": true}]},
	"world_writable": {"count": 0, "files": []},
	"unowned_files": {"count": 0, "files": []},
	"ungrouped_files": {"count": 0, "files": []},
	"suid_files": {"total_count": 12, "unknown_count": 1, "unknown_binaries": [{"path": "/usr/local/bin/tool", "review_required": false}]},
	"sgid_files": {"count": 8},
	"disabled_filesystem_modules": {"modules": [{"module": "cramfs", "compliant": true}]},
	"required_partitions": {"partitions": [{"cis_id": "2", "mount_point": "/tmp", "exists": true}]},
	"mount_options": {"mounts": [{"cis_id": "1.1.3", "mount_point": "/tmp", "compliant": true, "missing_options": []}]},
	"sticky_bit_check": {"world_writable_dirs": [{"path": "/tmp", "has_sticky_bit": true}]},
	"usb_storage_disabled": {"loaded": false, "disabled": true},
	"initial_setup": {
		"enabled_repos": ["main"], "gpg_keys": ["archive-keyring"],
		"aide_installed": true, "aide_cron_configured": true,
		"grub_password_configured": true, "grub_config_mode": "0600", "grub_owner_root": true,
		"core_dumps_enabled": false, "aslr_enabled": true, "prelink_installed": false, "ptrace_scope_restricted": true,
		"motd_exists": true, "motd_mode": "0644", "motd_owner": "root", "motd_contains_sensitive_info": false,
		"issue_exists": true, "issue_mode": "0644", "issue_owner": "root", "issue_contains_sensitive_info": false,
		"issue_net_exists": true, "issue_net_mode": "0644", "issue_net_owner": "root", "issue_net_contains_sensitive_info": false,
		"gdm_installed": true, "server_environment": true, "gui_required": true,
		"gdm_banner_configured": true, "gdm_screen_lock_enabled": true, "gdm_idle_delay": 600,
	},
	"rsyslog": {
		"installed": true, "service_active": true, "service_enabled": true,
		"file_create_mode": "0640", "logging_rules_count": 6, "remote_logging_configured": true,
	},
	"journald": {"forward_to_syslog": "yes", "compress_enabled": "yes", "storage_mode": "persistent", "service_active": true},
	"log_file_permissions": {"analysis": [{"file": "/var/log/syslog", "exists": true, "fully_compliant": true}]},
	"logrotate": {"installed": true},
	"sysctl_parameters": {
		"non_compliant_params": [],
		"analysis": [
			{"parameter": "net.ipv4.tcp_syncookies", "current_value": "1"},
			{"parameter": "net.ipv4.conf.all.rp_filter", "current_value": "1"},
			{"parameter": "net.ipv4.conf.all.log_martians", "current_value": "1"},
			{"parameter": "net.ipv4.icmp_echo_ignore_broadcasts", "current_value": "1"},
			{"parameter": "net.ipv4.conf.all.send_redirects", "current_value": "0"},
			{"parameter": "net.ipv4.conf.default.send_redirects", "current_value": "0"},
			{"parameter": "net.ipv4.conf.all.accept_source_route", "current_value": "0"},
			{"parameter": "net.ipv4.conf.all.accept_redirects", "current_value": "0"},
			{"parameter": "net.ipv4.conf.all.secure_redirects", "current_value": "0"},
		],
	},
	"ip_forwarding": {"ipv4_forwarding": 0, "ipv6_forwarding": 0},
	"ipv6": {"disabled": true},
	"wireless_interfaces": {"has_wireless": false, "compliant": true, "interfaces": []},
	"firewall": {"active": true, "type": "ufw", "default_incoming": "deny"},
	"pam": {
		"pwquality_conf_raw": "minlen = 14\nminclass = 4\n",
		"common_password_raw": "password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5\n",
		"faillock_configured": true, "faillock_deny": 5, "faillock_unlock_time": 900,
		"remember_configured": true, "remember_count": 5,
		"pass_min_days": 1, "pass_max_days": 365, "pass_warn_age": 7, "inactive_days": 30,
		"users_with_future_password_change": [], "system_accounts_with_login_shell": [],
		"tmout_configured": true, "tmout_value": 900, "default_umask": "027",
	},
	"autofs": {"installed": true, "active": false, "enabled": false},
	"time_synchronization": {"has_active_service": true, "compliant": true, "active_service": "chronyd"},
	"chronyd": {"service_active": true, "has_time_sources": true},
	"unnecessary_services": {
		"non_compliant": [],
		"analysis": [
			{"service": "inetd", "active": false},
			{"service": "telnet", "active": false},
			{"service": "avahi-daemon", "active": false},
			{"service": "cups", "active": false},
		],
	},
	"webserver": {"any_installed": false, "packages": [{"package": "apache2", "installed": false}]},
	"client_packages": {
		"any_installed": false, "installed_packages": [],
		"analysis": [
			{"package": "telnet", "installed": false},
			{"package": "rsh-client", "installed": false},
			{"package": "nis", "installed": false},
		],
	},
	"x11": {"any_installed": false, "packages": [{"package": "xserver-xorg", "installed": false}]},
	"ssh": {
		"sshd_config_raw": "LogLevel VERBOSE\nUsePAM yes\nPermitRootLogin no\nHostbasedAuthentication no\nPermitEmptyPasswords no\nPermitUserEnvironment no\nIgnoreRhosts yes\nX11Forwarding no\nAllowTcpForwarding no\nBanner /etc/issue.net\nMaxAuthTries 4\nMaxStartups 10:30:60\nMaxSessions 10\nLoginGraceTime 60\nClientAliveInterval 15\nClientAliveCountMax 3\nAllowGroups sshusers\nCiphers aes256-gcm@openssh.com,aes128-gcm@openssh.com\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\nKexAlgorithms curve25519-sha256\n",
		"sshd_config_mode": "0600", "sshd_config_owner": "root", "sshd_config_group": "root",
		"private_key_files": [{"path": "/etc/ssh/ssh_host_ed25519_key", "mode": "0600"}],
		"public_key_files": [{"path": "/etc/ssh/ssh_host_ed25519_key.pub", "mode": "0644"}],
	},
	"sudo": {
		"installed": true, "use_pty": true, "logfile_configured": true,
		"nopasswd_entries": [], "noauthenticate_entries": [],
		"timestamp_timeout": 15, "su_restricted": true, "su_allowed_group": "sudo",
		"sudoers_world_readable": false, "sudoers_mode": "0440",
	},
	"user_group": {
		"users_without_shadow": [], "users_with_empty_password": [], "passwd_groups_not_in_group_file": [],
		"duplicate_uids": {}, "duplicate_gids": {}, "duplicate_usernames": {}, "duplicate_groupnames": {},
		"root_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"root_path_dirs": ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"],
		"root_path_writable_dirs": [], "uid_zero_accounts": ["root"],
		"users_without_home_directory": [], "users_not_owning_home": [], "home_dirs_too_permissive": [],
		"users_with_netrc": [], "users_with_forward": [], "users_with_rhosts": [],
		"dotfiles_group_or_world_writable": [],
		"passwd_content": "root:x:0:0:root:/root:/bin/bash\n",
		"shadow_content": "root:*:19000:0:99999:7:::\n",
		"group_content": "root:x:0:\n",
	},
}

test_fixture_passes_cis_debian_11_main if {
	r := data.cis_debian_11.main.compliance_report with input as fixture_compliant
	r.compliant == true
	count(r.violations) == 0
	r.compliance_percentage == 100
	r.failed_controls == 0
	r.passed_controls == r.total_controls
}

test_empty_input_fails_cis_debian_11_main if {
	r := data.cis_debian_11.main.compliance_report with input as {}
	r.compliant == false
	count(r.violations) > 0
	r.compliance_percentage == 0
	r.failed_controls == r.total_controls
	r.passed_controls == 0
}
