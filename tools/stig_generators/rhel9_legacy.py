# Legacy rule logic carried verbatim from the hand-maintained module (2026-11-18 baseline).
# Entries move to gen_rhel9.RULES as each rule is reviewed against the V2R10 check text.
LEGACY = {}
LEGACY_HELPERS = {}
LEGACY_HELPERS['account_auth'] = ''
LEGACY['RHEL-09-611165'] = dict(sec='account_auth', comment='Multifactor authentication must be used', name='mfa_enabled', fix='Configure MFA via SSSD with smart card or PIV authentication',
    rego='default mfa_enabled := false\n\nmfa_enabled if {\n\tinput.pam_config.mfa_enabled == true\n}\n\nmfa_enabled if {\n\tinput.pam_config.sssd_mfa == true\n}')
LEGACY['RHEL-09-611140'] = dict(sec='account_auth', comment='Passwords must be hashed with SHA-512', name='password_sha512', fix='Configure PAM to use SHA-512: Set password sufficient pam_unix.so sha512 in /etc/pam.d/system-auth',
    rego='default password_sha512 := false\n\npassword_sha512 if {\n\tinput.password_policy.sha512 == true\n}\n\npassword_sha512 if {\n\tinput.pam_config.password_hash == "sha512"\n}')
LEGACY['RHEL-09-411075'] = dict(sec='account_auth', comment='Accounts must be locked after failed login attempts', name='account_lockout_enabled', fix='Configure pam_faillock: deny=3 in /etc/security/faillock.conf',
    rego='default account_lockout_enabled := false\n\naccount_lockout_enabled if {\n\tinput.pam_config.lockout_attempts <= 3\n\tinput.pam_config.lockout_attempts > 0\n}')
LEGACY['RHEL-09-611155'] = dict(sec='account_auth', comment='System must not have empty passwords in /etc/shadow', name='no_empty_password_hashes', fix='Lock accounts with empty passwords: passwd -l <username>',
    rego='default no_empty_password_hashes := false\n\nno_empty_password_hashes if {\n\tis_array(input.local_accounts_with_empty_passwords)\n\tcount(input.local_accounts_with_empty_passwords) == 0\n}')
LEGACY['RHEL-09-611090'] = dict(sec='account_auth', comment='Password minimum length must be 15', name='password_minlen', fix='Set minlen=15 in /etc/security/pwquality.conf',
    rego='default password_minlen := false\n\npassword_minlen if {\n\tinput.password_policy.minlen >= 15\n}')
LEGACY['RHEL-09-611110'] = dict(sec='account_auth', comment='Password must require at least 1 uppercase character', name='password_uppercase', fix='Set ucredit=-1 in /etc/security/pwquality.conf',
    rego='default password_uppercase := false\n\npassword_uppercase if {\n\tinput.password_policy.ucredit <= -1\n}\n\npassword_uppercase if {\n\tinput.password_policy.minclass >= 4\n}')
LEGACY['RHEL-09-611065'] = dict(sec='account_auth', comment='Password must require at least 1 lowercase character', name='password_lowercase', fix='Set lcredit=-1 in /etc/security/pwquality.conf',
    rego='default password_lowercase := false\n\npassword_lowercase if {\n\tinput.password_policy.lcredit <= -1\n}\n\npassword_lowercase if {\n\tinput.password_policy.minclass >= 4\n}')
LEGACY['RHEL-09-611070'] = dict(sec='account_auth', comment='Password must require at least 1 numeric character', name='password_numeric', fix='Set dcredit=-1 in /etc/security/pwquality.conf',
    rego='default password_numeric := false\n\npassword_numeric if {\n\tinput.password_policy.dcredit <= -1\n}\n\npassword_numeric if {\n\tinput.password_policy.minclass >= 4\n}')
LEGACY['RHEL-09-611100'] = dict(sec='account_auth', comment='Password must require at least 1 special character', name='password_special', fix='Set ocredit=-1 in /etc/security/pwquality.conf',
    rego='default password_special := false\n\npassword_special if {\n\tinput.password_policy.ocredit <= -1\n}')
LEGACY['RHEL-09-411010'] = dict(sec='account_auth', comment='Password maximum age must be 60 days or less', name='password_maxage', fix='Set PASS_MAX_DAYS 60 in /etc/login.defs',
    rego='default password_maxage := false\n\npassword_maxage if {\n\tinput.password_policy.maxdays <= 60\n\tinput.password_policy.maxdays > 0\n}')
LEGACY['RHEL-09-611075'] = dict(sec='account_auth', comment='Password minimum age must be 1 day', name='password_minage', fix='Set PASS_MIN_DAYS 1 in /etc/login.defs',
    rego='default password_minage := false\n\npassword_minage if {\n\tinput.password_policy.mindays >= 1\n}')
LEGACY['RHEL-09-411085'] = dict(sec='account_auth', comment='Account lockout time must be at least 15 minutes', name='lockout_duration_ok', fix='Set unlock_time=900 in /etc/security/faillock.conf',
    rego='default lockout_duration_ok := false\n\nlockout_duration_ok if {\n\tinput.pam_config.lockout_time >= 900 # 900 seconds = 15 minutes\n}')
LEGACY['RHEL-09-411050'] = dict(sec='account_auth', comment='Inactive accounts must be disabled after 35 days', name='inactive_lock_ok', fix='Set INACTIVE=35 in /etc/default/useradd',
    rego='default inactive_lock_ok := false\n\ninactive_lock_ok if {\n\tinput.password_policy.inactive_days <= 35\n\tinput.password_policy.inactive_days >= 0\n}')
LEGACY['RHEL-09-411030'] = dict(sec='account_auth', comment='No duplicate UIDs should exist', name='no_duplicate_uids', fix="Identify and resolve duplicate UIDs: awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d",
    rego='default no_duplicate_uids := false\n\nno_duplicate_uids if {\n\tis_array(input.duplicate_uids)\n\tcount(input.duplicate_uids) == 0\n}')
LEGACY['RHEL-09-411110'] = dict(sec='account_auth', comment='No duplicate GIDs should exist', name='no_duplicate_gids', fix='Identify and resolve duplicate GIDs',
    rego='default no_duplicate_gids := false\n\nno_duplicate_gids if {\n\tis_array(input.duplicate_gids)\n\tcount(input.duplicate_gids) == 0\n}')
LEGACY_HELPERS['audit_logging'] = '# Helper: check if audit rule exists\naudit_rule_exists(pattern) if {\n\tsome rule in input.audit_rules\n\tcontains(rule, pattern)\n}'
LEGACY['RHEL-09-653015'] = dict(sec='audit_logging', comment='auditd service must be running', name='auditd_active', fix='Enable and start auditd: systemctl enable --now auditd',
    rego='default auditd_active := false\n\nauditd_active if {\n\tinput.services.auditd == "active"\n}')
LEGACY['RHEL-09-653055'] = dict(sec='audit_logging', comment='Audit log storage must be sufficient (max_log_file_action must not be ignore)', name='audit_storage_ok', fix='Set max_log_file_action = keep_logs in /etc/audit/auditd.conf',
    rego='default audit_storage_ok := false\n\naudit_storage_ok if {\n\tinput.auditd_config.max_log_file_action != "ignore"\n\tinput.auditd_config.max_log_file_action != "IGNORE"\n}')
LEGACY['RHEL-09-653025'] = dict(sec='audit_logging', comment='Admin space left action must be configured', name='admin_space_left_action_ok', fix='Set admin_space_left_action = single in /etc/audit/auditd.conf',
    rego='default admin_space_left_action_ok := false\n\nadmin_space_left_action_ok if {\n\taction := input.auditd_config.admin_space_left_action\n\taction != "ignore"\n\taction != "IGNORE"\n}')
LEGACY['RHEL-09-653040'] = dict(sec='audit_logging', comment='space_left_action must notify admin', name='space_left_action_ok', fix='Set space_left_action = email in /etc/audit/auditd.conf',
    rego='default space_left_action_ok := false\n\nspace_left_action_ok if {\n\taction := input.auditd_config.space_left_action\n\taction == "email"\n}\n\nspace_left_action_ok if {\n\taction := input.auditd_config.space_left_action\n\taction == "syslog"\n}')
LEGACY['RHEL-09-654010'] = dict(sec='audit_logging', comment='Audit rules: execve (b64) must be audited', name='audit_execve_b64', fix='Add audit rule: -a always,exit -F arch=b64 -S execve -k exec_commands',
    rego='default audit_execve_b64 := false\n\naudit_execve_b64 if {\n\taudit_rule_exists("-a always,exit -F arch=b64 -S execve")\n}')
LEGACY['RHEL-09-654020'] = dict(sec='audit_logging', comment='Audit rules: chown must be audited', name='audit_chown', fix='Add audit rule for chown: -a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown',
    rego='default audit_chown := false\n\naudit_chown if {\n\taudit_rule_exists("-a always,exit -F arch=b64 -S chown")\n}')
LEGACY['RHEL-09-654015'] = dict(sec='audit_logging', comment='Audit rules: chmod must be audited', name='audit_chmod', fix='Add audit rule for chmod: -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat',
    rego='default audit_chmod := false\n\naudit_chmod if {\n\taudit_rule_exists("-a always,exit -F arch=b64 -S chmod")\n}')
LEGACY['RHEL-09-654025'] = dict(sec='audit_logging', comment='Audit rules: setxattr must be audited', name='audit_setxattr', fix='Add audit rules for xattr operations',
    rego='default audit_setxattr := false\n\naudit_setxattr if {\n\taudit_rule_exists("-a always,exit -F arch=b64 -S setxattr")\n}')
LEGACY['RHEL-09-654070'] = dict(sec='audit_logging', comment='Audit rules: open with EACCES must be audited', name='audit_open_failure', fix='Add audit rules for failed file access: -a always,exit -F arch=b64 -S open -F exit=-EACCES -k access',
    rego='default audit_open_failure := false\n\naudit_open_failure if {\n\taudit_rule_exists("-a always,exit -F arch=b64 -S open")\n\taudit_rule_exists("-F exit=-EACCES")\n}\n\naudit_open_failure if {\n\taudit_rule_exists("EACCES")\n\taudit_rule_exists("EPERM")\n}')
LEGACY['RHEL-09-654215'] = dict(sec='audit_logging', comment='Audit rules: sudoers modification must be audited', name='audit_sudoers', fix='Add audit rule: -w /etc/sudoers -p wa -k sudoers_change',
    rego='default audit_sudoers := false\n\naudit_sudoers if {\n\taudit_rule_exists("-w /etc/sudoers")\n}')
LEGACY['RHEL-09-654240'] = dict(sec='audit_logging', comment='Audit rules: /etc/passwd modification must be audited', name='audit_passwd_file', fix='Add audit rule: -w /etc/passwd -p wa -k usermod',
    rego='default audit_passwd_file := false\n\naudit_passwd_file if {\n\taudit_rule_exists("-w /etc/passwd")\n}')
LEGACY['RHEL-09-654150'] = dict(sec='audit_logging', comment='Audit rules: privileged command use must be audited', name='audit_privileged_cmds', fix='Add audit rule: -a always,exit -F path=/usr/bin/sudo -F perm=x -k priv_cmd',
    rego='default audit_privileged_cmds := false\n\naudit_privileged_cmds if {\n\taudit_rule_exists("-a always,exit -F path=/usr/bin/sudo")\n}\n\naudit_privileged_cmds if {\n\taudit_rule_exists("privileged")\n}')
LEGACY['RHEL-09-654080'] = dict(sec='audit_logging', comment='Audit rules: module loading/unloading must be audited', name='audit_modules', fix='Add audit rules for module operations',
    rego='default audit_modules := false\n\naudit_modules if {\n\taudit_rule_exists("-a always,exit -F arch=b64 -S finit_module")\n}\n\naudit_modules if {\n\taudit_rule_exists("-a always,exit -F arch=b64 -S init_module")\n}')
LEGACY_HELPERS['configuration_management'] = ''
LEGACY['RHEL-09-211050'] = dict(sec='configuration_management', comment='Ctrl-Alt-Delete key sequence must be disabled', name='ctrl_alt_del_disabled', fix='Configure the system to disable the Ctrl-Alt-Delete sequence: systemctl mask ctrl-alt-del.target',
    rego='default ctrl_alt_del_disabled := false\n\nctrl_alt_del_disabled if {\n\tinput.services["ctrl-alt-del.target"] == "masked"\n}\n\nctrl_alt_del_disabled if {\n\tinput.services["ctrl-alt-del.target"] == "inactive"\n\tinput.kernel_params["kernel.ctrl-alt-del"] == "0"\n}')
LEGACY['RHEL-09-431010'] = dict(sec='configuration_management', comment='SELinux must be enabled in enforcing mode', name='selinux_enforcing', fix='Configure SELinux to be enabled: Set SELINUX=enforcing in /etc/selinux/config',
    rego='default selinux_enforcing := false\n\nselinux_enforcing if {\n\tinput.selinux.status == "enforcing"\n}')
LEGACY['RHEL-09-671010'] = dict(sec='configuration_management', comment='FIPS mode must be enabled', name='fips_mode_enabled', fix='Enable FIPS mode: fips-mode-setup --enable && reboot',
    rego='default fips_mode_enabled := false\n\nfips_mode_enabled if {\n\tinput.fips_mode == true\n}')
LEGACY['RHEL-09-215105'] = dict(sec='configuration_management', comment='System crypto policy must be FIPS', name='crypto_policy_fips', fix='Set the crypto policy: update-crypto-policies --set FIPS',
    rego='default crypto_policy_fips := false\n\ncrypto_policy_fips if {\n\tinput.crypto_policy == "FIPS"\n}\n\ncrypto_policy_fips if {\n\tinput.crypto_policy == "FIPS:OSPP"\n}')
LEGACY['RHEL-09-271105'] = dict(sec='configuration_management', comment='The Ctrl-Alt-Delete graphical key sequence must be disabled', name='ctrl_alt_del_graphical_disabled', fix="Disable Ctrl-Alt-Del in GNOME: gsettings set org.gnome.settings-daemon.plugins.media-keys logout ''",
    rego='default ctrl_alt_del_graphical_disabled := false\n\nctrl_alt_del_graphical_disabled if {\n\tinput.dconf_settings["org/gnome/settings-daemon/plugins/media-keys/logout"] == "\'\'"\n}\n\nctrl_alt_del_graphical_disabled if {\n\tis_object(input.packages)\n\tnot input.packages["gnome-desktop3"]\n}')
LEGACY['RHEL-09-431015'] = dict(sec='configuration_management', comment='SELinux policy must be targeted', name='selinux_targeted', fix='Configure SELinux policy: Set SELINUXTYPE=targeted in /etc/selinux/config',
    rego='default selinux_targeted := false\n\nselinux_targeted if {\n\tinput.selinux.policy == "targeted"\n}')
LEGACY['RHEL-09-212010'] = dict(sec='configuration_management', comment='GRUB bootloader must be password protected', name='grub_password_set', fix='Configure a bootloader password: grub2-setpassword',
    rego='default grub_password_set := false\n\ngrub_password_set if {\n\tinput.grub_config.password_set == true\n}')
LEGACY['RHEL-09-211020'] = dict(sec='configuration_management', comment='Must display the Standard Mandatory DoD Notice on login banner', name='login_banner_set', fix='Configure /etc/issue with the DoD warning banner text',
    rego='default login_banner_set := false\n\nlogin_banner_set if {\n\tcontains(input.login_banner.issue, "You are accessing a U.S. Government")\n}\n\nlogin_banner_set if {\n\tcontains(input.login_banner.issue, "authorized users only")\n}')
LEGACY['RHEL-09-255025'] = dict(sec='configuration_management', comment='SSH must display banner before granting access', name='ssh_banner_set', fix='Configure Banner in /etc/ssh/sshd_config to point to /etc/issue',
    rego='default ssh_banner_set := false\n\nssh_banner_set if {\n\tinput.ssh_config.Banner != ""\n\tinput.ssh_config.Banner != "none"\n}')
LEGACY['RHEL-09-213070'] = dict(sec='configuration_management', comment='kernel.randomize_va_space must be set to 2', name='aslr_enabled', fix='Set kernel.randomize_va_space=2 in /etc/sysctl.d/99-stig.conf and run sysctl -p',
    rego='default aslr_enabled := false\n\naslr_enabled if {\n\tinput.kernel_params["kernel.randomize_va_space"] == "2"\n}')
LEGACY['RHEL-09-213010'] = dict(sec='configuration_management', comment='kernel.dmesg_restrict must be set to 1', name='dmesg_restricted', fix='Set kernel.dmesg_restrict=1 in /etc/sysctl.d/99-stig.conf',
    rego='default dmesg_restricted := false\n\ndmesg_restricted if {\n\tinput.kernel_params["kernel.dmesg_restrict"] == "1"\n}')
LEGACY['RHEL-09-213015'] = dict(sec='configuration_management', comment='kernel.perf_event_paranoid must be set to 2', name='perf_event_restricted', fix='Set kernel.perf_event_paranoid=2 in /etc/sysctl.d/99-stig.conf',
    rego='default perf_event_restricted := false\n\nperf_event_restricted if {\n\tto_number(input.kernel_params["kernel.perf_event_paranoid"]) >= 2\n}')
LEGACY['RHEL-09-213075'] = dict(sec='configuration_management', comment='kernel.unprivileged_bpf_disabled must be set to 1', name='bpf_restricted', fix='Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/99-stig.conf',
    rego='default bpf_restricted := false\n\nbpf_restricted if {\n\tinput.kernel_params["kernel.unprivileged_bpf_disabled"] == "1"\n}')
LEGACY['RHEL-09-251045'] = dict(sec='configuration_management', comment='net.core.bpf_jit_harden must be set to 2', name='bpf_jit_hardened', fix='Set net.core.bpf_jit_harden=2 in /etc/sysctl.d/99-stig.conf',
    rego='default bpf_jit_hardened := false\n\nbpf_jit_hardened if {\n\tinput.kernel_params["net.core.bpf_jit_harden"] == "2"\n}')
LEGACY['RHEL-09-291010'] = dict(sec='configuration_management', comment='USB storage kernel module must be disabled', name='usb_storage_disabled', fix="Disable USB storage: echo 'install usb-storage /bin/false' >> /etc/modprobe.d/usb-storage.conf",
    rego='default usb_storage_disabled := false\n\nusb_storage_disabled if {\n\tinput.kernel_modules["usb-storage"].status == "disabled"\n}\n\nusb_storage_disabled if {\n\tinput.kernel_modules["usb-storage"].blacklisted == true\n}')
LEGACY['RHEL-09-213055'] = dict(sec='configuration_management', comment='Firewire kernel module must be disabled', name='firewire_disabled', fix="Disable Firewire: echo 'install firewire-core /bin/false' >> /etc/modprobe.d/firewire.conf",
    rego='default firewire_disabled := false\n\nfirewire_disabled if {\n\tinput.kernel_modules["firewire-core"].status == "disabled"\n}\n\nfirewire_disabled if {\n\tinput.kernel_modules["firewire-core"].blacklisted == true\n}')
LEGACY['RHEL-09-651015'] = dict(sec='configuration_management', comment='AIDE integrity checking cron job must exist', name='aide_cron_configured', fix="Configure AIDE cron job: echo '0 5 * * * /usr/sbin/aide --check' >> /etc/cron.d/aide",
    rego='default aide_cron_configured := false\n\naide_cron_configured if {\n\tinput.aide_config.cron_job == true\n}')
LEGACY['RHEL-09-651010'] = dict(sec='configuration_management', comment='AIDE must be installed', name='aide_installed', fix='Install AIDE: dnf install aide -y && aide --init',
    rego='default aide_installed := false\n\naide_installed if {\n\tinput.packages.aide == true\n}')
LEGACY['RHEL-09-231015'] = dict(sec='configuration_management', comment='/tmp must be on a separate partition', name='tmp_separate_partition', fix='Configure /tmp on a separate partition in /etc/fstab',
    rego='default tmp_separate_partition := false\n\ntmp_separate_partition if {\n\tsome mount in input.filesystem_mounts\n\tmount.mount == "/tmp"\n\tmount.device != "tmpfs"\n}')
LEGACY['RHEL-09-231045'] = dict(sec='configuration_management', comment='/tmp must have nodev option', name='tmp_nodev', fix='Add nodev option to /tmp in /etc/fstab',
    rego='default tmp_nodev := false\n\ntmp_nodev if {\n\tsome mount in input.filesystem_mounts\n\tmount.mount == "/tmp"\n\t"nodev" in mount.options\n}')
LEGACY['RHEL-09-231050'] = dict(sec='configuration_management', comment='/tmp must have nosuid option', name='tmp_nosuid', fix='Add nosuid option to /tmp in /etc/fstab',
    rego='default tmp_nosuid := false\n\ntmp_nosuid if {\n\tsome mount in input.filesystem_mounts\n\tmount.mount == "/tmp"\n\t"nosuid" in mount.options\n}')
LEGACY['RHEL-09-231055'] = dict(sec='configuration_management', comment='/tmp must have noexec option', name='tmp_noexec', fix='Add noexec option to /tmp in /etc/fstab',
    rego='default tmp_noexec := false\n\ntmp_noexec if {\n\tsome mount in input.filesystem_mounts\n\tmount.mount == "/tmp"\n\t"noexec" in mount.options\n}')
LEGACY['RHEL-09-231025'] = dict(sec='configuration_management', comment='/var/log must be a separate partition', name='var_log_separate', fix='Configure /var/log on a separate partition',
    rego='default var_log_separate := false\n\nvar_log_separate if {\n\tsome mount in input.filesystem_mounts\n\tmount.mount == "/var/log"\n}')
LEGACY['RHEL-09-231030'] = dict(sec='configuration_management', comment='/var/log/audit must be a separate partition', name='var_log_audit_separate', fix='Configure /var/log/audit on a separate partition',
    rego='default var_log_audit_separate := false\n\nvar_log_audit_separate if {\n\tsome mount in input.filesystem_mounts\n\tmount.mount == "/var/log/audit"\n}')
LEGACY_HELPERS['file_permissions'] = '# Parse an octal permission string ("644", "0644", "0o644") to an integer; undefined if not octal.\noctal(s) := n if {\n\tt := trim_prefix(lower(trim_space(sprintf("%v", [s]))), "0o")\n\tregex.match(`^[0-7]{1,4}$`, t)\n\tp := concat("", [substring("0000", 0, 4 - count(t)), t])\n\tds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]\n\tn := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])\n}\n\n# true when mode grants nothing beyond max (both octal strings)\nmode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0'
LEGACY['RHEL-09-232255'] = dict(sec='file_permissions', comment='No unowned files or directories', name='no_unowned_files', fix='Find and remediate unowned files: find / -nouser -xdev -print',
    rego='default no_unowned_files := false\n\nno_unowned_files if {\n\tis_array(input.file_permissions.unowned_files)\n\tcount(input.file_permissions.unowned_files) == 0\n}')
LEGACY['RHEL-09-232250'] = dict(sec='file_permissions', comment='No ungrouped files or directories', name='no_ungrouped_files', fix='Find and remediate ungrouped files: find / -nogroup -xdev -print',
    rego='default no_ungrouped_files := false\n\nno_ungrouped_files if {\n\tis_array(input.file_permissions.ungrouped_files)\n\tcount(input.file_permissions.ungrouped_files) == 0\n}')
LEGACY['RHEL-09-232075'] = dict(sec='file_permissions', comment='/etc/passwd must have mode 0644 or less', name='passwd_permissions_ok', fix='Fix /etc/passwd permissions: chmod 0644 /etc/passwd',
    rego='default passwd_permissions_ok := false\n\npasswd_permissions_ok if {\n\tmode_within(input.file_permissions.etc_passwd.mode, "0644")\n}')
LEGACY['RHEL-09-232270'] = dict(sec='file_permissions', comment='/etc/shadow must have mode 0000', name='shadow_permissions_ok', fix='Fix /etc/shadow permissions: chmod 0000 /etc/shadow',
    rego='default shadow_permissions_ok := false\n\nshadow_permissions_ok if {\n\tmode_within(input.file_permissions.etc_shadow.mode, "0000")\n}')
LEGACY['RHEL-09-232055'] = dict(sec='file_permissions', comment='/etc/group must have mode 0644 or less', name='group_permissions_ok', fix='Fix /etc/group permissions: chmod 0644 /etc/group',
    rego='default group_permissions_ok := false\n\ngroup_permissions_ok if {\n\tmode_within(input.file_permissions.etc_group.mode, "0644")\n}')
LEGACY['RHEL-09-232065'] = dict(sec='file_permissions', comment='/etc/gshadow must have mode 0000', name='gshadow_permissions_ok', fix='Fix /etc/gshadow permissions: chmod 0000 /etc/gshadow',
    rego='default gshadow_permissions_ok := false\n\ngshadow_permissions_ok if {\n\tmode_within(input.file_permissions.etc_gshadow.mode, "0000")\n}')
LEGACY['RHEL-09-232020'] = dict(sec='file_permissions', comment='Library files must have mode 0755 or less', name='lib_permissions_ok', fix='Fix library permissions: find /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec chmod 755 {} \\;',
    rego='default lib_permissions_ok := false\n\nlib_permissions_ok if {\n\tinput.file_permissions.library_files_ok == true\n}')
LEGACY['RHEL-09-232200'] = dict(sec='file_permissions', comment='Library dirs must be owned by root', name='lib_dirs_owned_root', fix='Fix library ownership: find /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec chown root {} \\;',
    rego='default lib_dirs_owned_root := false\n\nlib_dirs_owned_root if {\n\tinput.file_permissions.library_dirs_owned_root == true\n}')
LEGACY['RHEL-09-232010'] = dict(sec='file_permissions', comment='System commands must have mode 0755 or less', name='sys_commands_permissions_ok', fix='Fix system command permissions: find /bin /sbin /usr/bin /usr/sbin -perm /022 -exec chmod 755 {} \\;',
    rego='default sys_commands_permissions_ok := false\n\nsys_commands_permissions_ok if {\n\tinput.file_permissions.system_commands_ok == true\n}')
LEGACY['RHEL-09-232050'] = dict(sec='file_permissions', comment='All interactive local users must have home dir permissions set to 0750 or less', name='home_dir_permissions_ok', fix='Fix home directory permissions: chmod 0750 /home/<username>',
    rego='default home_dir_permissions_ok := false\n\nhome_dir_permissions_ok if {\n\tis_array(input.file_permissions.insecure_home_dirs)\n\tcount(input.file_permissions.insecure_home_dirs) == 0\n}')
LEGACY_HELPERS['network'] = ''
LEGACY['RHEL-09-251015'] = dict(sec='network', comment='Firewall must be active', name='firewall_active', fix='Enable firewalld: systemctl enable --now firewalld',
    rego='default firewall_active := false\n\nfirewall_active if {\n\tinput.firewall.active == true\n}\n\nfirewall_active if {\n\tinput.services.firewalld == "active"\n}\n\nfirewall_active if {\n\tinput.services.nftables == "active"\n}')
LEGACY['RHEL-09-253075'] = dict(sec='network', comment='IP forwarding must be disabled', name='ip_forwarding_disabled', fix='Disable IP forwarding: Set net.ipv4.ip_forward=0 in /etc/sysctl.d/99-stig.conf',
    rego='default ip_forwarding_disabled := false\n\nip_forwarding_disabled if {\n\tinput.kernel_params["net.ipv4.ip_forward"] == "0"\n\tinput.network_config.ipv4_forwarding == false\n}\n\nip_forwarding_disabled if {\n\tinput.kernel_params["net.ipv4.ip_forward"] == "0"\n}')
LEGACY['RHEL-09-253015'] = dict(sec='network', comment='ICMP redirects must not be accepted (IPv4)', name='icmp_redirect_accept_disabled', fix='Set net.ipv4.conf.all.accept_redirects=0 in /etc/sysctl.d/99-stig.conf',
    rego='default icmp_redirect_accept_disabled := false\n\nicmp_redirect_accept_disabled if {\n\tinput.kernel_params["net.ipv4.conf.all.accept_redirects"] == "0"\n\tinput.kernel_params["net.ipv4.conf.default.accept_redirects"] == "0"\n}')
LEGACY['RHEL-09-253065'] = dict(sec='network', comment='ICMP redirects must not be sent', name='icmp_redirect_send_disabled', fix='Set net.ipv4.conf.all.send_redirects=0 in /etc/sysctl.d/99-stig.conf',
    rego='default icmp_redirect_send_disabled := false\n\nicmp_redirect_send_disabled if {\n\tinput.kernel_params["net.ipv4.conf.all.send_redirects"] == "0"\n\tinput.kernel_params["net.ipv4.conf.default.send_redirects"] == "0"\n}')
LEGACY['RHEL-09-253020'] = dict(sec='network', comment='Source routing must be disabled', name='source_routing_disabled', fix='Set net.ipv4.conf.all.accept_source_route=0 in /etc/sysctl.d/99-stig.conf',
    rego='default source_routing_disabled := false\n\nsource_routing_disabled if {\n\tinput.kernel_params["net.ipv4.conf.all.accept_source_route"] == "0"\n\tinput.kernel_params["net.ipv4.conf.default.accept_source_route"] == "0"\n}')
LEGACY['RHEL-09-253060'] = dict(sec='network', comment='Bogus ICMP responses must be ignored', name='icmp_bogus_error_responses', fix='Set net.ipv4.icmp_ignore_bogus_error_responses=1 in /etc/sysctl.d/99-stig.conf',
    rego='default icmp_bogus_error_responses := false\n\nicmp_bogus_error_responses if {\n\tinput.kernel_params["net.ipv4.icmp_ignore_bogus_error_responses"] == "1"\n}')
LEGACY['RHEL-09-253010'] = dict(sec='network', comment='IPv4 TCP syncookies must be enabled', name='tcp_syncookies_enabled', fix='Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.d/99-stig.conf',
    rego='default tcp_syncookies_enabled := false\n\ntcp_syncookies_enabled if {\n\tinput.kernel_params["net.ipv4.tcp_syncookies"] == "1"\n}')
LEGACY['RHEL-09-253035'] = dict(sec='network', comment='Reverse path filter must be enabled', name='rp_filter_enabled', fix='Set net.ipv4.conf.all.rp_filter=1 in /etc/sysctl.d/99-stig.conf',
    rego='default rp_filter_enabled := false\n\nrp_filter_enabled if {\n\tinput.kernel_params["net.ipv4.conf.all.rp_filter"] == "1"\n}\n\nrp_filter_enabled if {\n\tinput.kernel_params["net.ipv4.conf.all.rp_filter"] == "2"\n}')
LEGACY['RHEL-09-291040'] = dict(sec='network', comment='Wireless interfaces must be disabled unless mission requires', name='wireless_disabled', fix='Disable wireless: nmcli radio wifi off or disable in NetworkManager',
    rego='default wireless_disabled := false\n\nwireless_disabled if {\n\tinput.network_config.wireless_disabled == true\n}\n\nwireless_disabled if {\n\tis_array(input.wireless_interfaces)\n\tcount(input.wireless_interfaces) == 0\n}')
LEGACY['RHEL-09-291035'] = dict(sec='network', comment='Bluetooth kernel module must be disabled', name='bluetooth_module_disabled', fix="Blacklist bluetooth: echo 'install bluetooth /bin/false' >> /etc/modprobe.d/bluetooth.conf",
    rego='default bluetooth_module_disabled := false\n\nbluetooth_module_disabled if {\n\tinput.kernel_modules.bluetooth.blacklisted == true\n}\n\nbluetooth_module_disabled if {\n\tinput.kernel_modules.bluetooth.status == "disabled"\n}')
LEGACY['RHEL-09-251040'] = dict(sec='network', comment='Network interfaces must not be in promiscuous mode', name='no_promiscuous_interfaces', fix='Disable promiscuous mode: ip link set <interface> promisc off',
    rego='default no_promiscuous_interfaces := false\n\nno_promiscuous_interfaces if {\n\tis_array(input.promiscuous_interfaces)\n\tcount(input.promiscuous_interfaces) == 0\n}')
LEGACY_HELPERS['pki_crypto'] = ''
LEGACY['RHEL-09-672020'] = dict(sec='pki_crypto', comment='Crypto policy must not be overridden', name='crypto_policy_not_overridden', fix='Remove any CRYPTO_POLICY overrides from application config files',
    rego='default crypto_policy_not_overridden := false\n\ncrypto_policy_not_overridden if {\n\tis_array(input.crypto_policy_overrides)\n\tcount(input.crypto_policy_overrides) == 0\n}')
LEGACY['RHEL-09-672055'] = dict(sec='pki_crypto', comment='openssl must use system crypto policy', name='openssl_system_policy', fix='Ensure /etc/crypto-policies/ is configured and not overriding system-wide policy',
    rego='default openssl_system_policy := false\n\nopenssl_system_policy if {\n\tinput.openssl_config.system_policy == true\n}\n\nopenssl_system_policy if {\n\tinput.openssl_config.legacy_override == false\n}')
LEGACY['RHEL-09-611170'] = dict(sec='pki_crypto', comment='Certificate revocation must be checked (OCSP/CRL)', name='cert_revocation_check', fix='Configure OCSP: Set ocsp_stapling=yes and enable CRL checking in SSSD',
    rego='default cert_revocation_check := false\n\ncert_revocation_check if {\n\tinput.pki_config.ocsp_enabled == true\n}\n\ncert_revocation_check if {\n\tinput.pki_config.crl_checking == true\n}')
LEGACY['RHEL-09-631010'] = dict(sec='pki_crypto', comment='The system must use a DoD-approved PKI to authenticate', name='dod_ca_trusted', fix='Install DoD Root CA: trust anchor --store DoD_PKE_CA_chain.pem',
    rego='default dod_ca_trusted := false\n\ndod_ca_trusted if {\n\tinput.certificates.dod_root_ca_installed == true\n}')
LEGACY['RHEL-09-271045'] = dict(sec='pki_crypto', comment='smartcard removal must lock the session', name='smartcard_lock_on_removal', fix='Configure pcscd and GNOME smart card removal action to lock session',
    rego='default smartcard_lock_on_removal := false\n\nsmartcard_lock_on_removal if {\n\tinput.pam_config.smartcard_removal_lock == true\n}')
LEGACY['RHEL-09-631015'] = dict(sec='pki_crypto', comment='System must map certificate to user', name='cert_user_mapping', fix='Configure certificate to user mapping in SSSD configuration',
    rego='default cert_user_mapping := false\n\ncert_user_mapping if {\n\tinput.sssd_config.cert_user_mapping != ""\n}\n\ncert_user_mapping if {\n\tinput.pam_config.cert_mapping_configured == true\n}')
LEGACY_HELPERS['services'] = '# Helper: service is inactive or masked. Fail closed: a service with no\n# reported state is NOT treated as disabled (absent telemetry is not evidence).\nservice_disabled(svc) if input.services[svc] in {"inactive", "masked"}\n\n# Helper: package not installed. Fail closed: only an explicit `false` counts.\npkg_absent(pkg) if input.packages[pkg] == false\n\n# Helper: at least one alias is explicitly absent and no alias is installed.\npkgs_absent(names) if {\n\tsome n in names\n\tpkg_absent(n)\n\tevery m in names {\n\t\tnot input.packages[m] == true\n\t}\n}'
LEGACY['RHEL-09-215060'] = dict(sec='services', comment='TFTP server must not be installed', name='tftp_server_absent', fix='Remove tftp-server: dnf remove tftp-server -y',
    rego='default tftp_server_absent := false\n\ntftp_server_absent if pkg_absent("tftp-server")')
LEGACY['RHEL-09-215015'] = dict(sec='services', comment='FTP server must not be running', name='ftp_server_disabled', fix='Remove vsftpd: dnf remove vsftpd -y',
    rego='default ftp_server_disabled := false\n\n# The vsftpd package must not be installed (an inactive ftpd service is not enough).\nftp_server_disabled if pkg_absent("vsftpd")')
LEGACY['RHEL-09-215040'] = dict(sec='services', comment='telnet server must not be installed', name='telnet_server_absent', fix='Remove telnet-server: dnf remove telnet-server -y',
    rego='default telnet_server_absent := false\n\ntelnet_server_absent if pkgs_absent(["telnet-server", "telnetd"])')
LEGACY['RHEL-09-231040'] = dict(sec='services', comment='autofs must be disabled', name='autofs_disabled', fix='Disable autofs: systemctl disable --now autofs',
    rego='default autofs_disabled := false\n\nautofs_disabled if service_disabled("autofs")')
LEGACY['RHEL-09-215025'] = dict(sec='services', comment='NFS server must not be running unless required', name='nfs_disabled', fix='Disable NFS server: systemctl disable --now nfs-server',
    rego='default nfs_disabled := false\n\nnfs_disabled if service_disabled("nfs-server")\nnfs_disabled if service_disabled("nfsd")')
LEGACY_HELPERS['software_integrity'] = ''
LEGACY['RHEL-09-214025'] = dict(sec='software_integrity', comment='GPG must be enabled for all repo files', name='all_repos_gpgcheck', fix='Enable gpgcheck=1 in all .repo files under /etc/yum.repos.d/',
    rego='default all_repos_gpgcheck := false\n\nall_repos_gpgcheck if {\n\tcount([r | some r in input.yum_repos; object.get(r, "gpgcheck", false) != true]) == 0\n\tcount(input.yum_repos) > 0\n}\n\nall_repos_gpgcheck if {\n\tcount(input.yum_repos) == 0\n}')
LEGACY['RHEL-09-214020'] = dict(sec='software_integrity', comment='Kernel must not load unverified modules', name='localpkg_gpgcheck', fix='Enable local package GPG check: Set localpkg_gpgcheck=1 in /etc/dnf/dnf.conf',
    rego='default localpkg_gpgcheck := false\n\nlocalpkg_gpgcheck if {\n\tinput.dnf_config.localpkg_gpgcheck == true\n}')
LEGACY['RHEL-09-214010'] = dict(sec='software_integrity', comment='GPG check must be globally activated for repository packages', name='gpgcheck_global', fix='Enable GPG check globally: Set gpgcheck=1 in /etc/dnf/dnf.conf',
    rego='default gpgcheck_global := false\n\ngpgcheck_global if {\n\tinput.dnf_config.gpgcheck == true\n}\n\ngpgcheck_global if {\n\tinput.yum_config.gpgcheck == true\n}')
LEGACY['RHEL-09-651020'] = dict(sec='software_integrity', comment='AIDE must be configured to use FIPS 140-3 approved hashes', name='aide_fips_hashes', fix='Configure AIDE to use SHA-512: Set NORMAL = sha512+rmd160+sha1+haval+tiger+crc32 in /etc/aide.conf',
    rego='default aide_fips_hashes := false\n\naide_fips_hashes if {\n\tinput.aide_config.hash_algorithms\n\talgorithms := input.aide_config.hash_algorithms\n\t"sha512" in algorithms\n}\n\naide_fips_hashes if {\n\tinput.aide_config.hash_algorithms\n\talgorithms := input.aide_config.hash_algorithms\n\t"sha256" in algorithms\n}')
LEGACY['RHEL-09-213020'] = dict(sec='software_integrity', comment='kernel module loading via sysctl must be disabled (kexec)', name='kexec_disabled', fix='Disable kexec: Set kernel.kexec_load_disabled=1 in /etc/sysctl.d/99-stig.conf',
    rego='default kexec_disabled := false\n\nkexec_disabled if {\n\tinput.kernel_params["kernel.kexec_load_disabled"] == "1"\n}')
LEGACY['RHEL-09-652010'] = dict(sec='software_integrity', comment='rsyslog must be installed', name='rsyslog_installed', fix='Install rsyslog: dnf install rsyslog -y',
    rego='default rsyslog_installed := false\n\nrsyslog_installed if {\n\tinput.packages.rsyslog == true\n}')
LEGACY['RHEL-09-652020'] = dict(sec='software_integrity', comment='rsyslog service must be active', name='rsyslog_active', fix='Enable and start rsyslog: systemctl enable --now rsyslog',
    rego='default rsyslog_active := false\n\nrsyslog_active if {\n\tinput.services.rsyslog == "active"\n}')
LEGACY_HELPERS['ssh_config'] = '# Approved ciphers for FIPS compliance\napproved_ciphers := {\n\t"aes256-gcm@openssh.com",\n\t"aes128-gcm@openssh.com",\n\t"aes256-ctr",\n\t"aes192-ctr",\n\t"aes128-ctr",\n}\n\n# Approved MACs\napproved_macs := {\n\t"hmac-sha2-512",\n\t"hmac-sha2-256",\n\t"hmac-sha2-512-etm@openssh.com",\n\t"hmac-sha2-256-etm@openssh.com",\n}\n\n# Approved key exchange algorithms\napproved_kex := {\n\t"ecdh-sha2-nistp256",\n\t"ecdh-sha2-nistp384",\n\t"ecdh-sha2-nistp521",\n\t"diffie-hellman-group-exchange-sha256",\n\t"diffie-hellman-group14-sha256",\n}'
LEGACY['RHEL-09-255065'] = dict(sec='ssh_config', comment='SSH must use FIPS-approved ciphers', name='ssh_fips_ciphers', fix='Set Ciphers aes256-ctr,aes192-ctr,aes128-ctr in /etc/ssh/sshd_config',
    rego='default ssh_fips_ciphers := false\n\nssh_fips_ciphers if {\n\tciphers_str := input.ssh_config.Ciphers\n\tciphers := split(ciphers_str, ",")\n\tcount([c | some c in ciphers; not c in approved_ciphers]) == 0\n\tcount(ciphers) > 0\n}')
LEGACY['RHEL-09-255075'] = dict(sec='ssh_config', comment='SSH must use FIPS-approved MACs', name='ssh_fips_macs', fix='Set MACs hmac-sha2-512,hmac-sha2-256 in /etc/ssh/sshd_config',
    rego='default ssh_fips_macs := false\n\nssh_fips_macs if {\n\tmacs_str := input.ssh_config.MACs\n\tmacs := split(macs_str, ",")\n\tcount([m | some m in macs; not m in approved_macs]) == 0\n\tcount(macs) > 0\n}')
LEGACY['RHEL-09-255040'] = dict(sec='ssh_config', comment='SSH must not permit empty passwords', name='ssh_no_empty_passwords', fix='Set PermitEmptyPasswords no in /etc/ssh/sshd_config',
    rego='default ssh_no_empty_passwords := false\n\nssh_no_empty_passwords if {\n\tlower(input.ssh_config.PermitEmptyPasswords) == "no"\n}')
LEGACY['RHEL-09-255050'] = dict(sec='ssh_config', comment='SSH must use privilege separation', name='ssh_use_pam', fix='Set UsePAM yes in /etc/ssh/sshd_config',
    rego='default ssh_use_pam := false\n\nssh_use_pam if {\n\tlower(input.ssh_config.UsePAM) == "yes"\n}')
LEGACY['RHEL-09-255045'] = dict(sec='ssh_config', comment='SSH must not permit root login', name='ssh_no_root_login', fix='Set PermitRootLogin no in /etc/ssh/sshd_config',
    rego='default ssh_no_root_login := false\n\nssh_no_root_login if {\n\tlower(input.ssh_config.PermitRootLogin) == "no"\n}\n\nssh_no_root_login if {\n\tlower(input.ssh_config.PermitRootLogin) == "forced-commands-only"\n}')
LEGACY['RHEL-09-255080'] = dict(sec='ssh_config', comment='SSH must not allow host-based authentication', name='ssh_no_hostbased_auth', fix='Set HostbasedAuthentication no in /etc/ssh/sshd_config',
    rego='default ssh_no_hostbased_auth := false\n\nssh_no_hostbased_auth if {\n\tlower(input.ssh_config.HostbasedAuthentication) == "no"\n}')
LEGACY['RHEL-09-255100'] = dict(sec='ssh_config', comment='SSH ClientAliveInterval must be 600 or less', name='ssh_client_alive_interval_ok', fix='Set ClientAliveInterval 600 in /etc/ssh/sshd_config',
    rego='default ssh_client_alive_interval_ok := false\n\nssh_client_alive_interval_ok if {\n\tinterval := to_number(input.ssh_config.ClientAliveInterval)\n\tinterval <= 600\n\tinterval > 0\n}')
LEGACY['RHEL-09-255095'] = dict(sec='ssh_config', comment='SSH ClientAliveCountMax must be 1 or less', name='ssh_client_alive_count_ok', fix='Set ClientAliveCountMax 1 in /etc/ssh/sshd_config',
    rego='default ssh_client_alive_count_ok := false\n\nssh_client_alive_count_ok if {\n\tcount_max := to_number(input.ssh_config.ClientAliveCountMax)\n\tcount_max > 0 # 0 disables connection termination in sshd\n\tcount_max <= 1\n}')
LEGACY['RHEL-09-255160'] = dict(sec='ssh_config', comment='SSH must use strict mode', name='ssh_strict_modes', fix='Set StrictModes yes in /etc/ssh/sshd_config',
    rego='default ssh_strict_modes := false\n\nssh_strict_modes if {\n\tlower(input.ssh_config.StrictModes) == "yes"\n}')
LEGACY['RHEL-09-255145'] = dict(sec='ssh_config', comment='SSH must disable rhosts authentication', name='ssh_ignore_rhosts', fix='Set IgnoreRhosts yes in /etc/ssh/sshd_config',
    rego='default ssh_ignore_rhosts := false\n\nssh_ignore_rhosts if {\n\tlower(input.ssh_config.IgnoreRhosts) == "yes"\n}')
LEGACY['RHEL-09-255150'] = dict(sec='ssh_config', comment='SSH must not allow .shosts', name='ssh_ignore_user_known_hosts', fix='Set IgnoreUserKnownHosts yes in /etc/ssh/sshd_config',
    rego='default ssh_ignore_user_known_hosts := false\n\nssh_ignore_user_known_hosts if {\n\tlower(input.ssh_config.IgnoreUserKnownHosts) == "yes"\n}')
LEGACY['RHEL-09-255165'] = dict(sec='ssh_config', comment='SSH PrintLastLog must be enabled', name='ssh_print_last_log', fix='Set PrintLastLog yes in /etc/ssh/sshd_config',
    rego='default ssh_print_last_log := false\n\nssh_print_last_log if {\n\tlower(input.ssh_config.PrintLastLog) == "yes"\n}')
LEGACY['RHEL-09-255155'] = dict(sec='ssh_config', comment='SSH X11Forwarding must be disabled', name='ssh_no_x11', fix='Set X11Forwarding no in /etc/ssh/sshd_config',
    rego='default ssh_no_x11 := false\n\nssh_no_x11 if {\n\tlower(input.ssh_config.X11Forwarding) == "no"\n}')
