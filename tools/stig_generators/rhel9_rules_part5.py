"""Reviewed logic table for gen_rhel9.py, part 5 (DISA STIG for RHEL 9, V2R10): auditd.conf settings, audit file
ownership and modes, the audit rules RHEL-09-654030 .. 654275 and four crypto rules. Same spec format as
rhel9_rules.py (R, helpers); imported by the last lines of rhel9_rules.py, so every name below is already defined
there. Reviewed 2026-11-22 against the full V2R10 check text of each rule.
"""
from rhel9_rules import AUID, R, RULES, helpers, nest, num_rule, rego_set

# ── audit_logging: /etc/audit/auditd.conf ───────────────────────────────────────────────────────


def conf_rule(sid, name, key, allowed, bad, att=None, what="", green=None):
    """an auditd.conf keyword whose value must be one of `allowed` (case-insensitive, as auditd reads it)"""
    R("audit_logging", sid, name, [("auditd_config", key)],
      [[f'_kw(["auditd_config", "{key}"]) in {rego_set(allowed)}']],
      {"auditd_config": {key: green or allowed[0]}}, [{"auditd_config": {key: b}} for b in bad],
      f"{key} in /etc/audit/auditd.conf must be {' or '.join(allowed)}"
      + (f", or the SA must attest that {what} (input.attest.{att})" if att else ""),
      f"Set {key} = {allowed[0]} in /etc/audit/auditd.conf and restart auditd",
      comment=f"{key} as configured in /etc/audit/auditd.conf (null when missing or commented out)",
      attest_alts=[[f'_attested("{att}")']] if att else [],
      pass_cases=[{"auditd_config": {key: a.upper()}} for a in allowed[1:]]
      + ([{"auditd_config": {key: bad[0]}, "attest": {att: True}}] if att else []))


conf_rule("RHEL-09-653050", "admin_space_left_single", "admin_space_left_action", ["single"], ["suspend", "halt"],
          att="rhel_09_653050_realtime_alerts",
          what="real-time alerts to the SA and ISSO are configured for 95 percent of audit storage", green="SINGLE")
conf_rule("RHEL-09-653060", "audit_name_format_set", "name_format", ["hostname", "fqd", "numeric"], ["none", "user"])
conf_rule("RHEL-09-653065", "audit_overflow_action_ok", "overflow_action", ["syslog", "single", "halt"], ["ignore", "suspend"],
          att="rhel_09_653065_audit_offload",
          what="the audit logs are off-loaded to a different system or media", green="SYSLOG")
conf_rule("RHEL-09-653075", "audit_local_events", "local_events", ["yes"], ["no"])
conf_rule("RHEL-09-653100", "audit_log_format_enriched", "log_format", ["enriched"], ["raw"], green="ENRICHED")
conf_rule("RHEL-09-653105", "audit_write_logs", "write_logs", ["yes"], ["no"])

R("audit_logging", "RHEL-09-653070", "audit_action_mail_acct_root", [("auditd_config", "action_mail_acct")],
  [['_str(["auditd_config", "action_mail_acct"]) == "root"']],
  {"auditd_config": {"action_mail_acct": "root"}},
  [{"auditd_config": {"action_mail_acct": "nobody"}}],
  "action_mail_acct in /etc/audit/auditd.conf must be root, or the SA must attest that the SA and ISSO are notified of an "
  "audit processing failure another way, e.g. another security account (input.attest.rhel_09_653070_failure_notification)",
  "Set action_mail_acct = root in /etc/audit/auditd.conf and restart auditd",
  comment="action_mail_acct as configured in /etc/audit/auditd.conf (null when missing or commented out)",
  attest_alts=[['_attested("rhel_09_653070_failure_notification")']],
  pass_cases=[{"auditd_config": {"action_mail_acct": "isso@example.mil"}, "attest": {"rhel_09_653070_failure_notification": True}}])

num_rule("audit_logging", "RHEL-09-653095", "audit_freq_ok", ["auditd_config", "freq"], 1, 100, 100, [0, 101, "fifty"],
         "freq in /etc/audit/auditd.conf must be between 1 and 100",
         "Set freq = 100 in /etc/audit/auditd.conf and restart auditd",
         "freq as configured in /etc/audit/auditd.conf (null when missing or commented out)",
         pass_cases=[{"auditd_config": {"freq": "50"}}, {"auditd_config": {"freq": 1}}])

R("audit_logging", "RHEL-09-653130", "audispd_plugins_installed", [("packages", "audispd-plugins")],
  [['input.packages["audispd-plugins"] == true']],
  {"packages": {"audispd-plugins": True}}, [{"packages": {"audispd-plugins": False}}],
  "the audispd-plugins package must be installed", "Install the package: dnf install audispd-plugins",
  comment="dnf list --installed audispd-plugins (input.packages[\"audispd-plugins\"])")

R("audit_logging", "RHEL-09-653125", "audit_root_mail_alias", [("postfix", "root_alias")],
  [['a := _str(["postfix", "root_alias"])', 'a != ""']],
  {"postfix": {"root_alias": "isso"}}, [{"postfix": {"root_alias": ""}}, {"postfix": {"root_alias": ["isso"]}}],
  "the Postfix alias maps must hold an alias for root (postmap -q root <alias_maps> returns one)",
  "Add a root alias (root: <ISSO account>) to the aliases map (/etc/aliases by default) and run newaliases",
  comment="output of postmap -q root <each map of postconf alias_maps>; an empty string when no alias is set")

# RHEL-09-653120: "If the command returns any outputs, and audit_backlog_limit is less than 8192, this is a finding":
# a boot entry without the argument is not returned by the grep and is not a finding under this rule.
helpers("audit_logging", r'''
# the audit_backlog_limit values on one boot entry's kernel argument string (grubby --info=ALL, args= line)
_backlog_values(args) := [m[1] | some m in regex.find_all_string_submatch_n(`(?:^|[\s"])audit_backlog_limit=([^\s"]*)`, args, -1)]

_backlog_ok(v) if {
	regex.match(`^[0-9]+$`, v)
	to_number(v) >= 8192
}''')

from rhel9_rules_part1 import ARGS_OK as _P1_ARGS_OK  # noqa: E402  one shared green value for input.grub.kernel_args

R("audit_logging", "RHEL-09-653120", "audit_backlog_limit_ok", [("grub", "kernel_args")],
  [["entries := input.grub.kernel_args", "is_array(entries)",
    "every e in entries {\n\tis_string(e)\n\tevery v in _backlog_values(e) {\n\t\t_backlog_ok(v)\n\t}\n}"]],
  {"grub": {"kernel_args": [_P1_ARGS_OK, _P1_ARGS_OK]}},  # same green value as the part 1 boot-argument rules
  [{"grub": {"kernel_args": ["ro audit=1 audit_backlog_limit=8192", "ro audit=1 audit_backlog_limit=4096"]}},
   {"grub": {"kernel_args": ["ro audit_backlog_limit=large"]}}, {"grub": {"kernel_args": "ro audit_backlog_limit=8192"}}],
  "every boot entry that sets audit_backlog_limit (grubby --info=ALL, args) must set it to 8192 or more",
  "Set the argument on every kernel: grubby --update-kernel=ALL --args=audit_backlog_limit=8192",
  comment="the args= value of every boot entry of grubby --info=ALL, one string per entry",
  pass_cases=[{"grub": {"kernel_args": ["ro audit=1 audit_backlog_limit=16384"]}}, {"grub": {"kernel_args": ["ro audit=1"]}}])

# ── file_permissions: audit logs and audit configuration files ──────────────────────────────────
R("file_permissions", "RHEL-09-653080", "audit_log_group_ok", [("file_permissions", "audit_log", "group")],
  [['_str(["file_permissions", "audit_log", "group"]) == "root"'],
   ['g := _str(["file_permissions", "audit_log", "group"])', 'g != ""', 'g == _str(["auditd_config", "log_group"])']],
  {"file_permissions": {"audit_log": {"group": "root"}}},
  [{"file_permissions": {"audit_log": {"group": "wheel"}}},
   {"file_permissions": {"audit_log": {"group": "wheel"}}, "auditd_config": {"log_group": "auditlog"}}],
  "the audit log (auditd.conf log_file) must be group-owned by root or by the log_group configured in /etc/audit/auditd.conf",
  "Set the group of the audit logs to the configured log_group: chgrp <group> /var/log/audit and its files",
  comment="group of the auditd.conf log_file (stat -c %G); input.auditd_config.log_group is read when the group is not root",
  pass_cases=[{"file_permissions": {"audit_log": {"group": "auditlog"}}, "auditd_config": {"log_group": "auditlog"}}])

R("file_permissions", "RHEL-09-653085", "audit_log_dir_owner_root", [("file_permissions", "audit_log_dir", "owner")],
  [['_str(["file_permissions", "audit_log_dir", "owner"]) == "root"']],
  {"file_permissions": {"audit_log_dir": {"owner": "root"}}}, [{"file_permissions": {"audit_log_dir": {"owner": "auditor"}}}],
  "the audit log directory (the directory of auditd.conf log_file) must be owned by root",
  "chown root /var/log/audit",
  comment="owner of the directory of the auditd.conf log_file (stat -c %U /var/log/audit)")

for sid, name, key, sample, expect, fix, comment in (
        ("RHEL-09-653090", "audit_log_files_mode_ok", "audit_log_files", "/var/log/audit/audit.log",
         "no file in the audit log directory may have a mode more permissive than 0600",
         "chmod 0600 each listed audit log file",
         "find <directory of auditd.conf log_file> -type f -exec stat -c '%a %n': [{path, mode}]"),
        ("RHEL-09-653110", "audit_config_files_mode_ok", "audit_config_files", "/etc/audit/auditd.conf",
         "/etc/audit/rules.d/*.rules, /etc/audit/audit.rules and /etc/audit/auditd.conf must have mode 0600 or less permissive",
         "chmod 0600 /etc/audit/rules.d/*.rules /etc/audit/audit.rules /etc/audit/auditd.conf",
         "stat -c '%a %n' of /etc/audit/rules.d/*.rules, /etc/audit/audit.rules and /etc/audit/auditd.conf: [{path, mode}]")):
    R("file_permissions", sid, name, [("file_permissions", key)],
      [[f"fs := input.file_permissions.{key}", "is_array(fs)", 'every f in fs {\n\tmode_within(f.mode, "0600")\n}']],
      {"file_permissions": {key: [{"path": sample, "mode": "600"}]}},
      [{"file_permissions": {key: [{"path": sample, "mode": "640"}]}}, {"file_permissions": {key: [{"path": sample}]}},
       {"file_permissions": {key: [{"path": sample, "mode": "600"}, {"path": sample + ".1", "mode": "0644"}]}}],
      expect, fix, comment=comment,
      pass_cases=[{"file_permissions": {key: [{"path": sample, "mode": "0400"}]}}, {"file_permissions": {key: []}}])

# ── audit_logging: loaded audit rules (auditctl -l, input.audit_rules) ──────────────────────────
# The shared green list is one list object held by every audit rule's green fixture (the fixtures must be
# identical to merge); the lines below are appended to it in place, so the earlier rules keep passing on it.
_GREEN_LISTS = []
for _spec in RULES.values():
    _l = _spec["green"].get("audit_rules") if isinstance(_spec.get("green"), dict) else None
    if isinstance(_l, list) and not any(_l is g for g in _GREEN_LISTS):
        _GREEN_LISTS.append(_l)
assert _GREEN_LISTS, "no shared audit green list in rhel9_rules"
GREEN = _GREEN_LISTS[0]
_NEW = []


def _add(*lines):
    _NEW.extend(lines)
    for g in _GREEN_LISTS:
        g.extend(l for l in lines if l not in g)


def cmd_line(path, key, arch=None, auid=True, perm="x", sc=" -S all"):
    return ("-a always,exit" + (f" -F arch={arch}" if arch else sc) + f" -F path={path} -F perm={perm}"
            + (" -F auid>=1000 -F auid!=-1" if auid else "") + f" -F key={key}")


def path_rule(sid, name, path, perms, lines, what):
    """a loaded rule on exactly `path` with at least `perms`; the check is a finding only when no rule is returned"""
    _add(*lines)
    q = ", ".join(f'"{c}"' for c in perms)

    # a patch replaces the whole list (object.union), so each one carries only the line under test
    bad = [{"audit_rules": []}, {"audit_rules": [f"-w {path} -p r -k k"]},
           {"audit_rules": [f"-a always,exit -F arch=b64 -F path={path} -F perm={perms} -F uid=0 -F key=k"]},
           {"audit_rules": [f"-a always,exit -S all -F path={path}.bak -F perm={perms} -F key=k"]}]
    ok = [{"audit_rules": [f"-w {path} -p {perms} -k k"]},
          {"audit_rules": [f"-a always,exit -F arch=b64 -F path={path} -F perm=rwxa -F auid>=1000 -F auid!=unset -F key=k"]}]
    R("audit_logging", sid, name, [("audit_rules",)],
      [["is_array(input.audit_rules)", f'_path_audited("{path}", [{q}])']],
      {"audit_rules": GREEN}, bad, f"a loaded audit rule must audit {what} of {path}",
      f"Add the rule to a file in /etc/audit/rules.d/ and load it (augenrules --load): {lines[-1]}",
      comment=f"a loaded rule (auditctl -l) on exactly {path}: -w {path} or -F path={path}", pass_cases=ok)


for sid, name, path, key in (
        ("RHEL-09-654030", "audit_umount_cmd", "/usr/bin/umount", "privileged-mount"),
        ("RHEL-09-654035", "audit_chacl", "/usr/bin/chacl", "perm_mod"),
        ("RHEL-09-654040", "audit_setfacl", "/usr/bin/setfacl", "perm_mod"),
        ("RHEL-09-654045", "audit_chcon", "/usr/bin/chcon", "perm_mod"),
        ("RHEL-09-654050", "audit_semanage", "/usr/sbin/semanage", "privileged-unix-update"),
        ("RHEL-09-654055", "audit_setfiles", "/usr/sbin/setfiles", "privileged-unix-update"),
        ("RHEL-09-654060", "audit_setsebool", "/usr/sbin/setsebool", "privileged"),
        ("RHEL-09-654085", "audit_chage", "/usr/bin/chage", "privileged-chage"),
        ("RHEL-09-654090", "audit_chsh", "/usr/bin/chsh", "priv_cmd"),
        ("RHEL-09-654095", "audit_crontab", "/usr/bin/crontab", "privileged-crontab"),
        ("RHEL-09-654105", "audit_kmod", "/usr/bin/kmod", "modules"),
        ("RHEL-09-654110", "audit_newgrp", "/usr/bin/newgrp", "priv_cmd"),
        ("RHEL-09-654115", "audit_pam_timestamp_check", "/usr/sbin/pam_timestamp_check", "privileged-pam_timestamp_check"),
        ("RHEL-09-654125", "audit_postdrop", "/usr/sbin/postdrop", "privileged-unix-update"),
        ("RHEL-09-654130", "audit_postqueue", "/usr/sbin/postqueue", "privileged-unix-update"),
        ("RHEL-09-654135", "audit_ssh_agent", "/usr/bin/ssh-agent", "privileged-ssh"),
        ("RHEL-09-654140", "audit_ssh_keysign", "/usr/libexec/openssh/ssh-keysign", "privileged-ssh"),
        ("RHEL-09-654145", "audit_su", "/usr/bin/su", "privileged-priv_change"),
        ("RHEL-09-654155", "audit_sudoedit", "/usr/bin/sudoedit", "priv_cmd"),
        ("RHEL-09-654160", "audit_unix_chkpwd", "/usr/sbin/unix_chkpwd", "privileged-unix-update"),
        ("RHEL-09-654165", "audit_unix_update", "/usr/sbin/unix_update", "privileged-unix-update"),
        ("RHEL-09-654170", "audit_userhelper", "/usr/sbin/userhelper", "privileged-unix-update"),
        ("RHEL-09-654175", "audit_usermod", "/usr/sbin/usermod", "privileged-usermod"),
        ("RHEL-09-654176", "audit_useradd", "/usr/sbin/useradd", "privileged-useradd"),
        ("RHEL-09-654180", "audit_mount_cmd", "/usr/bin/mount", "privileged-mount"),
        ("RHEL-09-654185", "audit_init", "/usr/sbin/init", "privileged-init"),
        ("RHEL-09-654190", "audit_poweroff", "/usr/sbin/poweroff", "privileged-poweroff"),
        ("RHEL-09-654195", "audit_reboot", "/usr/sbin/reboot", "privileged-reboot")):
    path_rule(sid, name, path, "x", [cmd_line(path, key)], "execution (perm x)")

# the check examples for gpasswd and passwd are per-arch rules without an auid filter
path_rule("RHEL-09-654100", "audit_gpasswd", "/usr/bin/gpasswd", "x",
          [f"-a always,exit -F arch={a} -S execve -F path=/usr/bin/gpasswd -F perm=x -F key=identity" for a in ("b32", "b64")],
          "execution (perm x)")
path_rule("RHEL-09-654120", "audit_passwd_cmd", "/usr/bin/passwd", "x",
          [cmd_line("/usr/bin/passwd", "identity", arch=a, auid=False) for a in ("b32", "b64")], "execution (perm x)")

for sid, name, path, auid, key in (
        ("RHEL-09-654225", "audit_group_file", "/etc/group", False, "identity"),
        ("RHEL-09-654230", "audit_gshadow_file", "/etc/gshadow", False, "identity"),
        ("RHEL-09-654235", "audit_opasswd_file", "/etc/security/opasswd", False, "identity"),
        ("RHEL-09-654245", "audit_shadow_file", "/etc/shadow", False, "identity"),
        ("RHEL-09-654250", "audit_faillock_file", "/var/log/faillock", True, "logins"),
        ("RHEL-09-654255", "audit_lastlog_file", "/var/log/lastlog", True, "logins")):
    path_rule(sid, name, path, "wa", [cmd_line(path, key, arch=a, auid=auid, perm="wa") for a in ("b32", "b64")],
              "write and attribute change (perm wa)")

# RHEL-09-654220: the watch is on a directory; auditctl -l prints it as -w /etc/sudoers.d[/], -F path= (the check's
# example) or -F dir= depending on the audit version, and the check's grep accepts any of them
helpers("audit_logging", r'''
# an always,exit rule on directory `dir` (-F dir=<dir>, with or without the trailing slash) with at least the
# permission letters in `perms` and no narrowing field
_dir_audited(dir, perms) if {
	some line in _audit_lines
	toks := _tokens(line)
	_exit_rule(toks)
	fs := _fields(toks)
	some d in fs
	startswith(d, "dir=")
	trim_suffix(substring(d, 4, -1), "/") == dir
	some f in fs
	startswith(f, "perm=")
	p := substring(f, 5, -1)
	every c in perms {
		contains(p, c)
	}
	every g in fs {
		_dir_field_ok(g)
	}
}

_dir_field_ok(f) if startswith(f, "dir=")

_dir_field_ok(f) if _path_field_ok(f, "")''')

_SUDOERS_D = [f"-a always,exit -F arch={a} -F path=/etc/sudoers.d -F perm=wa -F key=identity" for a in ("b32", "b64")]
_add(*_SUDOERS_D)
R("audit_logging", "RHEL-09-654220", "audit_sudoers_d", [("audit_rules",)],
  [["is_array(input.audit_rules)", '_path_audited("/etc/sudoers.d", ["w", "a"])'],
   ["is_array(input.audit_rules)", '_path_audited("/etc/sudoers.d/", ["w", "a"])'],
   ["is_array(input.audit_rules)", '_dir_audited("/etc/sudoers.d", ["w", "a"])']],
  {"audit_rules": GREEN},
  [{"audit_rules": []}, {"audit_rules": ["-w /etc/sudoers -p wa -k identity"]},
   {"audit_rules": ["-w /etc/sudoers.d/ -p r -k identity"]},
   {"audit_rules": ["-a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=wa -F uid=0 -F key=identity"]},
   {"audit_rules": ["-a always,exit -F arch=b64 -F dir=/etc/sudoers.d.bak -F perm=wa -F key=identity"]}],
  "a loaded audit rule must watch /etc/sudoers.d for write and attribute change (perm wa)",
  "Add the rule to a file in /etc/audit/rules.d/ and load it (augenrules --load): -w /etc/sudoers.d/ -p wa -k identity",
  comment="a loaded rule (auditctl -l) on /etc/sudoers.d: -w, -F path= or -F dir=",
  pass_cases=[{"audit_rules": ["-w /etc/sudoers.d/ -p wa -k identity"]}, {"audit_rules": ["-w /etc/sudoers.d -p wa -k identity"]},
              {"audit_rules": ["-a always,exit -F arch=b64 -F dir=/etc/sudoers.d/ -F perm=wa -F key=identity"]},
              {"audit_rules": ["-a always,exit -F arch=b64 -F dir=/etc/sudoers.d -F perm=rwa -F auid>=1000 -F auid!=unset -F key=identity"]}])


# ── audit_logging: system calls ─────────────────────────────────────────────────────────────────
def sc(arch, calls, fields):
    return f"-a always,exit -F arch={arch} -S {','.join(calls)} " + " ".join(f"-F {f}" for f in fields) + " -F key=k"


_AUID_F = ["auid>=1000", "auid!=-1"]


def _req(req):
    return "[" + ", ".join(rego_set(g) for g in req) + "]"


_RENAME = ["rename", "unlink", "rmdir", "renameat", "unlinkat"]
_add(*[sc(a, _RENAME, _AUID_F) for a in ("b32", "b64")])
R("audit_logging", "RHEL-09-654065", "audit_delete_syscalls", [("audit_rules",)],
  [["is_array(input.audit_rules)"] + [f'_syscalls_audited("{a}", {rego_set(_RENAME)}, {_req(AUID)})' for a in ("b32", "b64")]],
  {"audit_rules": GREEN},
  [{"audit_rules": [sc("b64", _RENAME, _AUID_F)]}, {"audit_rules": [sc(a, _RENAME[:-1], _AUID_F) for a in ("b32", "b64")]},
   {"audit_rules": [sc("b32", _RENAME, _AUID_F), sc("b64", _RENAME, _AUID_F + ["uid=1000"])]},
   {"audit_rules": [sc("b32", _RENAME, _AUID_F), sc("b64", _RENAME, [])]}],
  "rename, unlink, rmdir, renameat and unlinkat must be audited for both b32 and b64",
  "Add the rules to a file in /etc/audit/rules.d/ and load them (augenrules --load): " + sc("b64", _RENAME, _AUID_F),
  comment="always,exit rules for rename, unlink, rmdir, renameat and unlinkat, both arches (auditctl -l)",
  pass_cases=[{"audit_rules": [sc(a, _RENAME[:2], ["auid>=1000", "auid!=unset"]) for a in ("b32", "b64")]
               + [sc(a, _RENAME[2:], _AUID_F) for a in ("b32", "b64")]}])

_add(*[sc(a, ["delete_module"], _AUID_F) for a in ("b32", "b64")])
R("audit_logging", "RHEL-09-654075", "audit_delete_module", [("audit_rules",)],
  [["is_array(input.audit_rules)"] + [f'_syscalls_audited("{a}", {{"delete_module"}}, {_req(AUID)})' for a in ("b32", "b64")]],
  {"audit_rules": GREEN},
  [{"audit_rules": [sc("b64", ["delete_module"], _AUID_F)]}, {"audit_rules": [sc("b32", ["delete_module"], _AUID_F)]},
   {"audit_rules": [sc("b32", ["delete_module"], _AUID_F), sc("b64", ["delete_module"], _AUID_F + ["exe=/usr/bin/true"])]},
   {"audit_rules": [sc("b32", ["delete_module"], _AUID_F), sc("b64", ["init_module"], _AUID_F)]}],
  "delete_module must be audited for both b32 and b64",
  "Add the rules to a file in /etc/audit/rules.d/ and load them (augenrules --load): " + sc("b64", ["delete_module"], _AUID_F),
  comment="always,exit rules for delete_module, both arches (auditctl -l)",
  pass_cases=[{"audit_rules": [sc(a, ["init_module", "delete_module"], ["auid>=1000", "auid!=4294967295"]) for a in ("b32", "b64")]}])

# RHEL-09-654097: the four expected lines (execve by crond_t as euid 0, and by a logged-in user), both arches
_CRON = [sc(a, ["execve"], f) for f in (["subj_type=crond_t", "euid=0"], ["subj_type=crond_t", "auid>=1000", "auid!=unset"])
         for a in ("b64", "b32")]
_add(*_CRON)
_CRON_REQS = ([["subj_type=crond_t"], ["euid=0"]], [["subj_type=crond_t"]] + AUID)
R("audit_logging", "RHEL-09-654097", "audit_cron_exec", [("audit_rules",)],
  [["is_array(input.audit_rules)"] + [f'_syscalls_audited("{a}", {{"execve"}}, {_req(r)})' for r in _CRON_REQS for a in ("b32", "b64")]],
  {"audit_rules": GREEN},
  [{"audit_rules": _CRON[:3]}, {"audit_rules": _CRON[:2]}, {"audit_rules": _CRON[2:]},
   {"audit_rules": _CRON[:3] + [_CRON[3].replace("subj_type=crond_t", "subj_type=unconfined_t")]},
   {"audit_rules": _CRON[1:] + [_CRON[0].replace(" -F euid=0", " -F euid=0 -F uid=0")]}],
  "execve by subj_type=crond_t must be audited for b32 and b64, once with -F euid=0 and once with -F auid>=1000 -F auid!=unset "
  "(all four rules)",
  "Add the four rules to a file in /etc/audit/rules.d/ and load them (augenrules --load): "
  "-a always,exit -F arch=b64 -S execve -F subj_type=crond_t -F euid=0 -k cron_exec (and b32; and both with "
  "-F auid>=1000 -F auid!=unset in place of -F euid=0)",
  comment="execve rules on subj_type=crond_t (auditctl -l): euid=0 and auid>=1000, both arches",
  pass_cases=[{"audit_rules": [l.replace("-F key=k", "-k cron_exec").replace("auid!=unset", "auid!=-1") for l in _CRON]}])

# RHEL-09-654205: the check greps the b32 rules only (umount is not a 64-bit system call)
_add(sc("b32", ["umount"], _AUID_F))
R("audit_logging", "RHEL-09-654205", "audit_umount_syscall", [("audit_rules",)],
  [["is_array(input.audit_rules)", f'_syscalls_audited("b32", {{"umount"}}, {_req(AUID)})']],
  {"audit_rules": GREEN},
  [{"audit_rules": []}, {"audit_rules": [sc("b32", ["umount2"], _AUID_F)]}, {"audit_rules": [sc("b64", ["umount"], _AUID_F)]},
   {"audit_rules": [sc("b32", ["umount"], _AUID_F + ["uid=1000"])]}, {"audit_rules": [sc("b32", ["umount"], [])]}],
  "the umount system call must be audited for b32",
  "Add the rule to a file in /etc/audit/rules.d/ and load it (augenrules --load): " + sc("b32", ["umount"], _AUID_F),
  comment="always,exit rule for the umount system call, arch b32 (auditctl -l)",
  pass_cases=[{"audit_rules": [sc("b32", ["umount", "umount2"], ["auid>=1000", "auid!=unset"])]}])

# RHEL-09-654210: "If no line is returned, this is a finding": one umount2 rule (either arch) is a returned line
_add(*[sc(a, ["umount2"], _AUID_F) for a in ("b64", "b32")])
R("audit_logging", "RHEL-09-654210", "audit_umount2_syscall", [("audit_rules",)],
  [["is_array(input.audit_rules)", f'_syscalls_audited("{a}", {{"umount2"}}, {_req(AUID)})'] for a in ("b64", "b32")],
  {"audit_rules": GREEN},
  [{"audit_rules": []}, {"audit_rules": [sc("b32", ["umount"], _AUID_F)]},
   {"audit_rules": [sc("b64", ["umount2"], _AUID_F + ["uid=1000"])]}, {"audit_rules": [sc("b64", ["umount2"], [])]}],
  "the umount2 system call must be audited (the check expects a b64 and a b32 rule and is a finding when no rule is returned)",
  "Add the rules to a file in /etc/audit/rules.d/ and load them (augenrules --load): " + sc("b64", ["umount2"], _AUID_F)
  + " and the same for arch=b32",
  comment="always,exit rule for the umount2 system call (auditctl -l)",
  pass_cases=[{"audit_rules": [sc("b64", ["umount2"], _AUID_F)]}, {"audit_rules": [sc("b32", ["umount2"], ["auid>=1000", "auid!=unset"])]}])

# ── audit_logging: the rule files on disk ───────────────────────────────────────────────────────
# RHEL-09-654200 greps /etc/audit/rules.d/* (not auditctl -l); 654265 / 654270 / 654275 grep /etc/audit/audit.rules.
helpers("audit_logging", r'''
# _path_audited over a given list of rule lines (the rule files on disk rather than the loaded rules)
_path_audited_in(lines, path, perms) if {
	some line in lines
	is_string(line)
	toks := _tokens(line)
	some i, t in toks
	t == "-w"
	toks[i + 1] == path
	some j, u in toks
	u == "-p"
	p := toks[j + 1]
	every c in perms {
		contains(p, c)
	}
}

_path_audited_in(lines, path, perms) if {
	some line in lines
	is_string(line)
	toks := _tokens(line)
	_exit_rule(toks)
	fs := _fields(toks)
	concat("=", ["path", path]) in fs
	some f in fs
	startswith(f, "perm=")
	p := substring(f, 5, -1)
	every c in perms {
		contains(p, c)
	}
	every g in fs {
		_path_field_ok(g, path)
	}
}

# the uncommented, non-blank lines of /etc/audit/audit.rules, each as its tokens
_rules_file_toks := [toks |
	some l in input.audit_rules_file
	is_string(l)
	toks := _tokens(replace(l, "\t", " "))
	count(toks) > 0
	not startswith(toks[0], "#")
]''')

_SHUT = "-a always,exit -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=unset -k privileged-shutdown"
R("audit_logging", "RHEL-09-654200", "audit_shutdown", [("audit_rules_d",)],
  [["is_array(input.audit_rules_d)", '_path_audited_in(input.audit_rules_d, "/usr/sbin/shutdown", ["x"])']],
  {"audit_rules_d": [_SHUT]},
  [{"audit_rules_d": []}, {"audit_rules_d": ["-w /usr/sbin/shutdown -p r -k k"]},
   {"audit_rules_d": [_SHUT.replace("/usr/sbin/shutdown", "/usr/sbin/reboot")]},
   {"audit_rules_d": [_SHUT.replace(" -F perm=x", " -F perm=x -F uid=0")]}],
  "a rule in /etc/audit/rules.d/ must audit execution (perm x) of /usr/sbin/shutdown",
  "Add the rule to a file in /etc/audit/rules.d/ and load it (augenrules --load): " + _SHUT,
  comment="the uncommented lines of /etc/audit/rules.d/* (cat /etc/audit/rules.d/*), one string per line",
  pass_cases=[{"audit_rules_d": ["-a always,exit -S all -F path=/usr/sbin/shutdown -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-shutdown"]},
              {"audit_rules_d": ["-w /usr/sbin/shutdown -p x -k privileged-shutdown"]}])

_RULES_FILE = ["-D", "-b 8192", "-f 2", "--loginuid-immutable", "-e 2"]
R("audit_logging", "RHEL-09-654265", "audit_failure_mode_panic", [("audit_rules_file",)],
  [["is_array(input.audit_rules_file)", 'fs := [t | some t in _rules_file_toks; t[0] == "-f"]', "count(fs) > 0",
    'every t in fs {\n\tt == ["-f", "2"]\n}']],
  {"audit_rules_file": _RULES_FILE},
  [{"audit_rules_file": ["-D", "-f 1", "--loginuid-immutable", "-e 2"]}, {"audit_rules_file": ["-D", "--loginuid-immutable", "-e 2"]},
   {"audit_rules_file": ["-D", "-f 2", "-f 1", "--loginuid-immutable", "-e 2"]},
   {"audit_rules_file": ["-D", "#-f 2", "--loginuid-immutable", "-e 2"]}],
  "/etc/audit/audit.rules must set -f 2, or availability must be documented as an overriding concern "
  "(input.attest.rhel_09_654265_availability_overriding)",
  "Add -f 2 to a file in /etc/audit/rules.d/ and regenerate the rules (augenrules --load)",
  comment="the uncommented lines of /etc/audit/audit.rules (input.audit_rules_file): the -f lines",
  attest_alts=[['_attested("rhel_09_654265_availability_overriding")']],
  pass_cases=[{"audit_rules_file": ["-D", "-f 1", "--loginuid-immutable", "-e 2"], "attest": {"rhel_09_654265_availability_overriding": True}}])

R("audit_logging", "RHEL-09-654270", "audit_loginuid_immutable", [("audit_rules_file",)],
  [["is_array(input.audit_rules_file)", "some t in _rules_file_toks", 't == ["--loginuid-immutable"]']],
  {"audit_rules_file": _RULES_FILE},
  [{"audit_rules_file": ["-D", "-b 8192", "-f 2", "-e 2"]}, {"audit_rules_file": ["-D", "-f 2", "# --loginuid-immutable", "-e 2"]}],
  "/etc/audit/audit.rules must contain --loginuid-immutable (uncommented)",
  "Add --loginuid-immutable to a file in /etc/audit/rules.d/ and regenerate the rules (augenrules --load)",
  comment="the uncommented lines of /etc/audit/audit.rules (input.audit_rules_file): --loginuid-immutable")

R("audit_logging", "RHEL-09-654275", "audit_rules_immutable", [("audit_rules_file",)],
  [["is_array(input.audit_rules_file)", "n := count(_rules_file_toks)", "n > 0", '_rules_file_toks[n - 1] == ["-e", "2"]']],
  {"audit_rules_file": _RULES_FILE},
  [{"audit_rules_file": ["-D", "-f 2", "--loginuid-immutable", "-e 1"]}, {"audit_rules_file": ["-D", "-e 2", "-f 2", "--loginuid-immutable"]},
   {"audit_rules_file": []}],
  "the last uncommented line of /etc/audit/audit.rules must be -e 2",
  "Add -e 2 as the last line of the last file in /etc/audit/rules.d/ and regenerate the rules (augenrules --load)",
  comment="the uncommented lines of /etc/audit/audit.rules (input.audit_rules_file): the last one",
  pass_cases=[{"audit_rules_file": ["-D", "-f 2", "--loginuid-immutable", "-e   2", "# end"]}])

# ── account_auth / pki_crypto ───────────────────────────────────────────────────────────────────
# RHEL-09-671015: every interactive account's hash must begin with $6$; "!" and "*" hashes are not evaluated
# (a locked hash "!$6$..." starts with "!" and is skipped the same way)
R("account_auth", "RHEL-09-671015", "shadow_hashes_sha512", [("interactive_shadow_hashes",)],
  [["hs := input.interactive_shadow_hashes", "is_array(hs)",
    'every h in hs {\n\tis_string(h.hash)\n\t_shadow_hash_ok(h.hash)\n}']],
  {"interactive_shadow_hashes": [{"name": "nsauser", "hash": "$6$"}, {"name": "svcacct", "hash": "!"}]},
  [{"interactive_shadow_hashes": [{"name": "nsauser", "hash": "$y$"}]}, {"interactive_shadow_hashes": [{"name": "nsauser", "hash": "$1$"}]},
   {"interactive_shadow_hashes": [{"name": "nsauser"}]}, {"interactive_shadow_hashes": [{"name": "nsauser", "hash": ""}]}],
  "every interactive user's /etc/shadow password hash must begin with $6$ (hashes starting with ! or * are not evaluated)",
  "Lock each listed account until its password is regenerated with SHA-512: passwd -l <username>",
  comment="for each interactive user, the /etc/shadow password field cut to its scheme prefix (\"$6$\", \"$y$\", \"!\", \"*\"; "
          "the hash itself is not collected): [{name, hash}]",
  pass_cases=[{"interactive_shadow_hashes": []}, {"interactive_shadow_hashes": [{"name": "a", "hash": "*"}, {"name": "b", "hash": "!!"}]}])

helpers("account_auth", r'''
# an /etc/shadow password field the RHEL-09-671015 check accepts: SHA-512, or an inactive account (! or *)
_shadow_hash_ok(h) if startswith(h, "$6$")

_shadow_hash_ok(h) if startswith(h, "!")

_shadow_hash_ok(h) if startswith(h, "*")''')

R("account_auth", "RHEL-09-671025", "pam_unix_sha512_password_auth", [("pam", "password_auth", "pam_unix_password_lines")],
  [["ls := input.pam.password_auth.pam_unix_password_lines", "is_array(ls)", "some l in ls", "is_string(l)",
    r"regex.match(`^password.*pam_unix\.so.*sha512`, l)"]],
  {"pam": {"password_auth": {"pam_unix_password_lines": ["password    sufficient    pam_unix.so sha512 shadow use_authtok"]}}},
  [{"pam": {"password_auth": {"pam_unix_password_lines": ["password    sufficient    pam_unix.so yescrypt shadow use_authtok"]}}},
   {"pam": {"password_auth": {"pam_unix_password_lines": []}}},
   {"pam": {"password_auth": {"pam_unix_password_lines": ["#password sufficient pam_unix.so sha512"]}}}],
  "a password line for pam_unix.so in /etc/pam.d/password-auth must carry sha512, or the SA must demonstrate that the "
  "configuration is in a PAM file included or substacked from system-auth (input.attest.rhel_09_671025_included_pam_file)",
  "Add sha512 to the pam_unix.so password line of /etc/pam.d/password-auth: password sufficient pam_unix.so sha512",
  comment="the lines of /etc/pam.d/password-auth that match ^password.*pam_unix.so (grep '^password.*pam_unix.so')",
  attest_alts=[['_attested("rhel_09_671025_included_pam_file")']],
  pass_cases=[{"pam": {"password_auth": {"pam_unix_password_lines": []}}, "attest": {"rhel_09_671025_included_pam_file": True}}])

for sid, name, pkg, key, rx, good, bad_lines, what, fix in (
        ("RHEL-09-671020", "ipsec_uses_crypto_policy", "libreswan", "ipsec",
         r"^\s*include\s+/etc/crypto-policies/back-ends/libreswan\.config\s*$",
         "include /etc/crypto-policies/back-ends/libreswan.config",
         ["#include /etc/crypto-policies/back-ends/libreswan.config", "include /etc/ipsec.d/*.conf"],
         "/etc/ipsec.conf or /etc/ipsec.d/*.conf must contain include /etc/crypto-policies/back-ends/libreswan.config",
         "Add to /etc/ipsec.conf: include /etc/crypto-policies/back-ends/libreswan.config"),
        ("RHEL-09-672050", "bind_uses_crypto_policy", "bind", "named",
         r"^\s*include\s+\"/etc/crypto-policies/back-ends/bind\.config\"\s*;",
         'include "/etc/crypto-policies/back-ends/bind.config";',
         ['//include "/etc/crypto-policies/back-ends/bind.config";', 'include "/etc/named.rfc1912.zones";'],
         '/etc/named.conf must contain include "/etc/crypto-policies/back-ends/bind.config"; (uncommented)',
         'Add to the options section of /etc/named.conf: include "/etc/crypto-policies/back-ends/bind.config";')):
    R("pki_crypto", sid, name, [("packages", pkg), (key, "include_lines")],
      [[f"input.packages.{pkg} == true", f"ls := input.{key}.include_lines", "is_array(ls)", "some l in ls", "is_string(l)",
        f"regex.match(`{rx}`, l)"]],
      {"packages": {pkg: True}, key: {"include_lines": [good]}},
      [{key: {"include_lines": [b]}} for b in bad_lines] + [{key: {"include_lines": []}}],
      what + f" when the {pkg} package is installed", fix,
      comment=f"input.packages.{pkg}; the lines of " + ("/etc/ipsec.conf and /etc/ipsec.d/*.conf" if key == "ipsec" else "/etc/named.conf")
              + " that contain include (grep include), with the file name prefix removed",
      na=[[f"input.packages.{pkg} == false"]], na_expect=f"the {pkg} package is not installed",
      na_cases=[{"packages": {pkg: False}}, {"packages": {pkg: False}, key: {"include_lines": None}}])
