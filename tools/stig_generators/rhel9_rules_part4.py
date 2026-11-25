"""Reviewed logic table for gen_rhel9.py, part 4 (DISA STIG for RHEL 9, V2R10): 69 rules written against the
full V2R10 check text (RHEL-09-4110xx/4120xx accounts and sessions, 431/432/433 SELinux, sudo, fapolicyd,
611xxx PAM / pwquality / smart card, 631020, 651/652 AIDE and rsyslog, 653 auditd.conf).

Imported at the end of rhel9_rules.py; the specs land in rhel9_rules.RULES through R(). Same spec format.

Fact shapes this part introduces (collect the observed value; the policy holds the expected one):
  sudoers.lines       [{file, line}] every uncommented, non-blank line of /etc/sudoers and /etc/sudoers.d/*
  pam_d.<file>        [line, ...] the uncommented, non-blank lines of /etc/pam.d/<file>, in file order
  rsyslog.config_lines [line, ...] the uncommented lines of /etc/rsyslog.conf and /etc/rsyslog.d/*, a
                      multi-line RainerScript statement (module(...), action(...), input(...)) joined into one line
Flag options (faillock.conf even_deny_root / audit, pwquality.conf enforce_for_root) are booleans: true when
an uncommented line sets the option, false when the file was read and it is absent or commented out.
"""
from rhel9_rules import R, helpers, num_rule, nest

# helper names carry a _p4_ prefix so they cannot collide with another part's helpers in the same module


def pkg_rule(sec, sid, name, pkg, **kw):
    ref = f"input.packages.{pkg}" if pkg.replace("_", "").isalnum() else f'input.packages["{pkg}"]'
    R(sec, sid, name, [("packages", pkg)], [[f"{ref} == true"]],
      {"packages": {pkg: True}}, [{"packages": {pkg: False}}],
      f"the {pkg} package must be installed", f"Install the package: dnf install {pkg}",
      comment=f"{pkg} package installed (dnf list --installed {pkg})", **kw)


def flag_rule(sec, sid, name, path, f, what):
    p = "input." + ".".join(path)
    R(sec, sid, name, [tuple(path)], [[f"{p} == true"]], nest(path, True), [nest(path, False), nest(path, "false")],
      f"{f} must carry an uncommented {path[-1]} line ({what})", f"Add the line {path[-1]} to {f}",
      comment=f"{path[-1]} option present and uncommented in {f} (boolean)")


SUDOERS_HELPER = r'''
# input.sudoers.lines: [{file, line}], the uncommented lines of /etc/sudoers and /etc/sudoers.d/*
_p4_sudoers := [e | some e in input.sudoers.lines; is_string(e.line); is_string(e.file)]

_p4_sudoers_collected if is_array(input.sudoers.lines)

# the sudoers entries whose line matches a (case-insensitive) pattern, as the check's grep -i returns them
_p4_sudoers_matching(pattern) := [e | some e in _p4_sudoers; regex.match(pattern, e.line)]'''

PAM_HELPER = r'''
# input.pam_d[<file>]: the uncommented lines of /etc/pam.d/<file>, in file order
_p4_pam(file) := [l | some l in input.pam_d[file]; is_string(l)] if is_array(input.pam_d[file])

# a pam_faillock.so preauth line stands before every pam_unix.so line of the file
_p4_faillock_preauth_first(file) if {
	lines := _p4_pam(file)
	some i, l in lines
	contains(l, "pam_faillock.so")
	regex.match(`(^|\s)preauth(\s|$)`, l)
	every j, u in lines {
		_p4_not_unix_before(u, j, i)
	}
}

_p4_not_unix_before(u, _, _) if not contains(u, "pam_unix.so")

_p4_not_unix_before(u, j, i) if {
	contains(u, "pam_unix.so")
	j > i
}

# the rounds= values on the lines of a PAM file
_p4_rounds(file) := [v | some l in _p4_pam(file); some m in regex.find_all_string_submatch_n(`(^|\s)rounds=(\S*)`, l, -1); v := m[2]]

_p4_rounds_ok(file) if {
	some l in _p4_pam(file)
	regex.match(`^\s*password\s.*pam_unix\.so\s(.*\s)?rounds=[0-9]+(\s|$)`, l)
	every v in _p4_rounds(file) {
		regex.match(`^[0-9]+$`, v)
		to_number(v) >= 100000
	}
}'''

helpers("account_auth", SUDOERS_HELPER)
helpers("account_auth", PAM_HELPER)
helpers("configuration_management", SUDOERS_HELPER)
helpers("configuration_management", PAM_HELPER)

SUDOERS_GREEN = [{"file": "/etc/sudoers", "line": "Defaults timestamp_timeout=0"},
                 {"file": "/etc/sudoers", "line": "Defaults !targetpw"},
                 {"file": "/etc/sudoers", "line": "Defaults !rootpw"},
                 {"file": "/etc/sudoers", "line": "Defaults !runaspw"},
                 {"file": "/etc/sudoers", "line": "root ALL=(ALL) ALL"},
                 {"file": "/etc/sudoers.d/admins", "line": "%wheel ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL"}]
SUDO = {"sudoers": {"lines": SUDOERS_GREEN}}


def sudo_with(*extra, drop=()):
    return {"sudoers": {"lines": [e for e in SUDOERS_GREEN if not any(d in e["line"] for d in drop)]
                        + [{"file": f, "line": l} for f, l in extra]}}


PAM_AUTH_GREEN = ["auth required pam_env.so",
                  "auth required pam_faillock.so preauth",
                  "auth sufficient pam_unix.so",
                  "auth required pam_faillock.so authfail",
                  "auth required pam_deny.so",
                  "account required pam_faillock.so",
                  "account required pam_unix.so",
                  "password required pam_pwquality.so",
                  "password sufficient pam_unix.so sha512 shadow use_authtok rounds=100000",
                  "session required pam_unix.so"]
PAM_GREEN = {"pam_d": {"system-auth": PAM_AUTH_GREEN, "password-auth": PAM_AUTH_GREEN,
                       "su": ["auth sufficient pam_rootok.so", "auth required pam_wheel.so use_uid", "auth substack system-auth"],
                       "sudo": ["auth include system-auth", "account include system-auth", "password include system-auth",
                                "session include system-auth"]}}


def pam_with(file, lines):
    return {"pam_d": {file: lines}}


def pam_swap(old, new):
    """the green auth stack with one line replaced (new=None drops it)"""
    return [x for l in PAM_AUTH_GREEN for x in ([l] if l != old else ([new] if new else []))]


# ── account_auth: faillock, accounts, sessions ──────────────────────────────────────────────────
flag_rule("account_auth", "RHEL-09-411080", "faillock_even_deny_root", ["faillock_conf", "even_deny_root"],
          "/etc/security/faillock.conf", "the root account locks after failed logons")

R("account_auth", "RHEL-09-411090", "faillock_unlock_time_zero", [("faillock_conf", "unlock_time")],
  [['_num(["faillock_conf", "unlock_time"]) == 0']],
  {"faillock_conf": {"unlock_time": 0}}, [{"faillock_conf": {"unlock_time": 900}}, {"faillock_conf": {"unlock_time": "never"}}, {"faillock_conf": {"unlock_time": "0"}}],
  "unlock_time in /etc/security/faillock.conf must be 0 (locked until an administrator releases the account)",
  "Set unlock_time = 0 in /etc/security/faillock.conf",
  comment="unlock_time as configured in /etc/security/faillock.conf (null when missing or commented out)")

R("account_auth", "RHEL-09-411095", "no_unauthorized_accounts", [("local_interactive_users",)],
  [["us := input.local_interactive_users", "is_array(us)", "count(us) == 0"]],
  {"local_interactive_users": []}, [{"local_interactive_users": ["scsaustin", "djohnson"]}],
  "every local interactive user account in /etc/passwd must be on the list authorized by the SA or ISSO: the "
  "accounts found must be compared with that list and attested (input.attest.rhel_09_411095_accounts_authorized)",
  "Remove each unauthorized local interactive account: userdel <unauthorized_user>",
  comment="local interactive accounts in /etc/passwd (UID >= 1000, interactive shell); the comparison with the authorized list is an attestation",
  attest_alts=[['_attested("rhel_09_411095_accounts_authorized")']],
  pass_cases=[{"local_interactive_users": ["scsaustin"], "attest": {"rhel_09_411095_accounts_authorized": True}}])

R("account_auth", "RHEL-09-411100", "only_root_uid_zero", [("uid_zero_accounts",)],
  [["accts := input.uid_zero_accounts", "is_array(accts)", 'every a in accts {\n\ta == "root"\n}']],
  {"uid_zero_accounts": ["root"]}, [{"uid_zero_accounts": ["root", "toor"]}, {"uid_zero_accounts": ["admin"]}],
  "no account other than root may have UID 0 in /etc/passwd",
  "Change the UID of every account other than root that has UID 0 (usermod -u)",
  comment="account names printed by awk -F: '$3 == 0 {print $1}' /etc/passwd")

R("account_auth", "RHEL-09-411105", "faillock_dir_persistent", [("faillock_conf", "dir")],
  [['d := trim_right(_str(["faillock_conf", "dir"]), "/")', 'startswith(d, "/")',
    'not d in {"/var/run/faillock", "/run/faillock"}']],
  {"faillock_conf": {"dir": "/var/log/faillock"}},
  [{"faillock_conf": {"dir": "/var/run/faillock"}}, {"faillock_conf": {"dir": "/run/faillock/"}}, {"faillock_conf": {"dir": ""}}],
  "dir in /etc/security/faillock.conf must name a nondefault tally directory (not /var/run/faillock), e.g. /var/log/faillock",
  "Set dir = /var/log/faillock in /etc/security/faillock.conf",
  comment="dir as configured in /etc/security/faillock.conf (null when missing or commented out); the default /var/run/faillock does not persist")

R("account_auth", "RHEL-09-412035", "shell_tmout_set", [("profile_tmout",)],
  [["es := input.profile_tmout", "is_array(es)", "some e in es", 'startswith(e.file, "/etc/profile.d/")',
    "_p4_int_at_most(e.value, 600)"]],
  {"profile_tmout": [{"file": "/etc/profile.d/tmout.sh", "value": 600}]},
  [{"profile_tmout": []}, {"profile_tmout": [{"file": "/etc/profile.d/tmout.sh", "value": 900}]},
   {"profile_tmout": [{"file": "/etc/profile", "value": 600}]},
   ("invalid", {"profile_tmout": [{"file": "/etc/profile.d/tmout.sh", "value": "$IDLE"}]}, "profile_tmout[0].value is not a number (got string)"),
   ("invalid", {"profile_tmout": [{"file": "/etc/profile.d/tmout.sh", "value": "600"}]}, "profile_tmout[0].value is not a number (got string)"),
   ("invalid", {"profile_tmout": [{"file": "/etc/profile", "value": 900}, {"file": "/etc/profile.d/tmout.sh", "value": " 300 "}]},
    "profile_tmout[1].value is not a number (got string)"),
   ("invalid", {"profile_tmout": [{"file": "/etc/profile.d/tmout.sh", "value": 300.5}]}, "profile_tmout[0].value is not a number (got a fraction)")],
  "a script in /etc/profile.d/ must set TMOUT to 600 or less (uncommented)",
  "Add declare -xr TMOUT=600 to /etc/profile.d/tmout.sh",
  comment="uncommented TMOUT assignments in /etc/profile and /etc/profile.d/*.sh: [{file, value}] (value: the seconds as a "
          "JSON number; an assignment that is not a decimal integer, e.g. $IDLE, as the text written)",
  pass_cases=[{"profile_tmout": [{"file": "/etc/profile.d/tmout.sh", "value": 300}]},
              {"profile_tmout": [{"file": "/etc/profile", "value": 900}, {"file": "/etc/profile.d/tmout.sh", "value": 600}]},
              {"profile_tmout": [{"file": "/etc/profile", "value": "$IDLE"}, {"file": "/etc/profile.d/tmout.sh", "value": 600}]}],
  num_items=['[m | some i, e in input.profile_tmout; m := _not_a_number(sprintf("profile_tmout[%d].value", [i]), object.get(e, "value", null))]'])

R("account_auth", "RHEL-09-412040", "maxlogins_limited", [("limits_maxlogins",)],
  [["es := input.limits_maxlogins", "is_array(es)", "count(es) > 0",
    "every e in es {\n\t_p4_int_at_most(e.value, 10)\n}"]],
  {"limits_maxlogins": [{"file": "/etc/security/limits.conf", "domain": "*", "type": "hard", "value": 10}]},
  [{"limits_maxlogins": []},
   {"limits_maxlogins": [{"file": "/etc/security/limits.conf", "domain": "*", "type": "hard", "value": 11}]},
   {"limits_maxlogins": [{"file": "/etc/security/limits.conf", "domain": "*", "type": "hard", "value": 10},
                         {"file": "/etc/security/limits.d/ops.conf", "domain": "@ops", "type": "hard", "value": 50}]},
   ("invalid", {"limits_maxlogins": [{"file": "/etc/security/limits.conf", "domain": "*", "type": "hard", "value": "10"}]},
    "limits_maxlogins[0].value is not a number (got string)"),
   ("invalid", {"limits_maxlogins": [{"file": "/etc/security/limits.conf", "domain": "*", "type": "hard", "value": 10},
                                     {"file": "/etc/security/limits.d/ops.conf", "domain": "@ops", "type": "hard", "value": " 5 "}]},
    "limits_maxlogins[1].value is not a number (got string)"),
   ("invalid", {"limits_maxlogins": [{"file": "/etc/security/limits.conf", "domain": "*", "type": "hard", "value": "unlimited"}]},
    "limits_maxlogins[0].value is not a number (got string)"),
   ("invalid", {"limits_maxlogins": [{"file": "/etc/security/limits.conf", "domain": "*", "type": "hard", "value": 9.5}]},
    "limits_maxlogins[0].value is not a number (got a fraction)")],
  "every uncommented maxlogins item in /etc/security/limits.conf and limits.d/*.conf must be 10 or less (at least one item), "
  "or the value must be documented with the ISSO as an operational requirement (input.attest.rhel_09_412040_maxlogins_documented)",
  "Add * hard maxlogins 10 to /etc/security/limits.conf",
  comment="uncommented maxlogins items of /etc/security/limits.conf and limits.d/*.conf: [{file, domain, type, value}] "
          "(value: a JSON number; a value that is not a decimal integer as the text written)",
  attest_alts=[['_attested("rhel_09_412040_maxlogins_documented")']],
  pass_cases=[{"limits_maxlogins": [{"file": "/etc/security/limits.conf", "domain": "*", "type": "hard", "value": 5}]},
              {"limits_maxlogins": [{"file": "/etc/security/limits.conf", "domain": "*", "type": "hard", "value": 50}],
               "attest": {"rhel_09_412040_maxlogins_documented": True}}],
  num_items=['[m | some i, e in input.limits_maxlogins; m := _not_a_number(sprintf("limits_maxlogins[%d].value", [i]), object.get(e, "value", null))]'])
helpers("account_auth", r'''
# a non-negative JSON whole number no greater than max (a value written as something else, e.g. $IDLE or
# unlimited, arrives as that text and is not a number)
_p4_int_at_most(v, max) if {
	_whole_number(v)
	v >= 0
	v <= max
}

# the umask values of a shell start-up file: at least one uncommented umask command, every one 077
_p4_umask_077(key) if {
	vals := input.shell_umask[key]
	is_array(vals)
	count(vals) > 0
	every v in vals {
		v == "077"
	}
}''')

flag_rule("account_auth", "RHEL-09-412045", "faillock_audit", ["faillock_conf", "audit"],
          "/etc/security/faillock.conf", "the user name is logged on a failed logon")

num_rule("account_auth", "RHEL-09-412050", "login_fail_delay", ["login_defs", "FAIL_DELAY"], 4, None, 4, [3, 0, "four", "5"],
         "FAIL_DELAY in /etc/login.defs must be 4 or greater", "Set FAIL_DELAY 4 in /etc/login.defs",
         "FAIL_DELAY as configured in /etc/login.defs (null when missing or commented out)",
         pass_cases=[{"login_defs": {"FAIL_DELAY": 5}}])

for sid, name, key, f in (("RHEL-09-412055", "umask_bashrc", "etc_bashrc", "/etc/bashrc"),
                          ("RHEL-09-412060", "umask_cshrc", "etc_csh_cshrc", "/etc/csh.cshrc"),
                          ("RHEL-09-412070", "umask_profile", "etc_profile", "/etc/profile")):
    R("account_auth", sid, name, [("shell_umask", key)], [[f'_p4_umask_077("{key}")']],
      {"shell_umask": {key: ["077"]}},
      [{"shell_umask": {key: []}}, {"shell_umask": {key: ["022"]}}, {"shell_umask": {key: ["077", "002"]}},
       {"shell_umask": {key: ["000"]}}],
      f"every uncommented umask command in {f} must set 077 (at least one)", f"Set umask 077 in {f}",
      comment=f"the values of the uncommented umask commands in {f}, as written (e.g. [\"077\"]); empty when none")

R("account_auth", "RHEL-09-412065", "umask_login_defs", [("login_defs", "UMASK")],
  [['_str(["login_defs", "UMASK"]) == "077"']],
  {"login_defs": {"UMASK": "077"}}, [{"login_defs": {"UMASK": "022"}}, {"login_defs": {"UMASK": "000"}}],
  "UMASK in /etc/login.defs must be 077", "Set UMASK 077 in /etc/login.defs",
  comment="UMASK as configured in /etc/login.defs, a string so the leading zero survives (null when missing or commented out)")

R("account_auth", "RHEL-09-412080", "idle_sessions_terminated", [("logind_conf", "StopIdleSessionSec")],
  [['_str(["logind_conf", "StopIdleSessionSec"]) == "600"']],
  {"logind_conf": {"StopIdleSessionSec": "600"}},
  [{"logind_conf": {"StopIdleSessionSec": "infinity"}}, {"logind_conf": {"StopIdleSessionSec": "900"}}],
  "StopIdleSessionSec in the effective logind.conf (systemd-analyze cat-config systemd/logind.conf) must be 600",
  "Set StopIdleSessionSec=600 under [Login] in a file in /etc/systemd/logind.conf.d/ and restart systemd-logind",
  comment="effective (last uncommented) StopIdleSessionSec from systemd-analyze cat-config systemd/logind.conf; "
          "a cloud-hosted system with sshd ClientAliveInterval configured is Not Applicable",
  na=[['_attested("rhel_09_412080_cloud_hosted")', 'n := _num(["ssh_config", "ClientAliveInterval"])', "n >= 1", "n <= 600"]],
  na_expect="cloud-hosted system with sshd ClientAliveInterval configured (RHEL-09-255100)",
  na_cases=[{"logind_conf": {"StopIdleSessionSec": None}, "attest": {"rhel_09_412080_cloud_hosted": True},
             "ssh_config": {"ClientAliveInterval": 600}}],
  pass_cases=[{"logind_conf": {"StopIdleSessionSec": 600}}])


# ── account_auth: sudo and su ───────────────────────────────────────────────────────────────────
pkg_rule("account_auth", "RHEL-09-432010", "sudo_installed", "sudo")

R("account_auth", "RHEL-09-432015", "sudo_reauthentication", [("sudoers", "lines")],
  [["_p4_sudoers_collected", "es := _p4_sudoers_matching(`(?i)timestamp_timeout`)", "count(es) > 0",
    "count({e.file | some e in es}) == 1",
    "every e in es {\n\tregex.match(`^\\s*Defaults\\s+(.*,\\s*)?timestamp_timeout\\s*=\\s*0\\s*(,.*)?$`, e.line)\n}"]],
  SUDO,
  [sudo_with(drop=["timestamp_timeout"]),
   sudo_with(("/etc/sudoers", "Defaults timestamp_timeout=5"), drop=["timestamp_timeout"]),
   sudo_with(("/etc/sudoers", "Defaults timestamp_timeout=-1"), drop=["timestamp_timeout"]),
   sudo_with(("/etc/sudoers.d/extra", "Defaults timestamp_timeout=0")),
   sudo_with(("/etc/sudoers", "Defaults timestamp_timeout=15"))],
  "exactly one of /etc/sudoers and the /etc/sudoers.d/ files must set timestamp_timeout, and every such line must be "
  "Defaults timestamp_timeout=0",
  "Add Defaults timestamp_timeout=0 to /etc/sudoers or one file in /etc/sudoers.d/ and remove any other definition",
  comment="uncommented timestamp_timeout lines of /etc/sudoers and /etc/sudoers.d/* (input.sudoers.lines[{file, line}])",
  pass_cases=[sudo_with(("/etc/sudoers", "Defaults env_reset, timestamp_timeout = 0"), drop=["timestamp_timeout"])])

R("account_auth", "RHEL-09-432020", "sudo_invoking_user_password", [("sudoers", "lines")],
  [["_p4_sudoers_collected", "es := _p4_sudoers_matching(`(?i)!(rootpw|targetpw|runaspw)`)", "count(es) > 0",
    "count({e.file | some e in es}) == 1",
    'every opt in {"targetpw", "rootpw", "runaspw"} {\n\tsome e in es\n\tregex.match(sprintf(`^\\s*Defaults\\s+(.*,\\s*)?!%s\\s*(,.*)?$`, [opt]), e.line)\n}']],
  SUDO,
  [sudo_with(drop=["!targetpw"]), sudo_with(drop=["!rootpw"]), sudo_with(drop=["!runaspw"]),
   sudo_with(drop=["!targetpw", "!rootpw", "!runaspw"]),
   sudo_with(("/etc/sudoers.d/pw", "Defaults !runaspw"))],
  "Defaults !targetpw, Defaults !rootpw and Defaults !runaspw must all be defined, in a single file among /etc/sudoers and /etc/sudoers.d/*",
  "Add Defaults !targetpw, Defaults !rootpw and Defaults !runaspw to /etc/sudoers or a single file in /etc/sudoers.d/",
  comment="uncommented !rootpw / !targetpw / !runaspw lines of /etc/sudoers and /etc/sudoers.d/*",
  pass_cases=[sudo_with(("/etc/sudoers", "Defaults !targetpw, !rootpw, !runaspw"), drop=["!targetpw", "!rootpw", "!runaspw"])])

R("account_auth", "RHEL-09-432025", "sudo_no_authenticate_bypass", [("sudoers", "lines")],
  [["_p4_sudoers_collected", "count(_p4_sudoers_matching(`(?i)!authenticate`)) == 0"]],
  SUDO, [sudo_with(("/etc/sudoers.d/ops", "Defaults:ops !authenticate")), sudo_with(("/etc/sudoers", "Defaults !AUTHENTICATE"))],
  "no uncommented line of /etc/sudoers or /etc/sudoers.d/* may contain !authenticate",
  "Remove every occurrence of !authenticate from /etc/sudoers and the files in /etc/sudoers.d/",
  comment="uncommented lines of /etc/sudoers and /etc/sudoers.d/* containing !authenticate (case-insensitive)")

R("account_auth", "RHEL-09-432030", "sudo_not_open_to_all", [("sudoers", "lines")],
  [["_p4_sudoers_collected", r"count(_p4_sudoers_matching(`^\s*ALL\s+ALL\s*=\s*\(\s*ALL\s*(:\s*ALL\s*)?\)\s*ALL\s*$`)) == 0"]],
  SUDO, [sudo_with(("/etc/sudoers", "ALL     ALL=(ALL) ALL")), sudo_with(("/etc/sudoers.d/all", "ALL ALL=(ALL:ALL) ALL"))],
  "/etc/sudoers and /etc/sudoers.d/* must not carry ALL ALL=(ALL) ALL or ALL ALL=(ALL:ALL) ALL",
  "Remove the entries ALL ALL=(ALL) ALL and ALL ALL=(ALL:ALL) ALL from /etc/sudoers and /etc/sudoers.d/",
  comment="uncommented sudoers lines granting every user every command (ALL ALL=(ALL) ALL, ALL ALL=(ALL:ALL) ALL)",
  pass_cases=[sudo_with(("/etc/sudoers", "%wheel ALL=(ALL:ALL) ALL"))])

R("account_auth", "RHEL-09-432035", "su_restricted_to_wheel", [("pam_d", "su")],
  [['lines := _p4_pam("su")', "some l in lines", 'contains(l, "pam_wheel.so")']],
  PAM_GREEN, [pam_with("su", ["auth sufficient pam_rootok.so", "auth substack system-auth"]), pam_with("su", [])],
  "/etc/pam.d/su must carry an uncommented pam_wheel.so line (auth required pam_wheel.so use_uid)",
  "Uncomment auth required pam_wheel.so use_uid in /etc/pam.d/su",
  comment="uncommented lines of /etc/pam.d/su (input.pam_d.su) naming pam_wheel.so")

R("account_auth", "RHEL-09-611085", "sudo_requires_password", [("sudoers", "lines")],
  [["_p4_sudoers_collected", "count(_p4_sudoers_matching(`(?i)nopasswd`)) == 0"]],
  SUDO, [sudo_with(("/etc/sudoers.d/ops", "%ops ALL=(ALL) NOPASSWD: ALL")), sudo_with(("/etc/sudoers", "ansible ALL=(ALL) nopasswd: ALL"))],
  "no uncommented line of /etc/sudoers or /etc/sudoers.d/* may contain NOPASSWD, unless documented with the ISSO as an "
  "organizationally defined administrative group using MFA (input.attest.rhel_09_611085_nopasswd_mfa_documented)",
  "Remove every occurrence of NOPASSWD from /etc/sudoers and the files in /etc/sudoers.d/",
  comment="uncommented lines of /etc/sudoers and /etc/sudoers.d/* containing NOPASSWD (case-insensitive)",
  attest_alts=[['_attested("rhel_09_611085_nopasswd_mfa_documented")']],
  pass_cases=[dict(sudo_with(("/etc/sudoers.d/ops", "%ops ALL=(ALL) NOPASSWD: ALL")), attest={"rhel_09_611085_nopasswd_mfa_documented": True})])

R("account_auth", "RHEL-09-611145", "sudo_pam_no_succeed_if", [("pam_d", "sudo")],
  [['lines := _p4_pam("sudo")', 'count([l | some l in lines; contains(l, "pam_succeed_if")]) == 0']],
  PAM_GREEN, [pam_with("sudo", ["auth sufficient pam_succeed_if.so user ingroup wheel", "auth include system-auth"])],
  "/etc/pam.d/sudo must not contain pam_succeed_if",
  "Remove every pam_succeed_if line from /etc/pam.d/sudo",
  comment="uncommented lines of /etc/pam.d/sudo (input.pam_d.sudo) naming pam_succeed_if")


# ── account_auth: PAM stacks ────────────────────────────────────────────────────────────────────
INCLUDED = "the SA must demonstrate that the configuration is in a PAM file included or substacked from system-auth"
R("account_auth", "RHEL-09-611025", "pam_no_nullok", [("pam_d", "system-auth"), ("pam_d", "password-auth")],
  [['every f in {"system-auth", "password-auth"} {\n\tlines := _p4_pam(f)\n\tcount([l | some l in lines; contains(lower(l), "nullok")]) == 0\n}']],
  PAM_GREEN,
  [pam_with("system-auth", pam_swap("auth sufficient pam_unix.so", "auth sufficient pam_unix.so nullok")),
   pam_with("password-auth", pam_swap("auth sufficient pam_unix.so", "auth sufficient pam_unix.so try_first_pass NULLOK"))],
  f"/etc/pam.d/system-auth and /etc/pam.d/password-auth must not carry the nullok option, or {INCLUDED} (input.attest.rhel_09_611025_included_pam_config)",
  "Remove nullok: authselect enable-feature without-nullok (or edit /etc/pam.d/system-auth and password-auth)",
  comment="uncommented lines of /etc/pam.d/system-auth and /etc/pam.d/password-auth carrying nullok (case-insensitive)",
  attest_alts=[['_attested("rhel_09_611025_included_pam_config")']])

for sid, f in (("RHEL-09-611030", "system-auth"), ("RHEL-09-611035", "password-auth")):
    u = f.replace("-", "_")
    att = f"{sid.lower().replace('-', '_')}_included_pam_config"
    R("account_auth", sid, f"pam_faillock_{u}", [("pam_d", f)],
      [[f'_p4_faillock_preauth_first("{f}")']],
      PAM_GREEN,
      [pam_with(f, pam_swap("auth required pam_faillock.so preauth", None)),
       pam_with(f, ["auth sufficient pam_unix.so", "auth required pam_faillock.so preauth", "auth required pam_faillock.so authfail"]),
       pam_with(f, ["auth required pam_faillock.so authfail", "auth sufficient pam_unix.so", "account required pam_faillock.so"])],
      f"/etc/pam.d/{f} must carry pam_faillock.so with its preauth line before pam_unix.so, or {INCLUDED} (input.attest.{att})",
      f"Enable faillock: authselect enable-feature with-faillock (or add the pam_faillock.so preauth / authfail / account lines to /etc/pam.d/{f})",
      comment=f"uncommented lines of /etc/pam.d/{f} in file order (input.pam_d[\"{f}\"]): pam_faillock.so preauth before pam_unix.so",
      attest_alts=[[f'_attested("{att}")']],
      pass_cases=[dict(pam_with(f, pam_swap("auth required pam_faillock.so preauth", None)), attest={att: True})])

for sid, f in (("RHEL-09-611040", "password-auth"), ("RHEL-09-611045", "system-auth")):
    u = f.replace("-", "_")
    att = f"{sid.lower().replace('-', '_')}_included_pam_config"
    R("account_auth", sid, f"pam_pwquality_{u}", [("pam_d", f)],
      [[f'lines := _p4_pam("{f}")', "some l in lines", 'contains(l, "pam_pwquality.so")']],
      PAM_GREEN, [pam_with(f, pam_swap("password required pam_pwquality.so", None))],
      f"/etc/pam.d/{f} must carry an uncommented pam_pwquality.so line, or {INCLUDED} (input.attest.{att})",
      f"Add password required pam_pwquality.so to /etc/pam.d/{f}",
      comment=f"uncommented lines of /etc/pam.d/{f} naming pam_pwquality.so",
      attest_alts=[[f'_attested("{att}")']],
      pass_cases=[dict(pam_with(f, pam_swap("password required pam_pwquality.so", None)), attest={att: True})])

for sid, f in (("RHEL-09-611050", "password-auth"), ("RHEL-09-611055", "system-auth")):
    u = f.replace("-", "_")
    unix = "password sufficient pam_unix.so sha512 shadow use_authtok rounds=100000"
    R("account_auth", sid, f"pam_unix_rounds_{u}", [("pam_d", f)],
      [[f'_p4_rounds_ok("{f}")']],
      PAM_GREEN,
      [pam_with(f, pam_swap(unix, "password sufficient pam_unix.so sha512 shadow use_authtok")),
       pam_with(f, pam_swap(unix, "password sufficient pam_unix.so sha512 rounds=5000")),
       pam_with(f, pam_swap(unix, "password sufficient pam_unix.so sha512 rounds=")),
       pam_with(f, pam_swap(unix, None))],
      f"the pam_unix.so password line of /etc/pam.d/{f} must set rounds to 100000 or greater",
      f"Set rounds=100000 on the password sufficient pam_unix.so sha512 line of /etc/pam.d/{f}",
      comment=f"uncommented lines of /etc/pam.d/{f}: rounds= on the password pam_unix.so line",
      pass_cases=[pam_with(f, pam_swap(unix, "password sufficient pam_unix.so sha512 rounds=200000"))])


# ── account_auth: pwquality, shadow, libuser, emergency / rescue ────────────────────────────────
PWQ = "/etc/security/pwquality.conf"
num_rule("account_auth", "RHEL-09-611010", "pwquality_retry", ["password_policy", "retry"], 1, 3, 3, [0, 4, "three", "1"],
         f"retry in {PWQ}(.d) must be 1 to 3", f"Set retry = 3 in {PWQ}",
         f"effective retry from {PWQ} and pwquality.conf.d/*.conf (null when missing or commented out)",
         pass_cases=[{"password_policy": {"retry": 1}}])

flag_rule("account_auth", "RHEL-09-611060", "pwquality_enforce_for_root", ["password_policy", "enforce_for_root"],
          PWQ + " or pwquality.conf.d/*.conf", "password complexity applies to root")

R("account_auth", "RHEL-09-611080", "shadow_min_age_one_day", [("shadow_min_age_below_one",)],
  [["accts := input.shadow_min_age_below_one", "is_array(accts)",
    "count([a | some a in accts; not a.system_account == true]) == 0"]],
  {"shadow_min_age_below_one": []},
  [{"shadow_min_age_below_one": [{"name": "djohnson", "min_days": 0, "system_account": False}]},
   {"shadow_min_age_below_one": [{"name": "djohnson", "min_days": 0}]}],
  "no account other than a system account may have a minimum password lifetime below 1 day in /etc/shadow",
  "Set a 24 hour minimum password lifetime on each listed account: passwd -n 1 <user>",
  comment="accounts printed by awk -F: '$4 < 1 {printf \"%s %d\\n\", $1, $4}' /etc/shadow, each {name, min_days, system_account}",
  pass_cases=[{"shadow_min_age_below_one": [{"name": "bin", "min_days": 0, "system_account": True}]}])

R("account_auth", "RHEL-09-611105", "pwquality_dictcheck", [("password_policy", "dictcheck")],
  [['n := _num(["password_policy", "dictcheck"])', "n != 0"]],
  {"password_policy": {"dictcheck": 1}}, [{"password_policy": {"dictcheck": 0}}, {"password_policy": {"dictcheck": "0"}},
                                          {"password_policy": {"dictcheck": "yes"}}, {"password_policy": {"dictcheck": "1"}}],
  f"dictcheck in {PWQ}(.d) must be set to a value other than 0", f"Set dictcheck = 1 in {PWQ}",
  comment=f"effective dictcheck from {PWQ} and pwquality.conf.d/*.conf (null when missing or commented out)",
  pass_cases=[{"password_policy": {"dictcheck": 2}}])

num_rule("account_auth", "RHEL-09-611115", "pwquality_difok", ["password_policy", "difok"], 8, None, 8, [7, "5"],
         f"difok in {PWQ}(.d) must be 8 or greater", f"Set difok = 8 in {PWQ}",
         f"effective difok from {PWQ} and pwquality.conf.d/*.conf")
num_rule("account_auth", "RHEL-09-611120", "pwquality_maxclassrepeat", ["password_policy", "maxclassrepeat"], 1, 4, 4, [0, 5, "0"],
         f"maxclassrepeat in {PWQ}(.d) must be 1 to 4 (not 0)", f"Set maxclassrepeat = 4 in {PWQ}",
         f"effective maxclassrepeat from {PWQ} and pwquality.conf.d/*.conf")
# V2R10 check text: a finding only when "set to more than 3" or commented out (0 is not excluded, unlike maxclassrepeat)
num_rule("account_auth", "RHEL-09-611125", "pwquality_maxrepeat", ["password_policy", "maxrepeat"], 0, 3, 3, [4, -1, "4", "3"],
         f"maxrepeat in {PWQ}(.d) must be set to 3 or less", f"Set maxrepeat = 3 in {PWQ}",
         f"effective maxrepeat from {PWQ} and pwquality.conf.d/*.conf",
         pass_cases=[{"password_policy": {"maxrepeat": 2}}, {"password_policy": {"maxrepeat": 0}}])
num_rule("account_auth", "RHEL-09-611130", "pwquality_minclass", ["password_policy", "minclass"], 4, None, 4, [3, "3"],
         f"minclass in {PWQ}(.d) must be 4 or greater", f"Set minclass = 4 in {PWQ}",
         f"effective minclass from {PWQ} and pwquality.conf.d/*.conf")

R("account_auth", "RHEL-09-611135", "libuser_sha512", [("packages", "libuser")],
  [["input.packages.libuser == true", '_str(["libuser_conf", "defaults", "crypt_style"]) == "sha512"']],
  {"packages": {"libuser": True}, "libuser_conf": {"defaults": {"crypt_style": "sha512"}}},
  [{"libuser_conf": {"defaults": {"crypt_style": "md5"}}}, {"libuser_conf": {"defaults": {"crypt_style": None}}}],
  "libuser is installed: crypt_style in the [defaults] section of /etc/libuser.conf (input.libuser_conf.defaults.crypt_style) must be sha512",
  "Set crypt_style = sha512 in the [defaults] section of /etc/libuser.conf",
  comment="uncommented crypt_style of the [defaults] section of /etc/libuser.conf, read when libuser is installed; not installed is Not Applicable",
  na=[["input.packages.libuser == false"]], na_expect="the libuser package is not installed",
  na_cases=[{"packages": {"libuser": False}, "libuser_conf": None}])

for sid, mode, name in (("RHEL-09-611195", "emergency", "emergency_mode_authentication"),
                        ("RHEL-09-611200", "rescue", "single_user_mode_authentication")):
    want = f"ExecStart=-/usr/lib/systemd/systemd-sulogin-shell {mode}"
    key = f"{mode}.service"
    R("account_auth", sid, name, [("sulogin_lines", key, "unit_file"), ("sulogin_lines", key, "drop_ins")],
      [[f'some where in {{"unit_file", "drop_ins"}}', f'ls := input.sulogin_lines["{key}"][where]', "is_array(ls)",
        "some l in ls", "is_string(l)", f'trim_space(l) == "{want}"']],
      {"sulogin_lines": {key: {"unit_file": [want], "drop_ins": []}}},
      [{"sulogin_lines": {key: {"unit_file": []}}},
       {"sulogin_lines": {key: {"unit_file": [f"ExecStart=-/usr/bin/bash"]}}},
       {"sulogin_lines": {key: {"unit_file": [f"#{want}"]}}}],
      f"/usr/lib/systemd/system/{key} or a drop-in in /etc/systemd/system/{key}.d/ must carry {want}",
      f"Create /etc/systemd/system/{key}.d/{key}.conf with [Service], ExecStart= and {want}, then systemctl daemon-reload",
      comment=f"lines returned by grep sulogin on /usr/lib/systemd/system/{key} (unit_file) and /etc/systemd/system/{key}.d/*.conf (drop_ins)",
      pass_cases=[{"sulogin_lines": {key: {"unit_file": [], "drop_ins": [want]}}}])


# ── configuration_management: SELinux ───────────────────────────────────────────────────────────
R("configuration_management", "RHEL-09-431016", "sudo_selinux_context_elevated", [("sudoers", "lines")],
  [["_p4_sudoers_collected", "some e in _p4_sudoers",
    r"regex.match(`^\s*[^\s#]\S*\s+\S+\s*=.*\bTYPE\s*=\s*sysadm_t\b`, e.line)",
    r"regex.match(`^\s*[^\s#]\S*\s+\S+\s*=.*\bROLE\s*=\s*sysadm_r\b`, e.line)"]],
  SUDO,
  [sudo_with(drop=["sysadm_r"]), sudo_with(("/etc/sudoers.d/admins", "%wheel ALL=(ALL) ROLE=sysadm_r ALL"), drop=["sysadm_t"]),
   sudo_with(("/etc/sudoers.d/admins", "%wheel ALL=(ALL) TYPE=staff_t ROLE=staff_r ALL"), drop=["sysadm_t"])],
  "a sudoers user specification for the designated administrator group or account must elevate the SELinux context with "
  "TYPE=sysadm_t ROLE=sysadm_r",
  "Add %<admin_group> ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL to a file in /etc/sudoers.d/ (visudo -f)",
  comment="uncommented lines of /etc/sudoers and /etc/sudoers.d/* (input.sudoers.lines[{file, line}]) carrying TYPE=sysadm_t and ROLE=sysadm_r",
  pass_cases=[sudo_with(("/etc/sudoers", "admin1 ALL=(ALL) ROLE=sysadm_r TYPE=sysadm_t ALL"), drop=["sysadm_t"])])

R("configuration_management", "RHEL-09-431020", "faillock_dir_selinux_type", [("faillock_dir", "selinux_type")],
  [['_str(["faillock_dir", "selinux_type"]) == "faillog_t"']],
  {"faillock_dir": {"path": "/var/log/faillock", "selinux_type": "faillog_t"}},
  [{"faillock_dir": {"selinux_type": "var_log_t"}}],
  "the faillock tally directory (dir in /etc/security/faillock.conf) must have the SELinux context type faillog_t",
  "semanage fcontext -a -t faillog_t \"/var/log/faillock(/.*)?\" && restorecon -R -v /var/log/faillock",
  comment="SELinux type from ls -Zd of the directory named by dir in /etc/security/faillock.conf (input.faillock_dir {path, selinux_type}); "
          "SELinux not enforcing a targeted policy, or pam_faillock not configured, is Not Applicable",
  na=[['g := _kw(["selinux", "getenforce"])', 'g != "enforcing"'],
      ['p := _str(["selinux", "policy"])', 'p != "targeted"'],
      ['every f in {"system-auth", "password-auth"} {\n\tlines := _p4_pam(f)\n\tcount([l | some l in lines; contains(l, "pam_faillock.so")]) == 0\n}']],
  na_expect="SELinux is not enforcing a targeted policy, or pam_faillock is not configured in system-auth / password-auth",
  na_cases=[{"faillock_dir": {"selinux_type": None}, "selinux": {"getenforce": "Permissive"}},
            {"faillock_dir": {"selinux_type": "var_log_t"}, "selinux": {"policy": "mls"}},
            {"faillock_dir": {"selinux_type": None},
             "pam_d": {"system-auth": ["auth sufficient pam_unix.so"], "password-auth": ["auth sufficient pam_unix.so"]}}])

pkg_rule("configuration_management", "RHEL-09-431025", "policycoreutils_installed", "policycoreutils")
pkg_rule("configuration_management", "RHEL-09-431030", "policycoreutils_python_utils_installed", "policycoreutils-python-utils")


# ── software_integrity: fapolicyd, AIDE, rsyslog ────────────────────────────────────────────────
pkg_rule("software_integrity", "RHEL-09-433010", "fapolicyd_installed", "fapolicyd")

R("software_integrity", "RHEL-09-433015", "fapolicyd_active", [("services", "fapolicyd")],
  [['_kw(["services", "fapolicyd"]) == "active"']],
  {"services": {"fapolicyd": "active"}}, [{"services": {"fapolicyd": "inactive"}}, {"services": {"fapolicyd": "failed"}}],
  "fapolicyd must be active (systemctl is-active fapolicyd)", "Enable fapolicyd: systemctl enable --now fapolicyd",
  comment="systemctl is-active fapolicyd")

FAP_RULES = ["allow perm=any uid=0 : dir=/var/tmp/", "allow perm=open all : ftype=text/x-python trust=1",
             "deny_audit perm=any pattern=ld_so : all", "deny perm=any all : all"]
R("software_integrity", "RHEL-09-433016", "fapolicyd_deny_all", [("fapolicyd", "permissive"), ("fapolicyd", "compiled_rules")],
  [['_str(["fapolicyd", "permissive"]) == "0"', "rules := input.fapolicyd.compiled_rules", "is_array(rules)", "count(rules) > 0",
    "last := rules[count(rules) - 1]", "is_string(last)",
    r"regex.match(`^\s*deny(_audit|_log)?\s+perm=any\s+all\s*:\s*all\s*$`, last)"]],
  {"fapolicyd": {"permissive": "0", "compiled_rules": FAP_RULES}},
  [{"fapolicyd": {"permissive": "1"}}, {"fapolicyd": {"compiled_rules": FAP_RULES[:-1]}},
   {"fapolicyd": {"compiled_rules": FAP_RULES + ["allow perm=any all : all"]}}, {"fapolicyd": {"compiled_rules": []}}],
  "permissive in /etc/fapolicyd/fapolicyd.conf must be 0 and the last rule of /etc/fapolicyd/compiled.rules must deny all "
  "(deny perm=any all : all; deny_audit and deny_log also meet it)",
  "Set permissive = 0 in /etc/fapolicyd/fapolicyd.conf and end the rules in /etc/fapolicyd/rules.d/ with deny perm=any all : all",
  comment="permissive as configured in /etc/fapolicyd/fapolicyd.conf; the uncommented rules of /etc/fapolicyd/compiled.rules in file order",
  pass_cases=[{"fapolicyd": {"compiled_rules": FAP_RULES[:-1] + ["deny_audit perm=any all : all"]}},
              {"fapolicyd": {"permissive": 0}}])

AUDIT_TOOLS = ["auditctl", "auditd", "ausearch", "aureport", "autrace", "augenrules"]
AIDE_TOOL_LINES = [f"/usr/sbin/{t} p+i+n+u+g+s+b+acl+xattrs+sha512" for t in AUDIT_TOOLS]
helpers("software_integrity", r'''
# the audit tools the RHEL-09-651025 check lists
_p4_audit_tools := ''' + "{" + ", ".join(f'"/usr/sbin/{t}"' for t in AUDIT_TOOLS) + "}" + r'''

# an /etc/aide.conf selection line for exactly this path, with a rule after it
_p4_aide_selects(l, path) if {
	is_string(l)
	parts := regex.split(`\s+`, trim_space(l))
	count(parts) >= 2
	parts[0] == path
}

# an AIDE rule line (uncommented selection / group definition) that uses the given rule (acl, xattrs)
_p4_aide_uses(l, rule) if {
	is_string(l)
	parts := regex.split(`[=+ ]+`, trim_space(l))
	rule in parts
}

# input.rsyslog.config_lines: the uncommented lines of /etc/rsyslog.conf and /etc/rsyslog.d/*, a multi-line
# RainerScript statement joined into one line
_p4_rsyslog := [l | some l in input.rsyslog.config_lines; is_string(l)]

_p4_rsyslog_collected if is_array(input.rsyslog.config_lines)

# the values a pattern's last capture group takes over the rsyslog lines (group index n)
_p4_rsyslog_values(pattern, n) := [lower(m[n]) | some l in _p4_rsyslog; some m in regex.find_all_string_submatch_n(pattern, l, -1)]

# a StreamDriver setting inside a module() block (the check: a finding; it belongs in the omfwd action)
_p4_rsyslog_module_streamdriver(pattern) if {
	some l in _p4_rsyslog
	regex.match(`(?i)^\s*module\s*\(`, l)
	regex.match(pattern, l)
}

# a facility selector (auth, authpriv, daemon) logged at every priority by some rule line
_p4_rsyslog_logs(fac) if {
	some l in _p4_rsyslog
	regex.match(sprintf(`(^|[;,\s])%s\.\*`, [fac]), l)
}''')

R("software_integrity", "RHEL-09-651025", "aide_protects_audit_tools", [("packages", "aide"), ("aide", "audit_tool_lines")],
  [["input.packages.aide == true", "lines := input.aide.audit_tool_lines", "is_array(lines)",
    "every t in _p4_audit_tools {\n\tsome l in lines\n\t_p4_aide_selects(l, t)\n}"]],
  {"packages": {"aide": True}, "aide": {"audit_tool_lines": AIDE_TOOL_LINES}},
  [{"aide": {"audit_tool_lines": AIDE_TOOL_LINES[:-1]}}, {"aide": {"audit_tool_lines": []}},
   {"aide": {"audit_tool_lines": AIDE_TOOL_LINES[1:] + ["/usr/sbin/auditctl"]}}, {"packages": {"aide": False}}],
  "AIDE must be installed and /etc/aide.conf must carry a selection line for each of /usr/sbin/auditctl, auditd, ausearch, "
  "aureport, autrace and augenrules, or the SA must show the cryptographic mechanism protecting the audit tools "
  "(input.attest.rhel_09_651025_other_mechanism)",
  "Add a line '<tool> p+i+n+u+g+s+b+acl+xattrs+sha512' to /etc/aide.conf for each audit tool under /usr/sbin",
  comment="the uncommented lines of /etc/aide.conf naming /usr/sbin/au* (grep /usr/sbin/au /etc/aide.conf); empty when none",
  attest_alts=[['_attested("rhel_09_651025_other_mechanism")']],
  pass_cases=[{"packages": {"aide": False}, "attest": {"rhel_09_651025_other_mechanism": True}}])

for sid, rule, name, what in (("RHEL-09-651030", "acl", "aide_verifies_acls", "ACLs"),
                              ("RHEL-09-651035", "xattrs", "aide_verifies_xattrs", "extended attributes")):
    att = f"{sid.lower().replace('-', '_')}_other_tool"
    R("software_integrity", sid, name, [("aide", "rule_lines")],
      [["lines := input.aide.rule_lines", "is_array(lines)", "count(lines) > 0",
        f'every l in lines {{\n\t_p4_aide_uses(l, "{rule}")\n}}']],
      {"aide": {"rule_lines": ["All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux"]}},
      [{"aide": {"rule_lines": ["All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux", "NORMAL=p+i+n+u+g+s+m+sha512"]}},
       {"aide": {"rule_lines": ["All=p+i+n+u+g+s+m+S+sha512+" + ("xattrs" if rule == "acl" else "acl") + "+selinux"]}},
       {"aide": {"rule_lines": []}}],
      f"every uncommented selection line in /etc/aide.conf must use the {rule} rule, or another file integrity tool checking {what} "
      f"must be attested (input.attest.{att})",
      f"Add {rule} to every uncommented selection line in /etc/aide.conf",
      comment=f"the uncommented rule / selection lines of /etc/aide.conf must each carry {rule}",
      attest_alts=[[f'_attested("{att}")']],
      pass_cases=[{"aide": {"rule_lines": []}, "attest": {att: True}}])

pkg_rule("software_integrity", "RHEL-09-652015", "rsyslog_gnutls_installed", "rsyslog-gnutls")

RSYSLOG_GREEN = ["$DefaultNetstreamDriver gtls", "$ActionSendStreamDriverMode 1", "$ActionSendStreamDriverAuthMode x509/name",
                 "auth.*;authpriv.*;daemon.* /var/log/secure", "cron.* /var/log/cron", "*.* @@logserver.example.com:6514"]
RSYS = {"rsyslog": {"config_lines": RSYSLOG_GREEN, "listening_sockets": []}}


def rsys_with(*extra, drop=()):
    return {"rsyslog": {"config_lines": [l for l in RSYSLOG_GREEN if not any(d in l for d in drop)] + list(extra)}}


LISTEN_RE = r"(?i)(InputTCPServerRun|UDPServerRun|RELPServerRun|imtcp|imudp|imrelp)"
R("software_integrity", "RHEL-09-652025", "rsyslog_no_remote_reception", [("rsyslog", "listening_sockets"), ("rsyslog", "config_lines")],
  [["socks := input.rsyslog.listening_sockets", "is_array(socks)", "count(socks) == 0"],
   ["_p4_rsyslog_collected", "is_array(input.rsyslog.listening_sockets)",
    f"count([l | some l in _p4_rsyslog; regex.match(`{LISTEN_RE}`, l)]) == 0"]],
  RSYS,
  [dict(rsyslog={"listening_sockets": ["udp UNCONN 0 0 *:514 *:* users:((\"rsyslogd\",pid=1045,fd=4))"],
                 "config_lines": RSYSLOG_GREEN + ['module(load="imudp")', 'input(type="imudp" port="514")']}),
   dict(rsyslog={"listening_sockets": ["tcp LISTEN 0 25 *:514 *:* users:((\"rsyslogd\",pid=1045,fd=5))"],
                 "config_lines": RSYSLOG_GREEN + ["$InputTCPServerRun 514"]})],
  "rsyslog must not listen for remote messages (ss -tulnp shows no rsyslog socket, or no uncommented imtcp / imudp / imrelp / "
  "ServerRun line in /etc/rsyslog.conf and /etc/rsyslog.d/*), unless the system is documented and authorized as a log "
  "aggregation server (input.attest.rhel_09_652025_log_aggregation_server)",
  "Remove the InputTCPServerRun / UDPServerRun / RELPServerRun / imtcp / imudp / imrelp lines from /etc/rsyslog.conf and "
  "/etc/rsyslog.d/, then systemctl restart rsyslog.service",
  comment="rsyslog sockets from ss -tulnp | grep rsyslog (input.rsyslog.listening_sockets) and the uncommented rsyslog configuration "
          "lines (input.rsyslog.config_lines); another log off-load tool in lieu of rsyslog is Not Applicable",
  attest_alts=[['_attested("rhel_09_652025_log_aggregation_server")']],
  na=[['_attested("rhel_09_652025_other_log_tool")']],
  na_expect="the SA demonstrated another tool managing log off-load and aggregation in lieu of rsyslog",
  na_cases=[{"rsyslog": {"listening_sockets": None, "config_lines": None}, "attest": {"rhel_09_652025_other_log_tool": True}}],
  pass_cases=[dict(rsyslog={"listening_sockets": ["udp UNCONN 0 0 *:514 *:* users:((\"rsyslogd\",pid=1045,fd=4))"],
                            "config_lines": RSYSLOG_GREEN}),
              dict(rsyslog={"listening_sockets": ["tcp LISTEN 0 25 *:514 *:* users:((\"rsyslogd\",pid=1045,fd=5))"],
                            "config_lines": RSYSLOG_GREEN + ["$InputTCPServerRun 514"]},
                   attest={"rhel_09_652025_log_aggregation_server": True})])

R("software_integrity", "RHEL-09-652030", "rsyslog_remote_access_logged", [("rsyslog", "config_lines")],
  [["_p4_rsyslog_collected", 'every fac in {"auth", "authpriv", "daemon"} {\n\t_p4_rsyslog_logs(fac)\n}']],
  RSYS,
  [rsys_with("authpriv.* /var/log/secure", drop=["auth.*"]), rsys_with("auth.*;authpriv.* /var/log/secure", drop=["auth.*"]),
   rsys_with(drop=["auth.*"])],
  "auth.*, authpriv.* and daemon.* must each be logged by an uncommented rule in /etc/rsyslog.conf or /etc/rsyslog.d/",
  "Add auth.*;authpriv.*;daemon.* /var/log/secure to /etc/rsyslog.conf and restart rsyslog",
  comment="uncommented rsyslog rule lines selecting auth.*, authpriv.* and daemon.*",
  pass_cases=[rsys_with("auth.* /var/log/secure", "authpriv.* /var/log/secure", "daemon.* /var/log/messages", drop=["auth.*"])])

AUTHMODE_RE = r"""(?i)streamdriver\.?authmode\s*(=\s*"?|\s+)([^"\s)]+)"""
MODE_RE = r"""(?i)streamdriver\.?mode\s*(=\s*"?|\s+)([^"\s)]+)"""
DRIVER_RE = r"""(?i)(defaultnetstreamdriver|streamdriver(\.name)?)\s*(=\s*"?|\s+)([^"\s)]+)"""
OMFWD = ('action(type="omfwd" target="logserver.example.com" port="6514" protocol="tcp" StreamDriver="gtls" '
         'StreamDriverMode="1" StreamDriverAuthMode="x509/name")')
MODULE_BAD = 'module(load="builtin:omfwd" StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="x509/name")'

R("software_integrity", "RHEL-09-652040", "rsyslog_authenticates_log_server", [("rsyslog", "config_lines")],
  [["_p4_rsyslog_collected", f"vals := _p4_rsyslog_values(`{AUTHMODE_RE}`, 2)", "count(vals) > 0",
    'every v in vals {\n\tv == "x509/name"\n}',
    "not _p4_rsyslog_module_streamdriver(`(?i)streamdriver\\.?authmode`)"]],
  RSYS,
  [rsys_with(drop=["AuthMode"]), rsys_with("$ActionSendStreamDriverAuthMode anon", drop=["AuthMode"]),
   rsys_with(MODULE_BAD, drop=["AuthMode"])],
  "$ActionSendStreamDriverAuthMode (or StreamDriverAuthMode / StreamDriver.AuthMode in an omfwd action, never in a module block) "
  "must be x509/name, or the SA must show that the audit log transfer to another system or media is encrypted "
  "(input.attest.rhel_09_652040_offload_encrypted)",
  "Set $ActionSendStreamDriverAuthMode x509/name in /etc/rsyslog.conf or /etc/rsyslog.d/<file>.conf",
  comment="uncommented StreamDriver AuthMode settings of /etc/rsyslog.conf and /etc/rsyslog.d/*.conf (input.rsyslog.config_lines)",
  attest_alts=[['_attested("rhel_09_652040_offload_encrypted")']],
  pass_cases=[rsys_with(OMFWD, drop=["$DefaultNetstreamDriver", "$ActionSend", "@@"]),
              dict(rsys_with(drop=["AuthMode"]), attest={"rhel_09_652040_offload_encrypted": True})])

R("software_integrity", "RHEL-09-652045", "rsyslog_encrypts_offload", [("rsyslog", "config_lines")],
  [["_p4_rsyslog_collected", f"vals := _p4_rsyslog_values(`{MODE_RE}`, 2)", "count(vals) > 0",
    'every v in vals {\n\tv == "1"\n}',
    "not _p4_rsyslog_module_streamdriver(`(?i)streamdriver\\.?authmode`)"]],
  RSYS,
  [rsys_with(drop=["DriverMode"]), rsys_with("$ActionSendStreamDriverMode 0", drop=["DriverMode"]), rsys_with(MODULE_BAD)],
  "$ActionSendStreamDriverMode (or StreamDriverMode / StreamDriver.Mode in an omfwd action) must be 1, and "
  "StreamDriverAuthMode must not be set in a module block",
  "Set $ActionSendStreamDriverMode 1 in /etc/rsyslog.conf or /etc/rsyslog.d/<file>.conf",
  comment="uncommented StreamDriver Mode settings of /etc/rsyslog.conf and /etc/rsyslog.d/*.conf (input.rsyslog.config_lines)",
  pass_cases=[rsys_with(OMFWD, drop=["$DefaultNetstreamDriver", "$ActionSend", "@@"])])

R("software_integrity", "RHEL-09-652050", "rsyslog_gtls_driver", [("rsyslog", "config_lines")],
  [["_p4_rsyslog_collected", f"vals := _p4_rsyslog_values(`{DRIVER_RE}`, 4)", "count(vals) > 0",
    'every v in vals {\n\tv == "gtls"\n}',
    "not _p4_rsyslog_module_streamdriver(`(?i)streamdriver(\\.name)?\\s*=`)"]],
  RSYS,
  [rsys_with(drop=["$DefaultNetstreamDriver"]), rsys_with("$DefaultNetstreamDriver ptcp", drop=["$DefaultNetstreamDriver"]),
   rsys_with(MODULE_BAD)],
  "$DefaultNetstreamDriver (or StreamDriver / StreamDriver.Name in an omfwd action, never in a module block) must be gtls",
  "Set $DefaultNetstreamDriver gtls in /etc/rsyslog.conf or /etc/rsyslog.d/<file>.conf",
  comment="uncommented DefaultNetstreamDriver / StreamDriver settings of /etc/rsyslog.conf and /etc/rsyslog.d/*.conf (input.rsyslog.config_lines)",
  pass_cases=[rsys_with(OMFWD, drop=["$DefaultNetstreamDriver", "$ActionSend", "@@"])])

R("software_integrity", "RHEL-09-652055", "rsyslog_forwards_via_tcp", [("rsyslog", "config_lines")],
  [["_p4_rsyslog_collected", "some l in _p4_rsyslog", r"regex.match(`@@\S`, l)"],
   ["_p4_rsyslog_collected", "some l in _p4_rsyslog", 'contains(l, `type="omfwd"`)']],
  RSYS,
  [rsys_with(drop=["@@"]), rsys_with("*.* @logserver.example.com:514", drop=["@@"])],
  "/etc/rsyslog.conf or /etc/rsyslog.d/ must forward to a remote server over TCP (*.* @@host:port, or an action of type omfwd), "
  "or the SA must show how audit logs are off-loaded to another system or media (input.attest.rhel_09_652055_offload_documented)",
  "Add *.* @@<remoteloggingserver>:<port> (or an omfwd action with protocol=\"tcp\") to /etc/rsyslog.conf or /etc/rsyslog.d/<file>.conf",
  comment="uncommented rsyslog lines with a @@ target or type=\"omfwd\" (input.rsyslog.config_lines)",
  attest_alts=[['_attested("rhel_09_652055_offload_documented")']],
  pass_cases=[rsys_with(OMFWD, drop=["@@"]), dict(rsys_with(drop=["@@"]), attest={"rhel_09_652055_offload_documented": True})])

R("software_integrity", "RHEL-09-652060", "rsyslog_cron_logging", [("rsyslog", "config_lines")],
  [["_p4_rsyslog_collected", "some l in _p4_rsyslog", r"regex.match(`(^|[;,\s])cron\.\*`, l)", 'contains(l, "/var/log/cron")']],
  RSYS,
  [rsys_with(drop=["cron.*"]), rsys_with("cron.* /var/log/messages", drop=["cron.*"])],
  "an uncommented rsyslog rule must log cron.* to /var/log/cron, or the functional test (logger -p cron.info, then grep "
  "/var/log/cron) must show the message logged (input.attest.rhel_09_652060_cron_test_logged)",
  "Add cron.* /var/log/cron to /etc/rsyslog.conf or a file in /etc/rsyslog.d/ and restart rsyslog",
  comment="uncommented cron.* rule lines of /etc/rsyslog.conf and /etc/rsyslog.d/*.conf logging to /var/log/cron",
  attest_alts=[['_attested("rhel_09_652060_cron_test_logged")']],
  pass_cases=[rsys_with('cron.* action(type="omfile" file="/var/log/cron")', drop=["cron.*"]),
              dict(rsys_with(drop=["cron.*"]), attest={"rhel_09_652060_cron_test_logged": True})])


# ── pki_crypto: smart card, cached authenticators ───────────────────────────────────────────────
ALT_MFA = "the SA demonstrated an approved alternate multifactor authentication method"

R("pki_crypto", "RHEL-09-611160", "cac_card_driver", [("opensc", "card_drivers")],
  [['drivers := {lower(d) | some d in _csv(["opensc", "card_drivers"])}', '"cac" in drivers']],
  {"opensc": {"card_drivers": "cac"}}, [{"opensc": {"card_drivers": "PIV-II"}}, {"opensc": {"card_drivers": ""}}],
  "opensc-tool --get-conf-entry app:default:card_drivers must list cac",
  "Load the CAC driver: opensc-tool --set-conf-entry app:default:card_drivers:cac, then systemctl restart pcscd",
  comment="output of opensc-tool --get-conf-entry app:default:card_drivers (comma-separated drivers; empty string when no line is returned)",
  pass_cases=[{"opensc": {"card_drivers": "cac, PIV-II"}}])

R("pki_crypto", "RHEL-09-611175", "pcsc_lite_installed", [("packages", "pcsc-lite")],
  [['input.packages["pcsc-lite"] == true']],
  {"packages": {"pcsc-lite": True}}, [{"packages": {"pcsc-lite": False}}],
  "the pcsc-lite package must be installed", "Install the package: dnf install pcsc-lite",
  comment="pcsc-lite package installed (dnf list --installed pcsc-lite); an approved alternate MFA method is Not Applicable",
  na=[['_attested("rhel_09_611175_alternate_mfa")']], na_expect=ALT_MFA,
  na_cases=[{"packages": {"pcsc-lite": False}, "attest": {"rhel_09_611175_alternate_mfa": True}}])

R("pki_crypto", "RHEL-09-611180", "pcscd_socket_active", [("services", "pcscd.socket")],
  [['_kw(["services", "pcscd.socket"]) == "active"']],
  {"services": {"pcscd.socket": "active"}}, [{"services": {"pcscd.socket": "inactive"}}],
  "pcscd.socket must be active (systemctl is-active pcscd.socket)", "Enable the socket: systemctl enable --now pcscd.socket",
  comment="systemctl is-active pcscd.socket")

pkg_rule("pki_crypto", "RHEL-09-611185", "opensc_installed", "opensc")

R("pki_crypto", "RHEL-09-611190", "ssh_private_keys_passphrase", [("ssh_private_keys_without_passphrase",)],
  [["ks := input.ssh_private_keys_without_passphrase", "is_array(ks)", "count(ks) == 0"]],
  {"ssh_private_keys_without_passphrase": []}, [{"ssh_private_keys_without_passphrase": ["/home/djohnson/.ssh/id_rsa"]}],
  "every SSH private key stored on the system must be protected by a passphrase (ssh-keygen -y -f <key> must prompt for it)",
  "Create a new key pair protected by a passphrase: ssh-keygen -N <passphrase>",
  comment="paths of the private keys for which ssh-keygen -y -f <key> printed the public key without a passphrase prompt; "
          "an approved alternate MFA method is Not Applicable",
  na=[['_attested("rhel_09_611190_alternate_mfa")']], na_expect=ALT_MFA,
  na_cases=[{"ssh_private_keys_without_passphrase": ["/home/djohnson/.ssh/id_rsa"], "attest": {"rhel_09_611190_alternate_mfa": True}}])

R("pki_crypto", "RHEL-09-631020", "sssd_cached_credentials_expire", [("sssd", "cache_credentials_values")],
  [["vals := input.sssd.cache_credentials_values", "is_array(vals)",
    'count([v | some v in vals; not lower(trim_space(sprintf("%v", [v]))) == "false"]) == 0'],
   ["is_array(input.sssd.cache_credentials_values)", '_str(["sssd", "offline_credentials_expiration"]) == "1"']],
  {"sssd": {"cache_credentials_values": ["true"], "offline_credentials_expiration": "1"}},
  [{"sssd": {"offline_credentials_expiration": "0"}}, {"sssd": {"offline_credentials_expiration": None}},
   {"sssd": {"cache_credentials_values": ["false", "True"], "offline_credentials_expiration": "7"}}],
  "when cache_credentials is true in /etc/sssd/sssd.conf or /etc/sssd/conf.d/, offline_credentials_expiration must be 1",
  "Set offline_credentials_expiration = 1 in the [pam] section of /etc/sssd/sssd.conf (or a conf.d file)",
  comment="every uncommented cache_credentials value in /etc/sssd/sssd.conf and conf.d (empty list when the option is missing); "
          "offline_credentials_expiration is read when one of them is not false",
  pass_cases=[{"sssd": {"cache_credentials_values": [], "offline_credentials_expiration": None}},
              {"sssd": {"cache_credentials_values": ["False"], "offline_credentials_expiration": None}},
              {"sssd": {"offline_credentials_expiration": 1}}])


# ── audit_logging: audit package and auditd.conf ────────────────────────────────────────────────
pkg_rule("audit_logging", "RHEL-09-653010", "audit_package_installed", "audit")

R("audit_logging", "RHEL-09-653020", "disk_error_action_ok", [("auditd_config", "disk_error_action")],
  [['_kw(["auditd_config", "disk_error_action"]) in {"syslog", "single", "halt"}']],
  {"auditd_config": {"disk_error_action": "HALT"}},
  [{"auditd_config": {"disk_error_action": "ignore"}}, {"auditd_config": {"disk_error_action": "suspend"}}],
  "disk_error_action in /etc/audit/auditd.conf must be SYSLOG, SINGLE or HALT, or the SA must attest that the system takes "
  "appropriate action when an audit process failure occurs (input.attest.rhel_09_653020_disk_error_action)",
  "Set disk_error_action = HALT in /etc/audit/auditd.conf",
  comment="disk_error_action as configured in /etc/audit/auditd.conf",
  attest_alts=[['_attested("rhel_09_653020_disk_error_action")']],
  pass_cases=[{"auditd_config": {"disk_error_action": "syslog"}}, {"auditd_config": {"disk_error_action": "Single"}},
              {"auditd_config": {"disk_error_action": "ignore"}, "attest": {"rhel_09_653020_disk_error_action": True}}])

# The check is a judgement (is the audit partition large enough for one week of records on this system): there is no
# threshold in the check text, so the rule passes on the attestation alone. kind attestation, no machine alternative.
R("audit_logging", "RHEL-09-653030", "audit_storage_one_week", [],
  [],
  {"attest": {"rhel_09_653030_audit_capacity_sufficient": True}},
  [{"attest": {"rhel_09_653030_audit_capacity_sufficient": False}}],
  "the partition holding the audit log (log_file in /etc/audit/auditd.conf; df -h) must be reviewed and attested as large enough "
  "for at least one week of audit records (input.attest.rhel_09_653030_audit_capacity_sufficient)",
  "Resize the audit partition, or create one, with space for at least one week of audit records",
  comment="organizational review of the audit partition size (df -h of the log_file directory): attestation only",
  kind="attestation", attest_alts=[['_attested("rhel_09_653030_audit_capacity_sufficient")']])

helpers("audit_logging", r'''
# an auditd.conf percentage ("25%") at path as a number; undefined for anything else (an absolute size in MiB
# cannot be compared with the check's percentage without the volume size)
_p4_percent(path) := to_number(m[0][1]) if {
	s := _str(path)
	m := regex.find_all_string_submatch_n(`^([0-9]+)\s*%$`, s, 1)
	count(m) == 1
}''')

R("audit_logging", "RHEL-09-653035", "space_left_25_percent", [("auditd_config", "space_left")],
  [['n := _p4_percent(["auditd_config", "space_left"])', "n >= 25", "n <= 100"]],
  {"auditd_config": {"space_left": "25%"}},
  [{"auditd_config": {"space_left": "10%"}}, {"auditd_config": {"space_left": "75"}}, {"auditd_config": {"space_left": 25}}],
  "space_left in /etc/audit/auditd.conf must be 25% or more of the audit storage volume (written as a percentage)",
  "Set space_left = 25% in /etc/audit/auditd.conf",
  comment="space_left as written in /etc/audit/auditd.conf, with its % sign (null when missing or commented out)",
  pass_cases=[{"auditd_config": {"space_left": "30%"}}])

R("audit_logging", "RHEL-09-653045", "admin_space_left_5_percent", [("auditd_config", "admin_space_left")],
  [['_p4_percent(["auditd_config", "admin_space_left"]) == 5']],
  {"auditd_config": {"admin_space_left": "5%"}},
  [{"auditd_config": {"admin_space_left": "2%"}}, {"auditd_config": {"admin_space_left": "50"}}, {"auditd_config": {"admin_space_left": "10%"}}],
  "admin_space_left in /etc/audit/auditd.conf must be 5% of the audit storage volume (written as a percentage)",
  "Set admin_space_left = 5% in /etc/audit/auditd.conf",
  comment="admin_space_left as written in /etc/audit/auditd.conf, with its % sign (null when missing or commented out)")
