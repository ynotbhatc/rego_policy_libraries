"""Reviewed logic table for gen_rhel9.py, part 1 (DISA STIG for RHEL 9, V2R10): 69 rules, RHEL-09-211010 to
RHEL-09-231145, each written against the full V2R10 check text. Same spec format as rhel9_rules.R; imported by
the last line of rhel9_rules.py, so the entries land in rhel9_rules.RULES / SECTION_HELPERS.
"""
from rhel9_rules import MOUNTS, RULES, R, alt_mfa, helpers, module_rule, sysctl_rule


def attested(sid, what):
    return f"rhel_09_{sid[-6:]}_{what}"


# ── release, patching, boot target, systemd ─────────────────────────────────────────────────────
R("configuration_management", "RHEL-09-211010", "vendor_supported_release",
  [("os_release", "redhat_release")],
  [['s := _str(["os_release", "redhat_release"])',
    r"regex.match(`^Red Hat Enterprise Linux release 9\.[0-9]+`, s)",
    '_attested("rhel_09_211010_release_supported")']],
  {"os_release": {"redhat_release": "Red Hat Enterprise Linux release 9.6 (Plow)"}, "attest": {"rhel_09_211010_release_supported": True}},
  [{"attest": {"rhel_09_211010_release_supported": False}},
   {"os_release": {"redhat_release": "Red Hat Enterprise Linux release 8.10 (Ootpa)"}}],
  "/etc/redhat-release must name a RHEL 9 release and the SA must attest that this release is vendor supported "
  "(input.attest.rhel_09_211010_release_supported)",
  "Upgrade to a supported version of RHEL 9",
  comment="content of /etc/redhat-release; whether that minor release is still supported is an attestation (the supported set changes over time)",
  kind="machine+attestation")

R("software_integrity", "RHEL-09-211015", "security_patches_current",
  [], [],
  {"attest": {"rhel_09_211015_patching_current": True}},
  [{"attest": {"rhel_09_211015_patching_current": False}}],
  "the SA must attest that security patches and updates are installed in line with the organizational patching policy "
  "(dnf history list compared with Red Hat errata; input.attest.rhel_09_211015_patching_current)",
  "Install security patches and updates at the organizationally defined frequency: dnf update",
  comment="a review of dnf history against Red Hat errata and the organizational patching policy: attestation only",
  kind="attestation", attest_alts=[['_attested("rhel_09_211015_patching_current")']])

R("configuration_management", "RHEL-09-211030", "default_target_multi_user",
  [("systemd", "default_target")],
  [['_str(["systemd", "default_target"]) == "multi-user.target"']],
  {"systemd": {"default_target": "multi-user.target"}},
  [{"systemd": {"default_target": "graphical.target"}}],
  "systemctl get-default must return multi-user.target, or the ISSO must have a documented requirement for a graphical "
  "user interface (input.attest.rhel_09_211030_gui_required)",
  "Set the default target: systemctl set-default multi-user.target (or document the GUI requirement with the ISSO)",
  comment="output of systemctl get-default",
  attest_alts=[['_attested("rhel_09_211030_gui_required")']],
  pass_cases=[{"systemd": {"default_target": "graphical.target"}, "attest": {"rhel_09_211030_gui_required": True}}])

R("services", "RHEL-09-211035", "rngd_active",
  [("services", "rngd")],
  [['_kw(["services", "rngd"]) == "active"']],
  {"services": {"rngd": "active"}},
  [{"services": {"rngd": "inactive"}}, {"services": {"rngd": "failed"}}],
  "rngd must be active (systemctl is-active rngd)",
  "Install rng-tools and enable the service: dnf install rng-tools && systemctl enable --now rngd",
  comment="systemctl is-active rngd; kernel FIPS mode enabled (/proc/sys/crypto/fips_enabled = 1) is Not Applicable",
  na=[['_str(["fips", "fips_enabled"]) == "1"']],
  na_expect="the kernel runs in FIPS mode (RHEL-09-671010)",
  na_cases=[{"services": {"rngd": "inactive"}, "fips": {"fips_enabled": "1"}}])

R("audit_logging", "RHEL-09-211040", "journald_active",
  [("services", "systemd-journald")],
  [['_kw(["services", "systemd-journald"]) == "active"']],
  {"services": {"systemd-journald": "active"}},
  [{"services": {"systemd-journald": "inactive"}}, {"services": {"systemd-journald": "failed"}}],
  "systemd-journald must be active (systemctl is-active systemd-journald)",
  "Enable the service: systemctl enable --now systemd-journald",
  comment="systemctl is-active systemd-journald")

R("configuration_management", "RHEL-09-211045", "ctrl_alt_del_burst_disabled",
  [("systemd_system_conf", "CtrlAltDelBurstAction")],
  [['_str(["systemd_system_conf", "CtrlAltDelBurstAction"]) == "none"']],
  {"systemd_system_conf": {"CtrlAltDelBurstAction": "none"}},
  [{"systemd_system_conf": {"CtrlAltDelBurstAction": "reboot-force"}}, {"systemd_system_conf": {"CtrlAltDelBurstAction": ""}}],
  "CtrlAltDelBurstAction must be set to none (uncommented) in /etc/systemd/system.conf or /etc/systemd/system.conf.d/",
  "Add CtrlAltDelBurstAction=none under [Manager] in a /etc/systemd/system.conf.d/ drop-in and run systemctl daemon-reload",
  comment="CtrlAltDelBurstAction as configured under /etc/systemd/system* (grep -iR; null when missing or commented out)")


def unit_masked_rule(sec, sid, name, unit, fix, att=None, what="", **kw):
    """the check's 'loaded and not masked' finding: the unit's LoadState must be masked, or the unit not loaded at all"""
    extra = {}
    if att:
        extra = dict(attest_alts=[[f'_attested("{att}")']],
                     pass_cases=[{"systemd_units": {unit: {"load_state": "not-found"}}},
                                 {"systemd_units": {unit: {"load_state": "loaded"}}, "attest": {att: True}}])
    else:
        extra = dict(pass_cases=[{"systemd_units": {unit: {"load_state": "not-found"}}}])
    extra.update(kw)
    R(sec, sid, name, [("systemd_units", unit, "load_state")],
      [[f'_kw(["systemd_units", "{unit}", "load_state"]) in {{"masked", "not-found"}}']],
      {"systemd_units": {unit: {"load_state": "masked"}}},
      [{"systemd_units": {unit: {"load_state": "loaded"}}}],
      f"{unit} must be masked (systemctl status: Loaded: masked), not loaded and unmasked"
      + (f", or {what} (input.attest.{att})" if att else ""),
      fix, comment=f"{unit} load state (systemctl show -p LoadState): masked, or not-found when the unit does not exist", **extra)


unit_masked_rule("configuration_management", "RHEL-09-211055", "debug_shell_masked", "debug-shell.service",
                 "Mask the service: systemctl disable --now debug-shell.service && systemctl mask --now debug-shell.service")


# ── GRUB 2 ──────────────────────────────────────────────────────────────────────────────────────
helpers("configuration_management", r'''
# the whitespace-separated arguments of a kernel command line
_cmdline_tokens(s) := {t | some t in regex.split(`\s+`, trim_space(s)); t != ""}

# every boot entry (input.grub.kernel_args: the args="..." value of each entry of grubby --info=ALL) carries arg
_grubby_all_have(arg) if {
	args := input.grub.kernel_args
	is_array(args)
	count(args) > 0
	every a in args {
		is_string(a)
		arg in _cmdline_tokens(a)
	}
}

# the uncommented GRUB_CMDLINE_LINUX of /etc/default/grub carries arg
_grub_default_has(arg) if {
	s := _str(["grub", "default_cmdline_linux"])
	arg in _cmdline_tokens(s)
}''')

ARGS_OK = "root=/dev/mapper/rhel-root ro audit=1 vsyscall=none page_poison=1 init_on_free=1 pti=on audit_backlog_limit=8192"


def args_without(arg):
    return " ".join(t for t in ARGS_OK.split() if t != arg)


R("configuration_management", "RHEL-09-212015", "no_interactive_boot",
  [("grub", "kernel_args")],
  [["args := input.grub.kernel_args", "is_array(args)", "count(args) > 0",
    'every a in args {\n\tis_string(a)\n\tnot contains(a, "systemd.confirm_spawn")\n}']],
  {"grub": {"kernel_args": [ARGS_OK, ARGS_OK]}},
  [{"grub": {"kernel_args": [ARGS_OK, ARGS_OK + " systemd.confirm_spawn=1"]}},
   {"grub": {"kernel_args": [ARGS_OK + " systemd.confirm_spawn"]}}, {"grub": {"kernel_args": []}}],
  "no boot entry (grubby --info=ALL, args) may carry systemd.confirm_spawn",
  'Remove the argument: grubby --update-kernel=ALL --remove-args="systemd.confirm_spawn"',
  comment="input.grub.kernel_args: the args value of every boot entry printed by grubby --info=ALL, one string per entry")

R("configuration_management", "RHEL-09-212020", "grub_superuser_unique",
  [("grub", "superusers")],
  [['s := _kw(["grub", "superusers"])', 's != ""', 'not s in {"root", "admin", "administrator"}']],
  {"grub": {"superusers": "bootmgr9"}},
  [{"grub": {"superusers": "root"}}, {"grub": {"superusers": "Admin"}}, {"grub": {"superusers": "administrator"}},
   {"grub": {"superusers": ""}}],
  "set superusers= in /etc/grub2.cfg must name an account that is not root, admin or administrator",
  'Set a unique name in /etc/grub.d/01_users (set superusers="<accountname>"; export superusers) and run grub2-mkconfig -o /boot/grub2/grub.cfg',
  comment="the value of set superusers= in /etc/grub2.cfg (grep -A1 superusers; null when not set); the common names the check lists are refused")

for _sid, _name, _field, _fmt, _cmd in (("RHEL-09-212025", "grub_cfg_group_root", "group", "%G", "chgrp"),
                                        ("RHEL-09-212030", "grub_cfg_owner_root", "owner", "%U", "chown")):
    R("file_permissions", _sid, _name, [("file_permissions", "grub_cfg", _field)],
      [[f'_str(["file_permissions", "grub_cfg", "{_field}"]) == "root"']],
      {"file_permissions": {"grub_cfg": {_field: "root"}}}, [{"file_permissions": {"grub_cfg": {_field: "bin"}}}],
      f"/boot/grub2/grub.cfg must have {_field} root", f"{_cmd} root /boot/grub2/grub.cfg",
      comment=f'{_field} of /boot/grub2/grub.cfg (stat -c "{_fmt} %n" /boot/grub2/grub.cfg)')

for _sid, _name, _arg, _att, _what, _fix in (
        ("RHEL-09-212035", "vsyscall_disabled", "vsyscall=none", "rhel_09_212035_vsyscall_documented",
         "the use of virtual system calls must be documented with the ISSO as an operational requirement",
         "Disable virtual system calls"),
        ("RHEL-09-212040", "page_poison_enabled", "page_poison=1", None, "", "Enable page poisoning"),
        ("RHEL-09-212050", "pti_enabled", "pti=on", None, "", "Enable kernel page-table isolation"),
        ("RHEL-09-212055", "audit_at_boot", "audit=1", None, "", "Enable auditing of processes that start before auditd")):
    _key = _arg.split("=")[0]
    _extra = {}
    if _att:
        _extra = dict(attest_alts=[[f'_attested("{_att}")']],
                      pass_cases=[{"grub": {"kernel_args": [args_without(_arg)]}, "attest": {_att: True}}])
    R("configuration_management", _sid, _name,
      [("grub", "kernel_args"), ("grub", "default_cmdline_linux")],
      [[f'_grubby_all_have("{_arg}")', f'_grub_default_has("{_arg}")']],
      {"grub": {"kernel_args": [ARGS_OK, ARGS_OK], "default_cmdline_linux": ARGS_OK}},
      [{"grub": {"kernel_args": [ARGS_OK, args_without(_arg)]}},
       {"grub": {"kernel_args": [ARGS_OK, args_without(_arg) + " " + _key + "=0"]}},
       {"grub": {"default_cmdline_linux": args_without(_arg)}}, {"grub": {"kernel_args": []}}],
      f"every boot entry (grubby --info=ALL, args) and GRUB_CMDLINE_LINUX in /etc/default/grub must carry {_arg}"
      + (f", or {_what} (input.attest.{_att})" if _att else ""),
      f'{_fix}: grubby --update-kernel=ALL --args="{_arg}" and add {_arg} to GRUB_CMDLINE_LINUX in /etc/default/grub',
      comment=f"{_arg} in every boot entry's args (grubby --info=ALL) and in the uncommented GRUB_CMDLINE_LINUX of /etc/default/grub",
      **_extra)

R("configuration_management", "RHEL-09-212045", "init_on_free_enabled",
  [("grub", "default_cmdline_linux")],
  [['_grub_default_has("init_on_free=1")']],
  {"grub": {"default_cmdline_linux": ARGS_OK}},
  [{"grub": {"default_cmdline_linux": args_without("init_on_free=1")}},
   {"grub": {"default_cmdline_linux": args_without("init_on_free=1") + " init_on_free=0"}}],
  "GRUB_CMDLINE_LINUX in /etc/default/grub must carry init_on_free=1 (uncommented)",
  'Enable init_on_free: grubby --update-kernel=ALL --args="init_on_free=1", then grub2-mkconfig -o /boot/grub2/grub.cfg and reboot',
  comment="the uncommented GRUB_CMDLINE_LINUX value of /etc/default/grub (null when missing or commented out)")


# ── kernel parameters and modules ───────────────────────────────────────────────────────────────
sysctl_rule("configuration_management", "RHEL-09-213025", "kptr_restricted", "kernel.kptr_restrict", "1", ["0", "2"],
            "kernel.kptr_restrict must be 1", "Set kernel.kptr_restrict = 1 in /etc/sysctl.d/99-kernel_kptr_restrict.conf and run sysctl --system")
sysctl_rule("configuration_management", "RHEL-09-213030", "protected_hardlinks", "fs.protected_hardlinks", "1", ["0"],
            "fs.protected_hardlinks must be 1", "Set fs.protected_hardlinks = 1 in /etc/sysctl.d/99-fs_protected_hardlinks.conf and run sysctl --system")
sysctl_rule("configuration_management", "RHEL-09-213035", "protected_symlinks", "fs.protected_symlinks", "1", ["0"],
            "fs.protected_symlinks must be 1", "Set fs.protected_symlinks = 1 in /etc/sysctl.d/99-fs_protected_symlinks.conf and run sysctl --system")
sysctl_rule("configuration_management", "RHEL-09-213080", "ptrace_restricted", "kernel.yama.ptrace_scope", "1", ["0", "2"],
            "kernel.yama.ptrace_scope must be 1", "Set kernel.yama.ptrace_scope = 1 in /etc/sysctl.d/99-kernel_yama.ptrace_scope.conf and run sysctl --system")
sysctl_rule("configuration_management", "RHEL-09-213105", "user_namespaces_disabled", "user.max_user_namespaces", "0", ["1", "31231"],
            "user.max_user_namespaces must be 0, or the use of namespaces must be operationally required and documented with the ISSM "
            "(input.attest.rhel_09_213105_namespaces_documented)",
            "Set user.max_user_namespaces = 0 in /etc/sysctl.d/99-user_max_user_namespaces.conf and run sysctl --system",
            attest_alts=[['_attested("rhel_09_213105_namespaces_documented")']],
            pass_cases=[{"kernel_params": {"user.max_user_namespaces": 0}},
                        {"kernel_params": {"user.max_user_namespaces": "31231"}, "attest": {"rhel_09_213105_namespaces_documented": True}}])

CORE_OFF = "|/bin/false"
CORE_ON = "|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h"
R("configuration_management", "RHEL-09-213040", "core_pattern_disabled",
  [("kernel_params", "kernel.core_pattern")],
  [['_str(["kernel_params", "kernel.core_pattern"]) == "|/bin/false"']],
  {"kernel_params": {"kernel.core_pattern": CORE_OFF}},
  [{"kernel_params": {"kernel.core_pattern": CORE_ON}}, {"kernel_params": {"kernel.core_pattern": "core"}}],
  "kernel.core_pattern must be |/bin/false, or the need for core dumps must be documented with the ISSO as an operational "
  "requirement (input.attest.rhel_09_213040_core_dumps_documented)",
  "Set kernel.core_pattern = |/bin/false in /etc/sysctl.d/99-kernel_core_pattern.conf and run sysctl --system",
  comment="runtime kernel.core_pattern (sysctl)",
  attest_alts=[['_attested("rhel_09_213040_core_dumps_documented")']],
  pass_cases=[{"kernel_params": {"kernel.core_pattern": CORE_ON}, "attest": {"rhel_09_213040_core_dumps_documented": True}}])

module_rule("configuration_management", "RHEL-09-213045", "atm_disabled", "atm", "rhel_09_213045_atm_documented")
module_rule("configuration_management", "RHEL-09-213050", "can_disabled", "can", "rhel_09_213050_can_documented")
module_rule("configuration_management", "RHEL-09-213060", "sctp_disabled", "sctp", "rhel_09_213060_sctp_documented")
module_rule("configuration_management", "RHEL-09-213065", "tipc_disabled", "tipc", "rhel_09_213065_tipc_documented")


# ── core dumps: Not Applicable when kernel dumps are disabled per RHEL-09-213040 (kernel.core_pattern = |/bin/false) ──
# The module's green fixture holds that Not Applicable state (green_na); each rule's own pass fixture sets a live
# core_pattern on top, so its pass, fail and evidence-missing tests exercise the check itself.
CORE_NA = dict(na=[['_str(["kernel_params", "kernel.core_pattern"]) == "|/bin/false"']],
               na_expect="kernel dumps are disabled in accordance with RHEL-09-213040 (kernel.core_pattern is |/bin/false)")
CORE_LIVE = {"kernel_params": {"kernel.core_pattern": CORE_ON}}


def core_na(sid):
    RULES[sid]["green_na"] = {"kernel_params": {"kernel.core_pattern": CORE_OFF}}


for _sid, _name, _key, _want, _bad in (("RHEL-09-213085", "coredump_backtraces_disabled", "ProcessSizeMax", "0", ["1", "2G"]),
                                       ("RHEL-09-213090", "coredump_storage_none", "Storage", "none", ["external", "journal"])):
    _att = f"rhel_09_{_sid[-6:]}_core_dumps_documented"
    R("configuration_management", _sid, _name, [("coredump_conf", _key)],
      [[f'_str(["coredump_conf", "{_key}"]) == "{_want}"']],
      dict(CORE_LIVE, coredump_conf={_key: _want}),
      [{"coredump_conf": {_key: b}} for b in _bad],
      f"{_key} in /etc/systemd/coredump.conf must be {_want} (uncommented), or the need for core dumps must be documented with "
      f"the ISSO as an operational requirement (input.attest.{_att})",
      f"Set {_key}={_want} in /etc/systemd/coredump.conf",
      comment=f"{_key} as configured in /etc/systemd/coredump.conf (grep -i; null when missing or commented out)",
      attest_alts=[[f'_attested("{_att}")']],
      pass_cases=[{"coredump_conf": {_key: _bad[0]}, "attest": {_att: True}}],
      na_cases=[{"coredump_conf": {_key: _bad[0]}}], **CORE_NA)
    core_na(_sid)

helpers("configuration_management", r'''
# every uncommented "core" line of /etc/security/limits.conf and limits.d/*.conf (input.limits_conf.core:
# [{domain, type, value}]) sets the value 0
_core_limits_all_zero if {
	xs := input.limits_conf.core
	is_array(xs)
	every x in xs {
		sprintf("%v", [x.value]) == "0"
	}
}''')

R("configuration_management", "RHEL-09-213095", "core_dumps_limited",
  [("limits_conf", "core")],
  [["count(input.limits_conf.core) > 0", "_core_limits_all_zero"]],
  dict(CORE_LIVE, limits_conf={"core": [{"domain": "*", "type": "hard", "value": "0"}]}),
  [{"limits_conf": {"core": []}},
   {"limits_conf": {"core": [{"domain": "*", "type": "hard", "value": "unlimited"}]}},
   {"limits_conf": {"core": [{"domain": "*", "type": "hard", "value": "0"}, {"domain": "@developers", "type": "soft", "value": "100000"}]}},
   {"limits_conf": {"core": [{"domain": "*", "type": "hard", "value": "0"}, {"domain": "@developers", "type": "soft", "value": "100000"}]},
    "attest": {"rhel_09_213095_core_dumps_documented": True}}],
  "/etc/security/limits.conf or limits.d/*.conf must carry an uncommented core item and every core item must be 0; a missing "
  "item is accepted only when the need for core dumps is documented with the ISSO (input.attest.rhel_09_213095_core_dumps_documented), "
  "and an entry with another value is a finding either way",
  "Add '* hard core 0' to /etc/security/limits.conf (or one file in limits.d/) and remove entries with another value",
  comment="uncommented core items found by grep -rs core /etc/security/limits.conf /etc/security/limits.d/*.conf: [{domain, type, value}]",
  attest_alts=[['_attested("rhel_09_213095_core_dumps_documented")', "_core_limits_all_zero"]],
  pass_cases=[{"limits_conf": {"core": [{"domain": "*", "type": "hard", "value": 0}, {"domain": "@ops", "type": "soft", "value": "0"}]}},
              {"limits_conf": {"core": []}, "attest": {"rhel_09_213095_core_dumps_documented": True}}],
  na_cases=[{"limits_conf": {"core": []}}], **CORE_NA)
core_na("RHEL-09-213095")

unit_masked_rule("configuration_management", "RHEL-09-213100", "coredump_socket_masked", "systemd-coredump.socket",
                 "Mask the socket: systemctl mask --now systemd-coredump.socket && systemctl daemon-reload",
                 att="rhel_09_213100_core_dumps_documented",
                 what="the need for core dumps must be documented with the ISSO as an operational requirement",
                 na_cases=[{"systemd_units": {"systemd-coredump.socket": {"load_state": "loaded"}}}], **CORE_NA)
RULES["RHEL-09-213100"]["green"] = dict(CORE_LIVE, **RULES["RHEL-09-213100"]["green"])
core_na("RHEL-09-213100")

R("configuration_management", "RHEL-09-213110", "nx_enabled",
  [("cpuinfo", "flags"), ("grub", "kernel_args")],
  [["flags := input.cpuinfo.flags", "is_array(flags)", "count(flags) > 0",
    "every f in flags {\n\tis_string(f)\n\tregex.match(`[^[:alnum:]]nx([^[:alnum:]]|$)`, f)\n}",
    "args := input.grub.kernel_args", "is_array(args)", "count(args) > 0",
    "every a in args {\n\tis_string(a)\n\tnot regex.match(`(^|[^[:alnum:]])noexec([^[:alnum:]]|$)`, a)\n}"]],
  {"cpuinfo": {"flags": ["flags : fpu vme de pse nx lm", "flags : fpu vme de pse nx lm"]},
   "grub": {"kernel_args": [ARGS_OK, ARGS_OK]}},
  [{"cpuinfo": {"flags": ["flags : fpu vme de pse nx lm", "flags : fpu vme de pse lm"]}},
   {"cpuinfo": {"flags": ["flags : fpu vme de pse nxt lm"]}}, {"cpuinfo": {"flags": []}},
   {"grub": {"kernel_args": [ARGS_OK, ARGS_OK + " noexec=off"]}}, {"grub": {"kernel_args": []}}],
  "every flags line of /proc/cpuinfo must carry nx, and no boot entry (grubby --info=ALL, args) may carry noexec",
  "Enable NX/XD in the BIOS or UEFI, and remove the argument: grubby --update-kernel=ALL --remove-args=noexec",
  comment="input.cpuinfo.flags: the flags lines of /proc/cpuinfo (grep ^flags), one string per processor; input.grub.kernel_args as above",
  pass_cases=[{"cpuinfo": {"flags": ["flags\t\t: fpu vme nx"]}, "grub": {"kernel_args": [ARGS_OK + " noexec32=off"]}}])

R("services", "RHEL-09-213115", "kdump_disabled",
  [("systemd_units", "kdump.service", "load_state"), ("services", "kdump")],
  [['_kw(["systemd_units", "kdump.service", "load_state"]) == "masked"'],
   ['_kw(["systemd_units", "kdump.service", "load_state"]) == "not-found"', '_kw(["services", "kdump"]) != "active"']],
  {"systemd_units": {"kdump.service": {"load_state": "masked"}}, "services": {"kdump": "inactive"}},
  [{"systemd_units": {"kdump.service": {"load_state": "loaded"}}},
   {"systemd_units": {"kdump.service": {"load_state": "loaded"}}, "services": {"kdump": "active"}},
   {"systemd_units": {"kdump.service": {"load_state": "not-found"}}, "services": {"kdump": "active"}}],
  "kdump.service must be masked (systemctl show kdump: LoadState=masked); a service that is loaded or active and not masked is a finding",
  "Disable and mask the service: systemctl disable --now kdump && systemctl mask --now kdump",
  comment="LoadState of kdump.service (systemctl show kdump) and systemctl is-active kdump",
  pass_cases=[{"systemd_units": {"kdump.service": {"load_state": "not-found"}}, "services": {"kdump": "inactive"}},
              {"services": {"kdump": "masked"}}])


# ── dnf and package integrity ───────────────────────────────────────────────────────────────────
R("software_integrity", "RHEL-09-214015", "dnf_gpgcheck",
  [("dnf_config", "gpgcheck")],
  [["_truthy(input.dnf_config.gpgcheck)"]],
  {"dnf_config": {"gpgcheck": "1"}},
  [{"dnf_config": {"gpgcheck": "0"}}, {"dnf_config": {"gpgcheck": "False"}}],
  "gpgcheck in /etc/dnf/dnf.conf must be 1, true or yes, or an approved GPG verification process must be attested "
  "(input.attest.rhel_09_214015_gpg_process)",
  "Set gpgcheck=1 in the [main] section of /etc/dnf/dnf.conf",
  comment="gpgcheck as written in /etc/dnf/dnf.conf (grep -w gpgcheck; null when missing or commented out)",
  attest_alts=[['_attested("rhel_09_214015_gpg_process")']],
  pass_cases=[{"dnf_config": {"gpgcheck": "True"}}, {"dnf_config": {"gpgcheck": "yes"}},
              {"dnf_config": {"gpgcheck": "0"}, "attest": {"rhel_09_214015_gpg_process": True}}])

R("software_integrity", "RHEL-09-214030", "rpm_hashes_match",
  [("rpm_verify", "hash_mismatch_files")],
  [["xs := input.rpm_verify.hash_mismatch_files", "is_array(xs)", "count(xs) == 0"]],
  {"rpm_verify": {"hash_mismatch_files": []}},
  [{"rpm_verify": {"hash_mismatch_files": ["S.5....T.    /usr/bin/znew"]}}],
  "rpm -Va --noconfig must report no non-configuration file whose hash differs from the RPM database",
  "Reinstall the package that owns each listed file: dnf provides <file>, then dnf -y reinstall <package>",
  comment="output lines of rpm -Va --noconfig | awk '$1 ~ /..5/ && $2 != \"c\"'")

R("software_integrity", "RHEL-09-214035", "dnf_clean_requirements",
  [("dnf_config", "clean_requirements_on_remove")],
  [["_truthy(input.dnf_config.clean_requirements_on_remove)"]],
  {"dnf_config": {"clean_requirements_on_remove": "True"}},
  [{"dnf_config": {"clean_requirements_on_remove": "0"}}, {"dnf_config": {"clean_requirements_on_remove": "False"}}],
  "clean_requirements_on_remove in /etc/dnf/dnf.conf must be 1, true or yes",
  "Set clean_requirements_on_remove=True in /etc/dnf/dnf.conf",
  comment="clean_requirements_on_remove as written in /etc/dnf/dnf.conf (grep -i; null when missing or commented out)",
  pass_cases=[{"dnf_config": {"clean_requirements_on_remove": "1"}}, {"dnf_config": {"clean_requirements_on_remove": "YES"}}])

R("software_integrity", "RHEL-09-215035", "no_epel_repository",
  [("dnf_repolist",)],
  [["repos := input.dnf_repolist", "is_array(repos)",
    'count([r | some r in repos; contains(lower(sprintf("%v %v", [object.get(r, "id", ""), object.get(r, "name", "")])), "epel")]) == 0']],
  {"dnf_repolist": [{"id": "rhel-9-for-x86_64-appstream-rpms", "name": "Red Hat Enterprise Linux 9 for x86_64 - AppStream (RPMs)"},
                    {"id": "rhel-9-for-x86_64-baseos-rpms", "name": "Red Hat Enterprise Linux 9 for x86_64 - BaseOS (RPMs)"}]},
  [{"dnf_repolist": [{"id": "epel", "name": "Extra Packages for Enterprise Linux 9 - x86_64"}]},
   {"dnf_repolist": [{"id": "local-mirror", "name": "EPEL 9 mirror"}]}],
  "dnf repolist must show no repository with epel in its id or name",
  "Remove the repository: dnf remove epel-release, and dnf config-manager --set-disabled epel",
  comment="the repositories printed by dnf repolist: [{id, name}] (the enabled ones; not the .repo files, which also list disabled repositories)",
  pass_cases=[{"dnf_repolist": []}])


def pkg_rule(sec, sid, name, pkg, installed, att=None, what="", na_att=None, na_expect="", fix=None):
    """a package that must (installed=True) or must not be installed; att: the check's documented-with-the-ISSO clause;
    na_att: the check's Not Applicable note, a fact only the organization can state"""
    p = f'input.packages["{pkg}"]' if "-" in pkg else f"input.packages.{pkg}"
    kw = {}
    if att:
        kw.update(attest_alts=[[f'_attested("{att}")']],
                  pass_cases=[{"packages": {pkg: not installed}, "attest": {att: True}}])
    if na_att:
        kw.update(na=[[f'_attested("{na_att}")']], na_expect=na_expect,
                  na_cases=[{"packages": {pkg: not installed}, "attest": {na_att: True}}])
    R(sec, sid, name, [("packages", pkg)], [[f"{p} == {'true' if installed else 'false'}"]],
      {"packages": {pkg: installed}}, [{"packages": {pkg: not installed}}],
      f"the {pkg} package must {'' if installed else 'not '}be installed" + (f", or {what} (input.attest.{att})" if att else ""),
      fix or (f"Install the package: dnf install {pkg}" if installed else f"Remove the package: dnf remove {pkg}"),
      comment=f"the {pkg} package must {'' if installed else 'not '}be installed (dnf list --installed {pkg})"
      + (f"; Not Applicable on input.attest.{na_att}" if na_att else ""), **kw)


ISSO = "its use must be documented with the ISSO as an operational requirement"
pkg_rule("software_integrity", "RHEL-09-215010", "subscription_manager_installed", "subscription-manager", True,
         na_att="rhel_09_215010_not_internet_connected", na_expect="the system is not an internet connected system")
pkg_rule("services", "RHEL-09-215020", "sendmail_absent", "sendmail", False)
pkg_rule("services", "RHEL-09-215045", "gssproxy_absent", "gssproxy", False, att="rhel_09_215045_gssproxy_documented", what=ISSO,
         na_att="rhel_09_215045_nfs_authorized", na_expect="NFS mounts are authorized and in use on the system")
pkg_rule("services", "RHEL-09-215050", "iprutils_absent", "iprutils", False, att="rhel_09_215050_iprutils_documented", what=ISSO)
pkg_rule("services", "RHEL-09-215055", "tuned_absent", "tuned", False, att="rhel_09_215055_tuned_documented", what=ISSO)
pkg_rule("services", "RHEL-09-215070", "graphical_display_manager_absent", "xorg-x11-server-common", False,
         att="rhel_09_215070_gui_documented",
         what="the use of a graphical user interface must be documented with the ISSO as an operational requirement",
         fix='Remove the xorg packages (dnf remove "xorg*") and set the default target: systemctl set-default multi-user.target')
_m = alt_mfa("RHEL-09-215075")
pkg_rule("pki_crypto", "RHEL-09-215075", "openssl_pkcs11_installed", "openssl-pkcs11", True,
         na_att=_m["na_key"], na_expect=_m["na_expect"])
pkg_rule("pki_crypto", "RHEL-09-215080", "gnutls_utils_installed", "gnutls-utils", True)
pkg_rule("pki_crypto", "RHEL-09-215085", "nss_tools_installed", "nss-tools", True)
pkg_rule("software_integrity", "RHEL-09-215090", "rng_tools_installed", "rng-tools", True)
pkg_rule("software_integrity", "RHEL-09-215095", "s_nail_installed", "s-nail", True)
pkg_rule("pki_crypto", "RHEL-09-215100", "crypto_policies_installed", "crypto-policies", True)
pkg_rule("software_integrity", "RHEL-09-215101", "postfix_installed", "postfix", True,
         na_att="rhel_09_215101_other_notification",
         na_expect="the admin demonstrated another system or service that sends audit failure notifications to the administrator / ISSO")


# ── file systems (the mount table and /etc/fstab) ───────────────────────────────────────────────
# MOUNTS is the section's one green mount table (every rule's fixture is the same list); the mount points these
# rules read are added to it in place, each once.
def ensure_mount(point, device, fstype):
    if not any(m["mount"] == point for m in MOUNTS):
        MOUNTS.append({"mount": point, "device": device, "fstype": fstype, "options": ["rw", "nodev", "nosuid", "noexec"]})


ensure_mount("/var", "/dev/mapper/rhel-var", "xfs")
ensure_mount("/var/tmp", "/dev/mapper/rhel-var_tmp", "xfs")
ensure_mount("/boot", "/dev/sda2", "xfs")
ensure_mount("/boot/efi", "/dev/sda1", "vfat")
ensure_mount("/dev/shm", "tmpfs", "tmpfs")


def mounts_without(point):
    return [m for m in MOUNTS if m["mount"] != point]


def mount_with(point, options, fstype=None):
    m = dict(next(m for m in MOUNTS if m["mount"] == point), options=options)
    if fstype:
        m["fstype"] = fstype
    return mounts_without(point) + [m]


for _sid, _name, _point in (("RHEL-09-231010", "home_separate", "/home"), ("RHEL-09-231020", "var_separate", "/var"),
                            ("RHEL-09-231035", "var_tmp_separate", "/var/tmp")):
    R("configuration_management", _sid, _name, [("filesystem_mounts",)], [[f'_mount("{_point}")']],
      {"filesystem_mounts": MOUNTS}, [{"filesystem_mounts": mounts_without(_point)}],
      f"a separate file system must be mounted on {_point}", f"Migrate {_point} onto a separate file system and mount it in /etc/fstab",
      comment=f"the mount table (mount / findmnt): a separate entry for {_point}")

for _sid, _name, _point, _opt in (("RHEL-09-231095", "boot_nodev", "/boot", "nodev"), ("RHEL-09-231100", "boot_nosuid", "/boot", "nosuid"),
                                  ("RHEL-09-231110", "dev_shm_nodev", "/dev/shm", "nodev"), ("RHEL-09-231115", "dev_shm_noexec", "/dev/shm", "noexec"),
                                  ("RHEL-09-231120", "dev_shm_nosuid", "/dev/shm", "nosuid"),
                                  ("RHEL-09-231125", "tmp_nodev", "/tmp", "nodev"), ("RHEL-09-231130", "tmp_noexec", "/tmp", "noexec"),
                                  ("RHEL-09-231135", "tmp_nosuid", "/tmp", "nosuid"),
                                  ("RHEL-09-231140", "var_nodev", "/var", "nodev"), ("RHEL-09-231145", "var_log_nodev", "/var/log", "nodev")):
    R("configuration_management", _sid, _name, [("filesystem_mounts",)],
      [[f'm := _mount("{_point}")', f'"{_opt}" in m.options']],
      {"filesystem_mounts": MOUNTS},
      [{"filesystem_mounts": mount_with(_point, [o for o in ["rw", "nodev", "nosuid", "noexec"] if o != _opt])},
       {"filesystem_mounts": mounts_without(_point)}],
      f"{_point} must be mounted with the {_opt} option (no {_point} entry in the mount table is a finding)",
      f"Add {_opt} to the {_point} options in /etc/fstab and remount",
      comment=f"the {_point} entry of the mount table (mount / findmnt) must carry {_opt}")

R("configuration_management", "RHEL-09-231105", "boot_efi_nosuid", [("filesystem_mounts",)],
  [['m := _mount("/boot/efi")', '"nosuid" in m.options']],
  {"filesystem_mounts": MOUNTS},
  [{"filesystem_mounts": mount_with("/boot/efi", ["rw", "relatime"], fstype="ext4")},
   {"filesystem_mounts": mounts_without("/boot/efi")}],
  "/boot/efi must be mounted with the nosuid option",
  "Add nosuid to the /boot/efi options in /etc/fstab and remount",
  comment="the /boot/efi entry of the mount table; a BIOS system (input.boot_firmware) or a vfat /boot/efi is Not Applicable",
  na=[['_kw(["boot_firmware"]) == "bios"'], ['m := _mount("/boot/efi")', "is_string(m.fstype)", 'lower(m.fstype) == "vfat"']],
  na_expect="the system uses BIOS, or /boot/efi is a vfat file system",
  na_cases=[{"filesystem_mounts": mounts_without("/boot/efi"), "boot_firmware": "bios"},
            {"filesystem_mounts": mount_with("/boot/efi", ["rw", "relatime"])}])

helpers("configuration_management", r'''
# the NFS entries of /etc/fstab (input.fstab: [{mount_point, fs_type, options}], uncommented entries; fs_type nfs / nfs4)
_fstab_nfs := [e | some e in input.fstab; is_string(e.fs_type); startswith(lower(e.fs_type), "nfs")]

# an fstab entry carries the mount option (options: the comma-separated fourth field)
_fstab_has_opt(e, opt) if {
	is_string(e.options)
	opt in {trim_space(x) | some x in split(e.options, ",")}
}''')

FSTAB9 = [{"mount_point": "/", "fs_type": "xfs", "options": "defaults"},
          {"mount_point": "/data", "fs_type": "nfs4", "options": "rw,nosuid,nodev,noexec,sync,soft,sec=krb5:krb5i:krb5p"}]
REMOVABLE = [{"mount_point": "/mnt/usbflash", "fs_type": "vfat", "options": "noauto,owner,ro,nosuid,nodev,noexec"}]


def opts_without(entry, opt):
    return dict(entry, options=",".join(o for o in entry["options"].split(",") if o != opt))


for _sid, _name, _opt in (("RHEL-09-231065", "nfs_nodev", "nodev"), ("RHEL-09-231070", "nfs_noexec", "noexec"),
                          ("RHEL-09-231075", "nfs_nosuid", "nosuid")):
    R("configuration_management", _sid, _name, [("fstab",)],
      [["is_array(input.fstab)", "count(_fstab_nfs) > 0", f'every e in _fstab_nfs {{\n\t_fstab_has_opt(e, "{_opt}")\n}}']],
      {"fstab": FSTAB9},
      [{"fstab": [FSTAB9[0], opts_without(FSTAB9[1], _opt)]},
       {"fstab": FSTAB9 + [{"mount_point": "/srv/share", "fs_type": "nfs", "options": "rw,sync"}]}],
      f"every NFS entry in /etc/fstab must carry the {_opt} option",
      f"Add {_opt} to the options of every NFS file system in /etc/fstab",
      comment=f"NFS entries of /etc/fstab (grep nfs /etc/fstab) must carry {_opt}; no NFS entry is Not Applicable",
      na=[["is_array(input.fstab)", "count(_fstab_nfs) == 0"]], na_expect="no NFS mounts are configured in /etc/fstab",
      na_cases=[{"fstab": [FSTAB9[0]]}])

for _sid, _name, _opt in (("RHEL-09-231080", "removable_media_noexec", "noexec"), ("RHEL-09-231085", "removable_media_nodev", "nodev"),
                          ("RHEL-09-231090", "removable_media_nosuid", "nosuid")):
    R("configuration_management", _sid, _name, [("removable_media_fstab",)],
      [["es := input.removable_media_fstab", "is_array(es)", f'every e in es {{\n\t_fstab_has_opt(e, "{_opt}")\n}}']],
      {"removable_media_fstab": REMOVABLE},
      [{"removable_media_fstab": [opts_without(REMOVABLE[0], _opt)]},
       {"removable_media_fstab": REMOVABLE + [{"mount_point": "/mnt/cdrom", "fs_type": "iso9660", "options": "noauto,ro"}]}],
      f"every /etc/fstab file system that refers to removable media must carry the {_opt} option",
      f"Add {_opt} to the /etc/fstab options of every file system associated with removable media",
      comment="input.removable_media_fstab: the /etc/fstab entries that refer to removable media (USB, optical, flash), "
              f"[{{mount_point, fs_type, options}}]; each must carry {_opt}; none is a pass",
      pass_cases=[{"removable_media_fstab": []}])
