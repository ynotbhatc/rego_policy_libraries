#!/usr/bin/env python3
"""CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0: every recommendation, from the benchmark's own workbook.

    python3 tools/cis_generators/gen_ubuntu_22_04.py CIS_Ubuntu_Linux_22.04_LTS_Benchmark_v3.0.0.xlsx [fields.json]

Needs openpyxl. The workbook is CIS-licensed and is never committed. Writes benchmarks/cis/ubuntu_22_04/ in the
ubuntu_24_04 layout (cis_ubuntu_22_04.<section>, roll-up cis_ubuntu_22_04, bridge cis_ubuntu_22_04.main) and
formats the files it wrote with `opa fmt`. It replaces the earlier hand-written module of that directory; the
framework-key bridge cis_ubuntu_2204_key_main.rego and the README are hand-written and are not touched.

The reader, the Spec builders, the Rego helpers and the emitters are gen_ubuntu_26_04.py's, and the logic table
is gen_ubuntu_24_04.py's (both imported, not copied). This file holds only the 22.04 table:

  * SAME      22.04 ids whose audit procedure was compared, text against text, with the 24.04 one of the same id;
  * RENUMBER  22.04 id -> 24.04 id for the same audit procedure under another number;
  * put(...)  logic written here from the 22.04 audit procedure where it differs (or is not in 24.04).

Every entry carries a title keyword checked against the 22.04 workbook title, so logic cannot attach to a
renumbered recommendation: the run aborts on any count, id, Automated/Manual status or keyword mismatch.
"""
import copy
import json
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen_ubuntu_26_04 as base  # noqa: E402
import gen_ubuntu_24_04 as u24  # noqa: E402
from gen_ubuntu_26_04 import (AR, SU, attest, custom, dotted, nest, not_in_use, pkg_absent,  # noqa: E402
                              pkg_present, ref)

PKG = "cis_ubuntu_22_04"
GEN = "tools/cis_generators/gen_ubuntu_22_04.py"
BENCH = "CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0"
VERSION = "v3.0.0"
EXPECTED_TOTAL, EXPECTED_AUTOMATED, EXPECTED_MANUAL = 306, 290, 16
OUT = HERE.parent.parent / "benchmarks" / "cis" / "ubuntu_22_04"

L, KW, USED = {}, {}, {}


def retag(x):
    """test fixtures of a carried entry name the release in banner text"""
    if isinstance(x, dict):
        return {k: retag(v) for k, v in x.items()}
    if isinstance(x, list):
        return [retag(v) for v in x]
    if isinstance(x, str):
        return x.replace("24.04", "22.04").replace("26.04", "22.04")
    return x


def put(rid, kw, spec):
    if rid in L:
        raise SystemExit(f"{rid} defined twice")
    L[rid], KW[rid] = spec, kw
    return spec


def take(rid, src_id=None, kw=None, table="24"):
    """The 24.04 (or 26.04) logic of src_id (default: the same id), deep-copied, with its title keyword."""
    src_id = src_id or rid
    lt, kt = (u24.L, u24.KW) if table == "24" else (base.L, base.KW)
    if src_id not in lt:
        raise SystemExit(f"{rid}: the {table}.04 table has no logic for {src_id}")
    if (table, src_id) in USED:
        raise SystemExit(f"{rid}: {table}.04 {src_id} already used by {USED[(table, src_id)]}")
    USED[(table, src_id)] = rid
    spec = copy.deepcopy(lt[src_id])
    if not spec.manual:
        spec.tp, spec.tf, spec.tm = retag(spec.tp), retag(spec.tf), retag(spec.tm)
    return put(rid, kw or kt[src_id], spec)


# ════════════════════════════════════════════════════════════════════════════════════════════
# 22.04 ids whose audit procedure is the 24.04 one of the same id (compared text against text; differences
# are wording, notes or shell quoting only)
# ════════════════════════════════════════════════════════════════════════════════════════════
SAME = """
1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 1.1.1.5 1.1.1.6 1.1.1.7 1.1.1.8
1.1.2.1.1 1.1.2.1.2 1.1.2.1.3 1.1.2.1.4 1.1.2.2.1 1.1.2.2.2 1.1.2.2.3 1.1.2.2.4 1.1.2.3.1 1.1.2.3.2 1.1.2.3.3
1.1.2.4.1 1.1.2.4.2 1.1.2.4.3 1.1.2.5.1 1.1.2.5.2 1.1.2.5.3 1.1.2.5.4 1.1.2.6.1 1.1.2.6.2 1.1.2.6.3 1.1.2.6.4
1.1.2.7.1 1.1.2.7.2 1.1.2.7.3 1.1.2.7.4 1.2.2.1 1.3.1.1 1.3.1.2 1.4.1 1.4.2 1.6.2 1.6.3
2.1.1 2.2.1 2.2.2 2.2.3 2.2.5 2.2.6 2.3.1.1 2.3.2.1 2.3.2.2 2.3.3.1 2.3.3.2 2.3.3.3
2.4.1.1 2.4.1.2 2.4.1.3 2.4.1.4 2.4.1.5 2.4.1.6 2.4.1.7 2.4.1.8 2.4.1.9 2.4.2.1 3.1.1 3.1.2 3.1.3
3.3.1.1 3.3.1.2 3.3.1.3 3.3.1.4 3.3.1.5 3.3.1.6 3.3.1.7 3.3.1.8 3.3.1.9 3.3.1.10 3.3.1.11 3.3.1.12 3.3.1.13
3.3.1.14 3.3.1.15 3.3.1.16 3.3.1.17 3.3.1.18 3.3.2.1 3.3.2.2 3.3.2.3 3.3.2.4 3.3.2.5 3.3.2.6 3.3.2.7 3.3.2.8
4.1.1 4.1.2 4.1.3 4.1.4 4.1.5
5.1.1 5.1.2 5.1.3 5.1.4 5.1.5 5.1.6 5.1.7 5.1.8 5.1.9 5.1.10 5.1.11 5.1.12 5.1.13 5.1.14 5.1.15 5.1.16
5.1.19 5.1.20 5.1.21 5.1.22 5.2.1 5.2.2 5.2.3 5.2.4 5.2.5 5.2.6 5.2.7
5.3.1.1 5.3.1.2 5.3.1.3 5.3.2.1 5.3.2.2 5.3.2.3 5.3.2.4 5.3.3.1.1 5.3.3.1.2 5.3.3.1.3
5.3.3.2.1 5.3.3.2.2 5.3.3.2.3 5.3.3.2.4 5.3.3.2.5 5.3.3.2.6 5.3.3.2.7 5.3.3.2.8
5.3.3.4.1 5.3.3.4.2 5.3.3.4.3 5.3.3.4.4 5.4.1.1 5.4.1.2 5.4.1.3 5.4.1.4 5.4.1.5 5.4.1.6
5.4.2.1 5.4.2.2 5.4.2.3 5.4.2.4 5.4.2.5 5.4.2.6 5.4.2.7 5.4.2.8 5.4.3.1 5.4.3.2 5.4.3.3
6.1.1.1.1 6.1.3.1 6.2.1.1 6.2.1.2 6.2.1.3 6.2.1.4 6.2.2.1 6.2.2.2 6.2.2.3 6.2.2.4
6.2.4.5 6.2.4.6 6.2.4.7 6.2.4.8 6.2.4.9 6.2.4.10 6.3.1 6.3.3
7.1.1 7.1.2 7.1.3 7.1.4 7.1.5 7.1.6 7.1.7 7.1.9 7.1.10 7.1.11 7.1.12 7.1.13
7.2.1 7.2.2 7.2.3 7.2.4 7.2.5 7.2.6 7.2.7 7.2.8 7.2.9 7.2.10
""".split()
for _rid in SAME:
    take(_rid)

# 22.04 id -> (24.04 id, keyword override or None): the same audit procedure under another number
RENUMBER = {
    "1.1.1.9": ("1.1.1.10", None), "1.1.1.10": ("1.1.1.11", None), "1.1.1.11": ("1.1.1.9", None),
    "1.3.1.4": ("1.3.1.3", None),
    # the 22.04 titles name the parameter without its kernel./fs. prefix
    "1.5.1": ("1.5.9", "randomize_va_space"), "1.5.2": ("1.5.3", "ptrace_scope"), "1.5.3": ("1.5.4", "suid_dumpable"),
    "1.5.5": ("1.5.6", None), "1.5.6": ("1.5.7", None),
    "1.6.4": ("1.6.6", None), "1.6.5": ("1.6.7", None), "1.6.6": ("1.6.8", None),
    "1.7.10": ("1.7.6", None), "1.7.11": ("1.7.7", None),
    "2.1.2": ("2.1.3", None), "2.1.4": ("2.1.7", None), "2.1.5": ("2.1.9", None), "2.1.6": ("2.1.8", None),
    "2.1.7": ("2.1.10", None), "2.1.8": ("2.1.11", None), "2.1.9": ("2.1.12", None), "2.1.10": ("2.1.13", None),
    "2.1.11": ("2.1.14", None), "2.1.12": ("2.1.15", None), "2.1.13": ("2.1.16", None), "2.1.14": ("2.1.17", None),
    "2.1.15": ("2.1.18", None), "2.1.16": ("2.1.20", None), "2.1.17": ("2.1.21", None), "2.1.18": ("2.1.6", None),
    "2.1.19": ("2.1.22", None), "2.1.20": ("2.1.23", None), "2.1.21": ("2.1.2", None), "2.1.22": ("2.1.4", None),
    "3.2.1": ("3.2.3", None), "3.2.2": ("3.2.6", None), "3.2.3": ("3.2.4", None), "3.2.4": ("3.2.5", None),
    "5.1.17": ("5.1.18", None), "5.1.18": ("5.1.17", None),
    "6.1.1.1.2": ("6.1.1.1.4", None), "6.1.1.1.3": ("6.1.1.1.5", None), "6.1.1.1.5": ("6.1.1.1.6", None),
    "6.1.1.1.6": ("6.1.1.1.7", None), "6.1.1.2.4": ("6.1.1.1.2", None),
    "6.1.2.4": ("6.1.2.3", None), "6.1.2.5": ("6.1.2.4", None), "6.1.2.6": ("6.1.2.5", None),
    "6.1.2.7": ("6.1.2.6", None), "6.1.2.8": ("6.1.2.7", None),
    "6.2.3.20": ("6.2.3.29", None), "6.2.3.21": ("6.2.3.30", None),
    "6.2.4.1": ("6.2.4.2", None), "6.2.4.2": ("6.2.4.3", None), "6.2.4.3": ("6.2.4.4", None), "6.2.4.4": ("6.2.4.1", None),
}
for _rid, (_src, _kw) in RENUMBER.items():
    take(_rid, _src, _kw)

# 1.5.4: the 22.04 audit (a `* hard core 0` limit, no larger value) is the 26.04 one; 24.04 dropped it
take("1.5.4", "1.5.10", table="26")

# ════════════════════════════════════════════════════════════════════════════════════════════
# 22.04 logic: written from the 22.04 audit procedure
# ════════════════════════════════════════════════════════════════════════════════════════════
# 1.2.1.1 / 1.2.1.2: Manual in 22.04 (review apt-key / keyring files and `apt-cache policy` against site policy)
put("1.2.1.1", "GPG keys", attest("apt_gpg_keys_reviewed"))
put("1.2.1.2", "package manager repositories", attest("apt_repositories_reviewed"))

# 1.3.1.3: profiles loaded (> 0), every one in enforce or complain mode, and no unconfined process
APP, APR = "input.apparmor.profiles", "input.apparmor.processes"
_prof = {"loaded": 37, "enforce": 35, "complain": 2}
put("1.3.1.3", "not disabled", custom(
    [f'{APP}.loaded != null', f'{APP}.enforce != null', f'{APP}.complain != null', f'{APR}.unconfined != null'],
    [[f'num({APP}.loaded) > 0', f'num({APP}.enforce) + num({APP}.complain) == num({APP}.loaded)',
      f'num({APR}.unconfined) == 0']],
    "apparmor.profiles/apparmor.processes",
    {"apparmor": {"profiles": _prof, "processes": {"unconfined": 0}}},
    {"apparmor": {"profiles": dict(_prof, enforce=30), "processes": {"unconfined": 0}}},
    reads=[["apparmor", "profiles"], ["apparmor", "processes"]]))

# 1.6.1: /etc/motd and /etc/motd.d/* only (the 24.04 fact motd_extra_files also lists /run, /usr/lib and
# /etc/update-motd.d files; the 22.04 audit does not read those, so only /etc/motd.d/ entries are judged)
MEX, MCT, MXF = ["initial_setup", "motd_exists"], ["initial_setup", "motd_content"], ["initial_setup", "motd_extra_files"]
_extra_ok = (f'every f in [f | some f in {ref(MXF)}; startswith(f.path, "/etc/motd.d/")] {{ is_string(f.content); '
             f'not regex.match({json.dumps(base.SYSINFO)}, f.content) }}')
_s = put("1.6.1", "/etc/motd is configured", custom(
    None,
    [[f'{ref(MEX)} == false', _extra_ok],
     [f'{ref(MEX)} == true', f'not regex.match({json.dumps(base.SYSINFO)}, {ref(MCT)})', _extra_ok]],
    "initial_setup.motd_exists/motd_content/motd_extra_files",
    {"initial_setup": {"motd_exists": True, "motd_content": "Authorized uses only. All activity may be monitored.",
                       "motd_extra_files": [{"path": "/etc/motd.d/10-site", "content": "Authorized uses only."}]}},
    {"initial_setup": {"motd_exists": True, "motd_content": "Authorized uses only.",
                       "motd_extra_files": [{"path": "/etc/motd.d/10-site", "content": "Welcome to Ubuntu 22.04 LTS"}]}},
    {}, reads=[MEX, MCT, MXF],
    ev_alts=[[f'{ref(MEX)} == false', f'is_array({ref(MXF)})'],
             [f'{ref(MEX)} == true', f'is_string({ref(MCT)})', f'is_array({ref(MXF)})']]))
_s.hollow_ok = True   # an empty banner and an empty file list are real values

# 1.7 GDM. As in 24.04, a host without GDM (initial_setup.gdm_installed false) passes 1.7.2-1.7.11. The 22.04
# audits read the effective gsettings values after checking that a dconf profile with user-db/system-db exists
# (gdm_dconf_profile_exists), and the "not overridden" recommendations read the dconf lock files
# (gdm_dconf_locks: the active lines of /etc/dconf/db/*/locks/*).
I = "input.initial_setup."
PROF = I + "gdm_dconf_profile_exists == true"
put("1.7.1", "GDM is removed", custom(
    ['is_boolean(input.initial_setup.gdm_installed)'], [['input.initial_setup.gdm_installed == false']],
    "initial_setup.gdm_installed", {"initial_setup": {"gdm_installed": False}},
    {"initial_setup": {"gdm_installed": True}}, reads=[["initial_setup", "gdm_installed"]]))
_p = {"gdm_dconf_profile_exists": True}
put("1.7.2", "GDM login banner", base.gdm(["gdm_dconf_profile_exists", "gdm_banner_configured"],
    [PROF, I + "gdm_banner_configured == true"],
    dict(_p, gdm_banner_configured=True), dict(_p, gdm_banner_configured=False)))
put("1.7.3", "disable-user-list", base.gdm(["gdm_dconf_profile_exists", "gdm_disable_user_list"],
    [PROF, I + "gdm_disable_user_list == true"],
    dict(_p, gdm_disable_user_list=True), dict(_p, gdm_disable_user_list=False)))
_lk = {"gdm_idle_delay": 900, "gdm_lock_delay": 5, "gdm_lock_enabled": True}
put("1.7.4", "screen locks when the user is idle", base.gdm(
    ["gdm_dconf_profile_exists", "gdm_idle_delay", "gdm_lock_delay", "gdm_lock_enabled"],
    [PROF, f"num({I}gdm_idle_delay) > 0", f"num({I}gdm_idle_delay) <= 900",
     f"num({I}gdm_lock_delay) >= 0", f"num({I}gdm_lock_delay) <= 5", I + "gdm_lock_enabled == true"],
    dict(_p, **_lk), dict(_p, **dict(_lk, gdm_idle_delay=0))))


def gdm_locks(keys, good):
    return base.gdm(["gdm_dconf_locks"], [f'every k in {json.dumps(keys)} {{ gdm_locked(k) }}'],
                    {"gdm_dconf_locks": good}, {"gdm_dconf_locks": good[:-1]})


put("1.7.5", "screen locks cannot be overridden", gdm_locks(
    ["idle-delay", "lock-delay", "lock-enabled"],
    ["/org/gnome/desktop/session/idle-delay", "/org/gnome/desktop/screensaver/lock-delay",
     "/org/gnome/desktop/screensaver/lock-enabled"]))
put("1.7.6", "automatic mounting of removable media is disabled", base.gdm(
    ["gdm_dconf_profile_exists", "gdm_automount_disabled", "gdm_automount_open_disabled"],
    [PROF, I + "gdm_automount_disabled == true", I + "gdm_automount_open_disabled == true"],
    dict(_p, gdm_automount_disabled=True, gdm_automount_open_disabled=True),
    dict(_p, gdm_automount_disabled=True, gdm_automount_open_disabled=False)))
put("1.7.7", "is not overridden", gdm_locks(
    ["automount", "automount-open"],
    ["/org/gnome/desktop/media-handling/automount", "/org/gnome/desktop/media-handling/automount-open"]))
put("1.7.8", "autorun-never is enabled", base.gdm(["gdm_dconf_profile_exists", "gdm_autorun_never_enabled"],
    [PROF, I + "gdm_autorun_never_enabled == true"],
    dict(_p, gdm_autorun_never_enabled=True), dict(_p, gdm_autorun_never_enabled=False)))
put("1.7.9", "autorun-never is not overridden", gdm_locks(
    ["autorun-never"], ["/org/gnome/desktop/screensaver/lock-delay", "/org/gnome/desktop/media-handling/autorun-never"]))

# 2.1.3: the 22.04 audit names isc-dhcp-server and its two units
put("2.1.3", "dhcp server", not_in_use({"isc-dhcp-server": ["isc-dhcp-server.service", "isc-dhcp-server6.service"]}))
# 2.2.4: the 22.04 audit names the telnet package only
put("2.2.4", "telnet client", pkg_absent(["telnet"]))

# 5.3.3.3.1-3: the argument on the pam_pwhistory line of common-password (22.04 has no pwhistory.conf alternative)
PCP = ["pam", "common_password"]
PWH = "password requisite pam_pwhistory.so remember=24 enforce_for_root use_authtok"


def pwh22(cond, bad_line):
    return custom([f'is_string({ref(PCP)})'], [['count(pwhistory_lines) > 0', cond]], dotted(PCP),
                  nest(PCP, PWH), nest(PCP, bad_line), reads=[PCP])


put("5.3.3.3.1", "history remember", pwh22('every l in pwhistory_lines { pam_arg_num(l, "remember") >= 24 }',
                                           PWH.replace("24", "5")))
put("5.3.3.3.2", "history is enforced for the root", pwh22(
    'every l in pwhistory_lines { regex.match(`\\senforce_for_root(\\s|$)`, l) }', PWH.replace(" enforce_for_root", "")))
put("5.3.3.3.3", "pam_pwhistory includes use_authtok", pwh22(
    'every l in pwhistory_lines { regex.match(`\\suse_authtok(\\s|$)`, l) }', PWH.replace(" use_authtok", "")))

# 6.1 logging. 22.04 asks the site to pick journald or rsyslog: 6.1.1.1.4 (ForwardToSyslog not yes) and 6.1.2.3
# (ForwardToSyslog yes) cannot both hold. input.logging_method ("journald" | "rsyslog") declares the choice; a
# recommendation of the other method passes on that declaration. With no declaration every check is evaluated.
LM = ["logging_method"]


def for_method(spec, method):
    other = {"journald": "rsyslog", "rsyslog": "journald"}[method]
    g = f'input.logging_method == "{other}"'
    spec.ev_alts = spec.ev_alts + [[g]]
    spec.passes = spec.passes + [[g]]
    spec.reads = spec.reads + [LM]
    spec.field = f"{spec.field} (or logging_method)"
    return spec


FTS = "input.journald.forward_to_syslog"
put("6.1.1.1.4", "ForwardToSyslog is disabled", for_method(custom(
    [f'is_string({FTS})'], [[f'lower({FTS}) != "yes"']], "journald.forward_to_syslog",
    {"journald": {"forward_to_syslog": "no"}}, {"journald": {"forward_to_syslog": "yes"}},
    reads=[["journald", "forward_to_syslog"]]), "journald"))
put("6.1.1.2.1", "systemd-journal-remote is installed", for_method(pkg_present("systemd-journal-remote"), "journald"))
put("6.1.1.2.2", "systemd-journal-upload authentication", attest("journal_upload_auth_reviewed"))
_up = "systemd-journal-upload.service"
put("6.1.1.2.3", "systemd-journal-upload is enabled", for_method(custom(
    ['services_collected'], [[f'unit_enabled_active("{_up}")']], f"services[{_up}]",
    {"services": dict(base.SSHU, **{_up: base.ON})}, {"services": dict(base.SSHU, **{_up: base.OFF})},
    reads=[["services"]]), "journald"))
# the rsyslog subsection's Automated checks (install, service, file creation mode, no remote reception) apply to a
# host that uses rsyslog; 6.1.1.2.4 (journal-remote not in use) applies under both methods
for _rid in ("6.1.2.1", "6.1.2.2"):
    for_method(take(_rid), "rsyslog")
for _rid in ("6.1.2.4", "6.1.2.7"):
    for_method(L[_rid], "rsyslog")
put("6.1.2.3", "send logs to rsyslog", for_method(custom(
    [f'is_string({FTS})', 'is_boolean(input.rsyslog.service_active)', 'is_boolean(input.journald.service_active)'],
    [[f'lower({FTS}) == "yes"', 'input.rsyslog.service_active == true', 'input.journald.service_active == true']],
    "journald.forward_to_syslog/rsyslog.service_active/journald.service_active",
    {"journald": {"forward_to_syslog": "yes", "service_active": True}, "rsyslog": {"service_active": True}},
    {"journald": {"forward_to_syslog": "no", "service_active": True}, "rsyslog": {"service_active": True}},
    reads=[["journald", "forward_to_syslog"], ["rsyslog", "service_active"], ["journald", "service_active"]]),
    "rsyslog"))

# 6.3.2: a cron entry running aide (--check, --update or $AIDEARGS), or aidecheck.service and aidecheck.timer
# enabled with the timer active. aide.cron_raw: /etc/crontab, /etc/cron.*/*, /var/spool/cron/** concatenated;
# aide.aidecheck: {service_unit_file_state, timer_unit_file_state, timer_active_state}.
AK = "input.aide.aidecheck"
put("6.3.2", "regularly checked", custom(
    None,
    [['aide_cron_check'],
     [f'{AK}.service_unit_file_state == "enabled"', f'{AK}.timer_unit_file_state == "enabled"',
      f'{AK}.timer_active_state == "active"']],
    "aide.cron_raw/aide.aidecheck",
    {"aide": {"cron_raw": "0 5 * * * root /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"}},
    {"aide": {"cron_raw": "0 5 * * * root /usr/bin/updatedb",
              "aidecheck": {"service_unit_file_state": "disabled", "timer_unit_file_state": "disabled",
                            "timer_active_state": "inactive"}}},
    {}, reads=[["aide", "cron_raw"], ["aide", "aidecheck"], ["aide", "collected"]],
    ev_alts=[['is_string(input.aide.cron_raw)'],
             [f'is_string({AK}.service_unit_file_state)', f'is_string({AK}.timer_unit_file_state)',
              f'is_string({AK}.timer_active_state)'],
             # collected and empty (no cron file mentions aide) is "not met", not "evidence missing";
             # type_name keeps the empty string (an is_string() condition is emitted as text_collected)
             ['input.aide.collected == true', 'type_name(input.aide.cron_raw) == "string"']]))
L["6.3.2"].field = "aide.cron_raw/aide.aidecheck/aide.collected"

# ── #332: gaps found feeding the module real host evidence ────────────────────────────────────
# An empty string or list cannot tell "collected, nothing found" from "not collected". A section's
# `collected: true` marker (chronyd.collected, pam.collected, aide.collected) says the collector read the
# host, so an empty value there is a real answer, judged by the requirement.

# 2.4.1.7: "IF cron is installed" stat /etc/cron.yearly/. A host without the directory has nothing to
# secure: a collected cron.cron_yearly_exists == false passes (as in rhel_9); a present one is checked.
_cy = L["2.4.1.7"]
_cy.ev_alts = _cy.ev_alts + [['input.cron.cron_yearly_exists == false']]
_cy.passes = _cy.passes + [['input.cron.cron_yearly_exists == false']]
_cy.reads = _cy.reads + [["cron", "cron_yearly_exists"]]
_cy.field = "cron.cron_yearly_mode/cron.cron_yearly_owner/cron.cron_yearly_group/cron.cron_yearly_exists (or packages.cron)"

# 2.3.3.2: "IF chrony is in use", no chronyd process may run as a user other than _chrony. With chronyd
# collected and no process running, chrony is not running as _chrony: not met (2.3.3.3 fails it too).
_cu = L["2.3.3.2"]
_cu.ev_alts = _cu.ev_alts + [['input.chronyd.collected == true', 'is_array(input.chronyd.process_users)']]
_cu.passes = [['timesyncd_only'],
              ['count(input.chronyd.process_users) > 0', 'every u in input.chronyd.process_users { u == "_chrony" }']]
_cu.reads = _cu.reads + [["chronyd", "collected"]]
_cu.field = "chronyd.process_users/chronyd.collected"

# 5.4.3.3: the 22.04 audit requires `umask` 027 or stricter in /etc/profile.d/*.sh AND UMASK 027 or stricter
# in /etc/login.defs. No umask line in profile.d is "not met" (the 24.04 logic passed it on any other
# profile line). pam.profile_d_raw: the profile.d lines; pam.default_umask: the login.defs UMASK value.
_um = L["5.4.3.3"]
_um.ev_alts = [['text_collected(input.pam.profile_d_raw)', 'input.pam.default_umask != null'],
               ['input.pam.collected == true', 'type_name(input.pam.profile_d_raw) == "string"']]
_um.passes = [['count(umask_values(input.pam.profile_d_raw)) > 0',
               'every u in umask_values(input.pam.profile_d_raw) { umask_ok(u) }',
               'umask_ok(sprintf("%v", [input.pam.default_umask]))']]
_um.reads = _um.reads + [["pam", "collected"]]
_um.field = "pam.profile_d_raw/pam.default_umask/pam.collected"

# 5.2.6: the default timeout is compared only as a number (brief rule 2: guard every comparison)
_st = L["5.2.6"]
_st.passes = [_st.passes[0], ['count(sudo_timeouts) == 0', 'is_number(input.sudo.default_timestamp_timeout)',
                              'input.sudo.default_timestamp_timeout >= 0', 'input.sudo.default_timestamp_timeout <= 15']]

# 7.1.8: no "absent passes" note in 22.04: /etc/gshadow- must exist with the stated access
put("7.1.8", "/etc/gshadow-", base.crit("/etc/gshadow-", "0640", ["root", "shadow"]))

# 6.2.3 audit rules. Every 22.04 audit reads the on-disk rules (/etc/audit/rules.d/*.rules: auditd.rules) AND
# the running rules (`auditctl -l`: auditd.active_rules), and only counts rules that carry a key (-k or key=), so
# each rule is required in both sets, with a key. auid filters are auid>=UID_MIN (user_group.uid_min, from
# /etc/login.defs) and auid!=unset (or -1 / 4294967295). Syscall rules are required for every architecture the
# audit's expected output lists.
ARD = ["auditd", "rules"]
UMIN = ["user_group", "uid_min"]
SETS = ["audit_rule_lines", "audit_disk_lines"]
B3264 = ["b32", "b64"]
_FX = {"auid": "-F auid>=1000 -F auid!=unset ", "euid": "-C euid!=uid -F auid!=unset ",
       "eacces": "-F exit=-EACCES -F auid>=1000 -F auid!=unset ", "eperm": "-F exit=-EPERM -F auid>=1000 -F auid!=unset "}


def audit22(watches=(), syscalls=(), execs=(), extra_ev=(), extra_conds=(), extra_good=None, extra_reads=()):
    """watches: [(path, perm)]; syscalls: [(names, fields, arches)]; execs: [path] (perm=x with the auid filters)."""
    conds, good = [], []
    uses_uid = bool(execs)
    for p, perm in watches:
        conds += [f'audit22_watch({s}, {json.dumps(p)}, {json.dumps(perm)})' for s in SETS]
        good.append(f"-w {p} -p {perm} -k k")
    for names, fields, arches in syscalls:
        uses_uid = uses_uid or any(f in ("auid", "eacces", "eperm") for f in fields)
        for s in SETS:
            conds.append(f'every n in {json.dumps(names)} {{ every a in {json.dumps(arches)} '
                         f'{{ audit22_syscall({s}, n, {json.dumps(fields)}, a) }} }}')
        good += [f"-a always,exit -F arch={a} -S {','.join(names)} {''.join(_FX[f] for f in fields)}-k k" for a in arches]
    for p in execs:
        conds += [f'audit22_exec({s}, {json.dumps(p)})' for s in SETS]
        good.append(f"-a always,exit -F path={p} -F perm=x -F auid>=1000 -F auid!=unset -k k")
    ev = [f'is_array({ref(AR)})', f'is_array({ref(ARD)})'] + ([f'is_number({ref(UMIN)})'] if uses_uid else [])
    reads = [AR, ARD] + ([UMIN] if uses_uid else []) + list(extra_reads)
    field = "auditd.active_rules/auditd.rules" + ("/user_group.uid_min" if uses_uid else "")

    def fx(lines):
        d = {"auditd": {"active_rules": lines, "rules": lines}}
        if uses_uid:
            d["user_group"] = {"uid_min": 1000}
        return base.merge(d, extra_good or {})
    return custom(ev + list(extra_ev), [conds + list(extra_conds)], field, fx(good), fx(good[:-1]), reads=reads)


put("6.2.3.1", "sudoers", audit22([("/etc/sudoers", "wa"), ("/etc/sudoers.d", "wa")]))
put("6.2.3.2", "another user", audit22(syscalls=[(["execve"], ["euid"], B3264)]))
# 6.2.3.3: a watch on every logfile= named in sudoers (none named: the audit errors, which is a failure)
_s = put("6.2.3.3", "sudo log file", audit22(
    extra_ev=[f'is_string({ref(SU)})'],
    extra_conds=['count(sudo_logfiles) > 0',
                 'every f in sudo_logfiles { audit22_watch(audit_rule_lines, f, "wa"); audit22_watch(audit_disk_lines, f, "wa") }'],
    extra_reads=[SU]))
_w = ["-w /var/log/sudo.log -p wa -k sudo_log_file"]
_s.tp = {"auditd": {"active_rules": _w, "rules": _w}, "sudo": {"sudoers_content": 'Defaults logfile="/var/log/sudo.log"'}}
_s.tf = {"auditd": {"active_rules": _w, "rules": []}, "sudo": {"sudoers_content": 'Defaults logfile="/var/log/sudo.log"'}}
_s.field = "auditd.active_rules/auditd.rules/sudo.sudoers_content"
put("6.2.3.4", "date and time", audit22([("/etc/localtime", "wa")],
                                        [(["adjtimex", "settimeofday", "clock_settime"], [], B3264)]))
put("6.2.3.5", "network environment", audit22(
    [(p, "wa") for p in ["/etc/issue", "/etc/issue.net", "/etc/hosts", "/etc/networks", "/etc/network", "/etc/netplan"]],
    [(["sethostname", "setdomainname"], [], B3264)]))
# 6.2.3.6: every setuid/setgid file on a mount without noexec/nosuid (auditd.privileged_commands) has a rule
# naming it with perm x, in the running and the on-disk rules
_s = put("6.2.3.6", "privileged commands", custom(
    [f'is_array({ref(AR)})', f'is_array({ref(ARD)})', 'is_array(input.auditd.privileged_commands)',
     'count(input.auditd.privileged_commands) > 0'],
    [['every c in input.auditd.privileged_commands { audit22_priv(audit_rule_lines, c); audit22_priv(audit_disk_lines, c) }']],
    "auditd.active_rules/auditd.rules/privileged_commands",
    {"auditd": {"active_rules": ["-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged"],
                "rules": ["-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged"],
                "privileged_commands": ["/usr/bin/su"]}},
    {"auditd": {"active_rules": ["-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged"],
                "rules": [], "privileged_commands": ["/usr/bin/su"]}},
    reads=[AR, ARD, ["auditd", "privileged_commands"]]))
_ACC = ["creat", "open", "openat", "truncate", "ftruncate"]
put("6.2.3.7", "unsuccessful file access", audit22(syscalls=[(_ACC, ["eacces"], B3264), (_ACC, ["eperm"], B3264)]))
put("6.2.3.8", "user/group information", audit22(
    [(p, "wa") for p in ["/etc/group", "/etc/passwd", "/etc/gshadow", "/etc/shadow", "/etc/security/opasswd",
                         "/etc/nsswitch.conf", "/etc/pam.conf", "/etc/pam.d"]]))
put("6.2.3.9", "discretionary access control", audit22(syscalls=[
    (["chmod", "fchmod", "fchmodat"], ["auid"], B3264), (["chown", "fchown", "lchown", "fchownat"], ["auid"], B3264),
    (["setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr"], ["auid"], B3264)]))
put("6.2.3.10", "file system mounts", audit22(syscalls=[(["mount"], ["auid"], B3264)]))
put("6.2.3.11", "session initiation", audit22([(p, "wa") for p in ["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"]]))
put("6.2.3.12", "login and logout", audit22([(p, "wa") for p in ["/var/log/lastlog", "/var/run/faillock"]]))
# 6.2.3.13: no renameat2 in 22.04
put("6.2.3.13", "file deletion", audit22(syscalls=[(["unlink", "unlinkat", "rename", "renameat"], ["auid"], B3264)]))
put("6.2.3.14", "Mandatory Access Controls", audit22([("/etc/apparmor", "wa"), ("/etc/apparmor.d", "wa")]))
put("6.2.3.15", "chcon", audit22(execs=["/usr/bin/chcon"]))
put("6.2.3.16", "setfacl", audit22(execs=["/usr/bin/setfacl"]))
put("6.2.3.17", "chacl", audit22(execs=["/usr/bin/chacl"]))
put("6.2.3.18", "usermod", audit22(execs=["/usr/sbin/usermod"]))
# 6.2.3.19: the module syscalls (the expected output lists arch=b64 only; query_module, a syscall the kernel no
# longer has, is not required), the kmod rule, and lsmod/rmmod/insmod/modinfo/modprobe/depmod resolving to kmod
# (auditd.kmod_symlinks: {path: `readlink -f path`}; auditd.kmod_target: `readlink -f /bin/kmod`)
KLINKS = ["/usr/sbin/lsmod", "/usr/sbin/rmmod", "/usr/sbin/insmod", "/usr/sbin/modinfo", "/usr/sbin/modprobe",
          "/usr/sbin/depmod"]
_s = put("6.2.3.19", "kernel module loading", audit22(
    syscalls=[(["init_module", "finit_module", "delete_module"], ["auid"], ["b64"])], execs=["/usr/bin/kmod"],
    extra_ev=['is_object(input.auditd.kmod_symlinks)', 'is_string(input.auditd.kmod_target)'],
    extra_conds=[f'every p in {json.dumps(KLINKS)} {{ input.auditd.kmod_symlinks[p] == input.auditd.kmod_target }}'],
    extra_good={"auditd": {"kmod_symlinks": {p: "/usr/bin/kmod" for p in KLINKS}, "kmod_target": "/usr/bin/kmod"}},
    extra_reads=[["auditd", "kmod_symlinks"], ["auditd", "kmod_target"]]))
_s.field += "/auditd.kmod_symlinks/kmod_target"

# ── helpers used by one module only: the 24.04 ones (plus the 26.04 core-limit helper) and the 22.04 additions ──
EXTRA = dict(u24.EXTRA)
EXTRA["process_hardening"] = base.EXTRA["process_hardening"]   # 1.5.4 core_hard_limits


def _guard(text, old, new):
    """a numeric comparison of a shared helper, re-emitted here with its is_number guard"""
    if text.count(old) != 1:
        raise SystemExit(f"shared helper changed: {old!r} not found once")
    return text.replace(old, new)


EXTRA["pam"] = _guard(EXTRA["pam"], "\tn := pam_arg_num(l, \"unlock_time\")\n\tn > 0\n",
                      "\tn := pam_arg_num(l, \"unlock_time\")\n\tis_number(n)\n\tn > 0\n")
EXTRA["ssh"] = _guard(EXTRA["ssh"], "\topenssh_version[0] == 9\n\topenssh_version[1] >= 9\n",
                      "\topenssh_version[0] == 9\n\tis_number(openssh_version[1])\n\topenssh_version[1] >= 9\n")
EXTRA["gdm"] = r'''
# a dconf lock entry for the key: "/org/gnome/desktop/screensaver/lock-delay", or the bare key name
# (a value written after "=" is ignored)
gdm_locked(key) if {
	some l in input.initial_setup.gdm_dconf_locks
	is_string(l)
	t := regex.replace(trim_space(l), `\s*=.*$`, "")
	regex.match(`^[^#]`, t)
	key in {t, regex.replace(t, `^.*/`, "")}
}
'''
EXTRA["integrity"] = base.EXTRA["integrity"].rstrip("\n") + r'''

# 6.3.2: an active cron line that runs aide (or aide.wrapper) with --check / --update or $AIDEARGS
aide_cron_check if {
	some l in active_lines(input.aide.cron_raw)
	regex.match(`^(([^#]*\s)?/usr/s?bin/)?aide(\.wrapper)?\s+([^#]*\s)?(--(check|update)\b|\$AIDEARGS\b)`, l)
}
'''
EXTRA["auditd"] = u24.EXTRA["auditd"].rstrip("\n") + r'''

# on-disk rules (/etc/audit/rules.d/*.rules), active lines
audit_disk_lines := [l |
	some r in input.auditd.rules
	is_string(r)
	l := trim_space(r)
	l != ""
	not startswith(l, "#")
]

# the 22.04 audits count only rules that carry a key: `-k <key>` or `-F key=<key>`
audit_keyed(l) if regex.match(`(^|\s)-k\s+\S`, l)

audit_keyed(l) if regex.match(`(^|\s)key=\S`, l)

# auid>=UID_MIN (user_group.uid_min, /etc/login.defs) and auid!=unset
audit22_auid(l) if {
	regex.match(concat("", [`(^|\s)auid>=`, format_int(input.user_group.uid_min, 10), `(\s|$)`]), l)
	regex.match(audit_unset, l)
}

audit22_field(l, "auid") if audit22_auid(l)

audit22_field(l, "euid") if audit_field(l, "euid")

audit22_field(l, "eacces") if {
	regex.match(`exit=-EACCES(\s|$)`, l)
	audit22_auid(l)
}

audit22_field(l, "eperm") if {
	regex.match(`exit=-EPERM(\s|$)`, l)
	audit22_auid(l)
}

audit22_watch(lines, p, perm) if {
	some l in lines
	audit_path_tok(l, p)
	pv := audit_perm(l)
	every i in numbers.range(0, count(perm) - 1) { contains(pv, substring(perm, i, 1)) }
	audit_keyed(l)
}

audit22_syscall(lines, s, fields, arch) if {
	some l in lines
	regex.match(`^-a\s+(always,exit|exit,always)(\s|$)`, l)
	concat("", ["arch=", arch]) in audit_toks(l)
	s in line_syscalls(l)
	every f in fields { audit22_field(l, f) }
	audit_keyed(l)
}

audit22_exec(lines, p) if {
	some l in lines
	regex.match(`^-a\s+(always,exit|exit,always)(\s|$)`, l)
	audit_path_tok(l, p)
	contains(audit_perm(l), "x")
	audit22_auid(l)
	audit_keyed(l)
}

# 6.2.3.6: a rule naming the privileged file with perm x (the audit greps for the path in the rules)
audit22_priv(lines, p) if {
	some l in lines
	audit_path_tok(l, p)
	contains(audit_perm(l), "x")
}
'''

# ── regression tests appended to the generated test files (keyed by module; 22.04 ids) ───────────
def _t(mod, name, inp, rid, want):
    cmp = {"fail": f'count([v | some v in vs; startswith(v, "{rid}: not met")]) > 0',
           "pass": f'count([v | some v in vs; startswith(v, "{rid}: ")]) == 0',
           "missing": f'count([v | some v in vs; startswith(v, "{rid}: evidence missing")]) > 0'}[want]
    return (f"test_{name} if {{\n\tvs := data.{PKG}.{mod}.violations with input as {json.dumps(inp)}\n"
            f"\t{cmp}\n}}\n")


_R = lambda *xs: "\n".join(xs)  # noqa: E731
_RULES = lambda lines, umin=1000: {"auditd": {"active_rules": lines, "rules": lines}, "user_group": {"uid_min": umin}}  # noqa: E731
_MNT = "-a always,exit -F arch={a} -S mount -F auid>={u} -F auid!=unset -k mounts"
_SSHD = "port 22\nhostkey /etc/ssh/ssh_host_rsa_key\nhostkey /etc/ssh/ssh_host_ed25519_key\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:22\npermitrootlogin no\nmaxauthtries 4"
REGRESSION_TESTS = {
    "banners": _R(
        "# 1.6.1 judges /etc/motd.d files; the other message-of-the-day locations are not part of the 22.04 audit.",
        _t("banners", "motd_d_file_with_release_text_flagged", {"initial_setup": {"motd_exists": False, "motd_extra_files": [{"path": "/etc/motd.d/x", "content": "Ubuntu 22.04"}]}}, "1.6.1", "fail"),
        _t("banners", "run_motd_d_file_not_judged", {"initial_setup": {"motd_exists": False, "motd_extra_files": [{"path": "/run/motd.d/x", "content": "Ubuntu 22.04"}]}}, "1.6.1", "pass"),
        _t("banners", "motd_extra_files_not_collected_is_missing_evidence", {"initial_setup": {"motd_exists": False}}, "1.6.1", "missing")),
    "gdm": _R(
        "# Lock entries are matched by key name; a host without GDM passes the GDM settings checks.",
        _t("gdm", "lock_entry_with_value_suffix_accepted", {"initial_setup": {"gdm_installed": True, "gdm_dconf_locks": ["automount=false", "automount-open=false"]}}, "1.7.7", "pass"),
        _t("gdm", "commented_lock_entry_not_counted", {"initial_setup": {"gdm_installed": True, "gdm_dconf_locks": ["/org/gnome/desktop/media-handling/automount", "# /org/gnome/desktop/media-handling/automount-open"]}}, "1.7.7", "fail"),
        _t("gdm", "longer_key_name_is_not_the_lock", {"initial_setup": {"gdm_installed": True, "gdm_dconf_locks": ["/org/gnome/desktop/media-handling/autorun-never-x"]}}, "1.7.9", "fail"),
        _t("gdm", "gdm_absent_passes_lock_checks", {"initial_setup": {"gdm_installed": False}}, "1.7.5", "pass"),
        _t("gdm", "no_dconf_profile_fails_banner", {"initial_setup": {"gdm_installed": True, "gdm_dconf_profile_exists": False, "gdm_banner_configured": True}}, "1.7.2", "fail")),
    "apparmor": _R(
        "# 1.3.1.3: complain mode is allowed; an unconfined process is not.",
        _t("apparmor", "profiles_in_complain_mode_pass_not_disabled", {"apparmor": {"profiles": {"loaded": 10, "enforce": 8, "complain": 2}, "processes": {"unconfined": 0}}}, "1.3.1.3", "pass"),
        _t("apparmor", "unconfined_process_flagged", {"apparmor": {"profiles": {"loaded": 10, "enforce": 10, "complain": 0}, "processes": {"unconfined": 1}}}, "1.3.1.3", "fail"),
        _t("apparmor", "complain_mode_fails_enforcing", {"apparmor": {"profiles": {"loaded": 10, "enforce": 8, "complain": 2}, "processes": {"unconfined": 0}}}, "1.3.1.4", "fail")),
    "services": _R(
        "# 2.1.21: 0.0.0.0 is the wildcard address, 127.0.0.1 is loopback, every token must be loopback.",
        _t("services", "mta_wildcard_address_flagged", {"mta": {"non_loopback_listeners": [], "inet_interfaces": "0.0.0.0"}}, "2.1.21", "fail"),
        _t("services", "mta_loopback_accepted", {"mta": {"non_loopback_listeners": [], "inet_interfaces": "127.0.0.1"}}, "2.1.21", "pass"),
        _t("services", "mta_mixed_list_flagged", {"mta": {"non_loopback_listeners": [], "inet_interfaces": "localhost, 192.0.2.10"}}, "2.1.21", "fail"),
        "# 2.1.3: an installed isc-dhcp-server whose units are off passes; a unit not reported is missing evidence.",
        _t("services", "dhcp_installed_units_off_passes", {"packages": {"isc-dhcp-server": True}, "services": {"ssh.service": base.ON, "isc-dhcp-server.service": base.OFF, "isc-dhcp-server6.service": base.OFF}}, "2.1.3", "pass"),
        _t("services", "dhcp_installed_unit_unreported_missing", {"packages": {"isc-dhcp-server": True}, "services": {"ssh.service": base.ON, "isc-dhcp-server.service": base.OFF}}, "2.1.3", "missing")),
    "ssh": _R(
        "# The `+` append syntax enables the named weak algorithm; repeated directives from `sshd -T` evaluate.",
        _t("ssh", "ciphers_plus_append_flagged", {"ssh": {"sshd_config_raw": "port 22\nciphers +aes128-cbc"}}, "5.1.6", "fail"),
        _t("ssh", "kex_plus_append_flagged", {"ssh": {"sshd_config_raw": "port 22\nkexalgorithms +diffie-hellman-group1-sha1"}}, "5.1.12", "fail"),
        _t("ssh", "macs_plus_append_flagged", {"ssh": {"sshd_config_raw": "port 22\nmacs +hmac-md5"}}, "5.1.15", "fail"),
        _t("ssh", "repeated_directives_evaluate", {"ssh": {"sshd_config_raw": _SSHD}}, "5.1.20", "pass")),
    "pam": _R(
        "# 5.3.3.3.x read the pam_pwhistory arguments only: 22.04 has no pwhistory.conf alternative.",
        _t("pam", "pwhistory_conf_does_not_replace_remember_argument", {"pam": {"common_password": "password requisite pam_pwhistory.so enforce_for_root use_authtok", "pwhistory_conf_raw": "remember = 24"}}, "5.3.3.3.1", "fail"),
        _t("pam", "pwhistory_conf_does_not_replace_enforce_for_root", {"pam": {"common_password": "password requisite pam_pwhistory.so remember=24 use_authtok", "pwhistory_conf_raw": "enforce_for_root"}}, "5.3.3.3.2", "fail"),
        _t("pam", "use_authtok_longer_token_not_a_match", {"pam": {"common_password": "password requisite pam_pwhistory.so remember=24 use_authtok_x"}}, "5.3.3.3.3", "fail")),
    "logging": _R(
        "# logging_method decides between 6.1.1.1.4 and 6.1.2.3; without it both are evaluated.",
        _t("logging", "journald_site_skips_rsyslog_forwarding", {"logging_method": "journald", "journald": {"forward_to_syslog": "no"}}, "6.1.2.3", "pass"),
        _t("logging", "journald_site_skips_rsyslog_install", {"logging_method": "journald"}, "6.1.2.1", "pass"),
        _t("logging", "rsyslog_site_skips_forward_disabled", {"logging_method": "rsyslog", "journald": {"forward_to_syslog": "yes"}}, "6.1.1.1.4", "pass"),
        _t("logging", "rsyslog_site_skips_journal_upload", {"logging_method": "rsyslog"}, "6.1.1.2.3", "pass"),
        _t("logging", "journald_site_skips_rsyslog_create_mode", {"logging_method": "journald"}, "6.1.2.4", "pass"),
        _t("logging", "journald_site_skips_rsyslog_remote_receive", {"logging_method": "journald"}, "6.1.2.7", "pass"),
        _t("logging", "undeclared_method_forwarding_on_fails_journald_check", {"journald": {"forward_to_syslog": "yes"}}, "6.1.1.1.4", "fail"),
        _t("logging", "undeclared_method_not_collected_is_missing", {}, "6.1.2.1", "missing"),
        "# 6.1.2.7: module(load=\"imtcp\" ...) and `input( type=` are remote-receive configuration; comments are not.",
        _t("logging", "remote_receive_module_with_params_flagged", {"rsyslog": {"installed": True, "config_raw": "module(load=\"imtcp\" MaxSessions=\"500\")\n"}}, "6.1.2.7", "fail"),
        _t("logging", "remote_receive_commented_out_not_flagged", {"rsyslog": {"installed": True, "config_raw": "#module(load=\"imtcp\")\n*.* /var/log/syslog\n"}}, "6.1.2.7", "pass")),
    "auditd": _R(
        "# 6.2.3: a rule is required in the running and the on-disk rules, with a key, for both listed architectures.",
        _t("auditd", "mount_rule_running_only_flagged", {"auditd": {"active_rules": [_MNT.format(a=a, u=1000) for a in B3264], "rules": []}, "user_group": {"uid_min": 1000}}, "6.2.3.10", "fail"),
        _t("auditd", "mount_rule_both_sets_passes", _RULES([_MNT.format(a=a, u=1000) for a in B3264]), "6.2.3.10", "pass"),
        _t("auditd", "mount_rule_b64_only_flagged", _RULES([_MNT.format(a="b64", u=1000)]), "6.2.3.10", "fail"),
        _t("auditd", "mount_rule_without_key_flagged", _RULES([_MNT.format(a=a, u=1000).replace(" -k mounts", "") for a in B3264]), "6.2.3.10", "fail"),
        _t("auditd", "auid_threshold_follows_uid_min", _RULES([_MNT.format(a=a, u=1000) for a in B3264], 500), "6.2.3.10", "fail"),
        _t("auditd", "uid_min_not_collected_is_missing", {"auditd": {"active_rules": [], "rules": []}}, "6.2.3.10", "missing"),
        _t("auditd", "deletion_without_renameat2_passes", _RULES([f"-a always,exit -F arch={a} -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=-1 -F key=delete" for a in B3264]), "6.2.3.13", "pass"),
        _t("auditd", "module_syscalls_b64_only_pass", base.merge(_RULES(["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"]), {"auditd": {"kmod_target": "/usr/bin/kmod", "kmod_symlinks": {p: "/usr/bin/kmod" for p in KLINKS}}}), "6.2.3.19", "pass"),
        _t("auditd", "kmod_symlink_elsewhere_flagged", base.merge(_RULES(["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"]), {"auditd": {"kmod_target": "/usr/bin/kmod", "kmod_symlinks": dict({p: "/usr/bin/kmod" for p in KLINKS}, **{"/usr/sbin/insmod": "/opt/insmod"})}}), "6.2.3.19", "fail"),
        _t("auditd", "networks_watch_does_not_cover_network", _RULES([f"-a always,exit -F arch={a} -S sethostname,setdomainname -k system-locale" for a in B3264] + [f"-w {p} -p wa -k system-locale" for p in ["/etc/issue", "/etc/issue.net", "/etc/hosts", "/etc/networks", "/etc/netplan"]]), "6.2.3.5", "fail")),
    "integrity": _R(
        "# 6.3.2: the aidecheck units are an alternative to a cron entry; a commented cron entry is not one.",
        _t("integrity", "aidecheck_units_pass", {"aide": {"aidecheck": {"service_unit_file_state": "enabled", "timer_unit_file_state": "enabled", "timer_active_state": "active"}}}, "6.3.2", "pass"),
        _t("integrity", "commented_cron_entry_flagged", {"aide": {"cron_raw": "#0 5 * * * root /usr/bin/aide --check"}}, "6.3.2", "fail"),
        _t("integrity", "audit_tools_without_autrace_flagged", {"aide": {"audit_tool_options": {t: base.AIDE_OPTS for t in ["auditctl", "auditd", "ausearch", "aureport", "augenrules"]}}}, "6.3.3", "fail"),
        "# 6.3.2 (#332): with aide.collected, cron text that names no aide check is not met, not missing evidence.",
        _t("integrity", "collected_cron_with_aide_check_passes", {"aide": {"collected": True, "cron_raw": "0 5 * * * root /usr/bin/aide --check"}}, "6.3.2", "pass"),
        _t("integrity", "collected_empty_cron_is_not_met", {"aide": {"collected": True, "cron_raw": ""}}, "6.3.2", "fail"),
        _t("integrity", "empty_cron_without_marker_is_missing", {"aide": {"cron_raw": ""}}, "6.3.2", "missing"),
        _t("integrity", "marker_without_cron_text_is_missing", {"aide": {"collected": True}}, "6.3.2", "missing")),
    "job_schedulers": _R(
        "# 2.4.1.7 (#332): an absent /etc/cron.yearly has nothing to secure; a present one is checked.",
        _t("job_schedulers", "cron_yearly_absent_passes", {"cron": {"cron_yearly_exists": False}}, "2.4.1.7", "pass"),
        _t("job_schedulers", "cron_yearly_present_open_mode_flagged", {"cron": {"cron_yearly_exists": True, "cron_yearly_mode": "0755", "cron_yearly_owner": "root", "cron_yearly_group": "root"}}, "2.4.1.7", "fail"),
        _t("job_schedulers", "cron_yearly_present_without_stat_is_missing", {"cron": {"cron_yearly_exists": True}}, "2.4.1.7", "missing")),
    "time_sync": _R(
        "# 2.3.3.2 (#332): with chronyd.collected, no chronyd process is not met; an empty list alone is missing evidence.",
        _t("time_sync", "collected_chronyd_as_chrony_passes", {"chronyd": {"collected": True, "process_users": ["_chrony"]}}, "2.3.3.2", "pass"),
        _t("time_sync", "collected_chronyd_stopped_is_not_met", {"chronyd": {"collected": True, "process_users": []}}, "2.3.3.2", "fail"),
        _t("time_sync", "empty_process_list_without_marker_is_missing", {"chronyd": {"process_users": []}}, "2.3.3.2", "missing"),
        _t("time_sync", "marker_false_is_missing", {"chronyd": {"collected": False, "process_users": []}}, "2.3.3.2", "missing"),
        _t("time_sync", "marker_without_process_list_is_missing", {"chronyd": {"collected": True}}, "2.3.3.2", "missing")),
    "accounts": _R(
        "# 5.4.3.3 (#332): umask 027 is required in /etc/profile.d/*.sh and in login.defs UMASK.",
        _t("accounts", "collected_umask_both_places_passes", {"pam": {"collected": True, "profile_d_raw": "umask 027", "default_umask": "027"}}, "5.4.3.3", "pass"),
        _t("accounts", "collected_no_profile_umask_is_not_met", {"pam": {"collected": True, "profile_d_raw": "", "default_umask": "027"}}, "5.4.3.3", "fail"),
        _t("accounts", "profile_lines_without_umask_not_met", {"pam": {"profile_d_raw": "export EDITOR=vi", "default_umask": "027"}}, "5.4.3.3", "fail"),
        _t("accounts", "collected_no_login_defs_umask_is_not_met", {"pam": {"collected": True, "profile_d_raw": "umask 027"}}, "5.4.3.3", "fail"),
        _t("accounts", "empty_profile_without_marker_is_missing", {"pam": {"profile_d_raw": "", "default_umask": "027"}}, "5.4.3.3", "missing"),
        _t("accounts", "marker_without_profile_text_is_missing", {"pam": {"collected": True, "default_umask": "027"}}, "5.4.3.3", "missing")),
    f"{PKG}_main": base.REGRESSION_TESTS[f"{base.FILE_STEM}_main"].replace(base.PKG, PKG),
}


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    base.OUT, base.PKG, base.FILE_STEM, base.GEN = OUT, PKG, PKG, GEN
    base.BENCH, base.VERSION = BENCH, VERSION
    base.EXPECTED_TOTAL, base.EXPECTED_AUTOMATED, base.EXPECTED_MANUAL = EXPECTED_TOTAL, EXPECTED_AUTOMATED, EXPECTED_MANUAL
    base.PROFILE_NOTE = """Levels differ by platform (e.g. 1.1.1.9 is
# Level 1 Server but Level 2 Workstation), so each control carries its own server/workstation level, and three
# recommendations (1.7.1, 2.1.20, 3.1.2) are on no Workstation sheet."""
    base.L, base.KW, base.EXTRA, base.REGRESSION_TESTS = L, KW, EXTRA, REGRESSION_TESTS
    base.MAIN_VIOLATION_COUNT = True   # the report contract of the framework keys asks for it
    rollup_tests = base.emit_rollup_tests

    def emit_rollup_tests(recs):   # the roll-up smoke test attests 26.04's 1.2.1.1; 22.04's is another name
        t = rollup_tests(recs)
        if t.count("apt_sources_signed_by_reviewed") != 1:
            raise SystemExit("gen_ubuntu_26_04.py roll-up test changed: the attested-control case was not found")
        return t.replace("apt_sources_signed_by_reviewed", "apt_gpg_keys_reviewed")
    base.emit_rollup_tests = emit_rollup_tests
    base.main()   # aborts on any count, id, Automated/Manual or keyword mismatch before writing
    written = [OUT / f"{n}.rego" for n, _, _ in base.SECTIONS] + \
              [OUT / "tests" / f"test_{n}.rego" for n, _, _ in base.SECTIONS] + \
              [OUT / f"{PKG}.rego", OUT / f"{PKG}_main.rego", OUT / "tests" / f"test_{PKG}_main.rego"]
    if shutil.which("opa"):
        subprocess.run(["opa", "fmt", "-w"] + [str(p) for p in written], check=True)
    else:
        print(f"opa not on PATH: run `opa fmt -w {OUT}` before committing")


if __name__ == "__main__":
    main()
