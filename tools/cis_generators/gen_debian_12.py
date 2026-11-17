#!/usr/bin/env python3
"""CIS Debian Linux 12 Benchmark v2.0.1: every recommendation, from the benchmark's own workbook.

    python3 tools/cis_generators/gen_debian_12.py CIS_Debian_Linux_12_Benchmark_v2.0.1.xlsx [fields.json]

Needs openpyxl. The workbook is CIS-licensed and is never committed. Writes benchmarks/cis/debian_12/: one
package per benchmark section (cis_debian_12.<section>), the roll-up package cis_debian_12 and the bridge
cis_debian_12.main (compliance_report), plus tests.

This is the Ubuntu 26.04 generator (gen_ubuntu_26_04.py) pointed at the Debian 12 workbook: the reader, the
spec builders, the Rego helpers and the emitters are its (imported, not copied); this file holds the Debian 12
logic table. Debian 12 v2.0.1 shares most recommendations with Ubuntu 26.04 v1.0.0, many under another id:

  * SAME      ids whose audit procedure matches the Ubuntu recommendation of the same id;
  * RENUMBER  Debian id -> Ubuntu id for the same recommendation under another number;
  * put(...)  logic written here because the Debian 12 audit procedure differs or the recommendation is new.

Every entry carries a title keyword. The run aborts on any count, id, Automated/Manual or keyword mismatch
with the workbook, so logic cannot attach to a renumbered recommendation. The input fact contract is the
ubuntu_26_04 module's; the facts Debian 12 adds are listed in benchmarks/cis/debian_12/README.md.
"""
import copy
import json
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen_ubuntu_26_04 as u  # noqa: E402
from neutralize import publish_titles  # noqa: E402

OUT = HERE.parent.parent / "benchmarks" / "cis" / "debian_12"
PKG = "cis_debian_12"
GEN = "tools/cis_generators/gen_debian_12.py"
BENCH = "CIS Debian Linux 12 Benchmark v2.0.1"
VERSION = "v2.0.1"
EXPECTED_TOTAL = 331
EXPECTED_AUTOMATED = 316
EXPECTED_MANUAL = 15

custom, audit, ref, nest, merge, dotted = u.custom, u.audit, u.ref, u.nest, u.merge, u.dotted
SU, AR, GL, UV, LINUX = u.SU, u.AR, u.GL, u.UV, u.LINUX

# ── the Ubuntu specs carry Ubuntu sample data and the os-release ID the banner checks look for ──
SWAPS = [("Ubuntu 26.04 LTS", "Debian GNU/Linux 12"), ("Ubuntu 26.04", "Debian GNU/Linux 12"), ("ubuntu", "debian"),
         ("Ubuntu", "Debian"), ("resolute", "bookworm"), ("noble", "bookworm")]


def debianize(x):
    if isinstance(x, str):
        for a, b in SWAPS:
            x = x.replace(a, b)
        return x
    if isinstance(x, list):
        return [debianize(v) for v in x]
    if isinstance(x, dict):
        return {debianize(k): debianize(v) for k, v in x.items()}
    return x


L, KW = {}, {}


def put(rid, kw, spec):
    if rid in L:
        raise SystemExit(f"{rid} defined twice")
    L[rid], KW[rid] = spec, kw
    return spec


def take(rid, uid=None, kw=None):
    """The Ubuntu 26.04 logic of recommendation uid (default: the same id), with its title keyword."""
    uid = uid or rid
    if uid not in u.L:
        raise SystemExit(f"{rid}: gen_ubuntu_26_04.py has no logic for {uid}")
    spec = copy.deepcopy(u.L[uid])
    if not spec.manual:
        for attr in ("ev_alts", "passes", "field", "tp", "tf", "tm"):
            setattr(spec, attr, debianize(getattr(spec, attr)))
    return put(rid, kw or u.KW[uid], spec)


# ════════════════════════════════════════════════════════════════════════════════════════════
# Recommendations whose Debian 12 audit procedure is the Ubuntu 26.04 one (compared text against text)
# ════════════════════════════════════════════════════════════════════════════════════════════
SAME = """
1.1.1.1 1.1.1.2 1.1.1.3 1.1.1.4 1.1.1.5 1.1.1.6 1.1.1.7 1.1.1.8 1.1.1.9 1.1.1.10 1.1.1.11 1.1.2.1.1
1.1.2.1.2 1.1.2.1.3 1.1.2.1.4 1.1.2.2.1 1.1.2.2.2 1.1.2.2.3 1.1.2.2.4 1.1.2.3.1 1.1.2.3.2 1.1.2.3.3
1.1.2.4.1 1.1.2.4.2 1.1.2.4.3 1.1.2.5.1 1.1.2.5.2 1.1.2.5.3 1.1.2.5.4 1.1.2.6.1 1.1.2.6.2 1.1.2.6.3
1.1.2.6.4 1.1.2.7.1 1.1.2.7.2 1.1.2.7.3 1.1.2.7.4 1.2.1.1 1.2.1.2 1.2.1.4 1.2.1.5 1.2.1.6
1.2.1.7 1.2.1.8 1.2.1.9 1.2.2.1 1.3.1.1 1.4.1 1.4.2 1.5.1 1.5.2 1.5.3 1.5.4 1.5.5
1.5.6 1.5.7 1.5.8 1.5.9 1.6.2 1.6.3 1.6.4 1.6.5 1.6.6 1.6.7 1.6.8 1.6.9 1.6.10 1.7.1 1.7.2
1.7.3 1.7.4 1.7.5 1.7.6 1.7.7 2.1.1 2.2.1 2.2.2 2.2.3 2.2.5 2.3.1.1 2.3.2.1 2.3.2.2
2.3.3.1 2.3.3.2 2.3.3.3 2.4.1.1 2.4.1.2 2.4.1.3 2.4.1.4 2.4.1.5 2.4.1.6 2.4.1.7 2.4.1.8 2.4.1.9
2.4.2.1 3.1.1 3.1.2 3.1.3 3.2.1 3.2.2 3.2.3 3.2.4 3.2.5 3.2.6 3.3.1.1 3.3.1.2 3.3.1.3 3.3.1.4
3.3.1.5 3.3.1.6 3.3.1.7 3.3.1.8 3.3.1.9 3.3.1.10 3.3.1.11 3.3.1.12 3.3.1.13 3.3.1.14 3.3.1.15
3.3.1.16 3.3.1.17 3.3.1.18 3.3.2.1 3.3.2.2 3.3.2.3 3.3.2.4 3.3.2.5 3.3.2.6 3.3.2.7 3.3.2.8 4.1.1
4.1.2 4.1.3 4.1.4 5.1.1 5.2.2 5.2.5 5.2.7 5.3.1.1 5.3.1.2 5.3.1.3
5.3.1.4 5.3.2.1 5.3.2.2 5.3.2.3 5.3.2.4 5.3.3.1.1 5.3.3.1.2 5.3.3.1.3 5.3.3.2.1 5.3.3.2.2 5.3.3.2.3
5.3.3.2.4 5.3.3.2.5 5.3.3.2.6 5.3.3.2.7 5.3.3.2.8 5.3.3.3.1 5.3.3.3.2 5.3.3.3.3 5.3.3.4.1 5.3.3.4.2
5.3.3.4.3 5.3.3.4.4 5.4.1.1 5.4.1.2 5.4.1.3 5.4.1.4 5.4.1.5 5.4.1.6 5.4.2.1 5.4.2.2 5.4.2.3 5.4.2.4
5.4.2.5 5.4.2.6 5.4.2.7 5.4.2.8 5.4.3.1 5.4.3.2 6.1.1.1.1 6.1.1.1.2 6.1.1.1.3 6.1.1.1.4
6.1.1.1.5 6.1.1.1.6 6.1.1.1.7 6.1.2.1 6.1.2.2 6.1.2.3 6.1.2.4 6.1.2.5 6.1.2.7 6.1.2.8
6.1.2.9 6.1.2.10 6.1.3.1 6.2.1.1 6.2.1.2 6.2.1.3 6.2.1.4 6.2.2.1 6.2.2.2 6.2.2.3 6.2.2.4
6.2.3.3 6.2.3.6 6.2.3.7 6.2.3.10 6.2.4.5 6.2.4.6 6.2.4.7
6.3.1 6.3.2 7.1.1 7.1.2 7.1.3 7.1.4 7.1.5 7.1.6 7.1.7 7.1.8 7.1.9 7.1.10 7.1.11 7.1.12 7.1.13
7.2.1 7.2.2 7.2.3 7.2.4 7.2.5 7.2.6 7.2.7 7.2.8 7.2.9 7.2.10
""".split()
for _rid in SAME:
    take(_rid)

# Debian 12 id -> Ubuntu 26.04 id of the same recommendation (same audit procedure, another number)
RENUMBER = {
    "1.5.10": "1.5.11", "1.5.11": "1.5.12", "2.1.2": "2.1.22", "2.1.3": "2.1.2", "2.1.4": "2.1.23",
    "2.1.5": "2.1.3", "2.1.6": "2.1.19", "2.1.7": "2.1.4", "2.1.8": "2.1.6", "2.1.9": "2.1.5", "2.1.10": "2.1.7",
    "2.1.11": "2.1.8", "2.1.12": "2.1.9", "2.1.13": "2.1.10", "2.1.14": "2.1.11", "2.1.15": "2.1.12",
    "2.1.16": "2.1.13", "2.1.17": "2.1.14", "2.1.18": "2.1.15", "2.1.19": "2.1.16", "2.1.20": "2.1.17",
    "2.1.21": "2.1.18", "2.1.22": "2.1.20", "2.1.23": "2.1.21", "5.1.2": "5.1.3", "5.1.3": "5.1.4",
    "5.1.4": "5.1.5", "5.1.5": "5.1.6", "5.1.6": "5.1.7", "5.1.7": "5.1.8", "5.1.8": "5.1.9", "5.1.9": "5.1.10",
    "5.1.10": "5.1.11", "5.1.11": "5.1.12", "5.1.12": "5.1.13", "5.1.13": "5.1.15", "5.1.14": "5.1.16",
    "5.1.15": "5.1.17", "5.1.16": "5.1.18", "5.1.17": "5.1.20", "5.1.18": "5.1.19", "5.1.19": "5.1.21",
    "5.1.20": "5.1.22", "5.1.21": "5.1.23", "5.1.22": "5.1.24",
    "6.2.3.11": "6.2.3.12", "6.2.3.12": "6.2.3.13", "6.2.3.13": "6.2.3.14", "6.2.3.14": "6.2.3.15",
    "6.2.3.15": "6.2.3.16", "6.2.3.16": "6.2.3.17", "6.2.3.20": "6.2.3.22", "6.2.3.21": "6.2.3.23",
    "6.2.3.23": "6.2.3.26", "6.2.3.29": "6.2.3.35", "6.2.3.30": "6.2.3.36", "6.2.4.1": "6.2.4.4",
    "6.2.4.2": "6.2.4.1", "6.2.4.3": "6.2.4.2", "6.2.4.4": "6.2.4.3",
}
for _rid, _uid in RENUMBER.items():
    take(_rid, _uid)

# ════════════════════════════════════════════════════════════════════════════════════════════
# Debian 12 logic: the audit procedure differs from Ubuntu 26.04, or the recommendation is new
# ════════════════════════════════════════════════════════════════════════════════════════════
# 1.2.1.3: step 1 the *gpg files under /usr/share/keyrings and /etc/apt/trusted.gpg.d (apt.key_files);
# step 2 the .list/.sources files of /etc/apt/sources.list.d (apt.sources_list_d_files): 0644 root root.
KF, SLF = ["apt", "key_files"], ["apt", "sources_list_d_files"]
_ok = 'list_item_ok(f, "mode", "owner", "group", "0644", ["root"], ["root"])'
_kf = {"path": "/usr/share/keyrings/debian-archive-keyring.gpg", "mode": "0644", "owner": "root", "group": "root"}
_sf = {"path": "/etc/apt/sources.list.d/debian.sources", "mode": "0644", "owner": "root", "group": "root"}
put("1.2.1.3", "gpg key files", custom(
    [f'is_array({ref(KF)})', f'count({ref(KF)}) > 0', f'is_array({ref(SLF)})'],
    [[f'every f in {ref(KF)} {{ {_ok} }}', f'every f in {ref(SLF)} {{ {_ok} }}']],
    "apt.key_files/apt.sources_list_d_files",
    merge(nest(KF, [_kf]), nest(SLF, [_sf])), merge(nest(KF, [_kf]), nest(SLF, [dict(_sf, mode="0664")])),
    reads=[KF, SLF]))

# 1.3.1.2: the Debian 12 audit reads only the `linux` lines of grub.cfg
put("1.3.1.2", "AppArmor is enabled", custom(
    [f'is_array({ref(GL)})', 'count(grub_linux_lines) > 0'],
    [['every l in grub_linux_lines { not regex.match(`(^|\\s)apparmor=0(\\s|$)`, l) }']], dotted(GL),
    nest(GL, [LINUX]), nest(GL, [LINUX, LINUX + " apparmor=0"]), reads=[GL]))
# 1.3.1.3: profiles loaded, none in complain mode, no unconfined process (Debian 12 apparmor_status)
put("1.3.1.3", "AppArmor Profiles are enforcing", custom(
    ['input.apparmor.profiles.loaded != null', 'input.apparmor.profiles.enforce != null',
     'input.apparmor.profiles.complain != null', 'input.apparmor.processes.unconfined != null'],
    [['num(input.apparmor.profiles.loaded) > 0', 'num(input.apparmor.profiles.enforce) == num(input.apparmor.profiles.loaded)',
      'num(input.apparmor.profiles.complain) == 0',
      'num(input.apparmor.processes.unconfined) == 0']],
    "apparmor.profiles/apparmor.processes",
    {"apparmor": {"profiles": {"loaded": 34, "enforce": 34, "complain": 0}, "processes": {"unconfined": 0}}},
    {"apparmor": {"profiles": {"loaded": 34, "enforce": 32, "complain": 2}, "processes": {"unconfined": 0}}},
    reads=[["apparmor", "profiles"], ["apparmor", "processes"]]))

# 1.6.1: /etc/motd plus the other message-of-the-day files the audit greps (motd_extra_files:
# /run/motd, /usr/lib/motd, /etc/motd.d/*, /run/motd.d/*, /usr/lib/motd.d/*, /etc/update-motd.d/*)
SYSINFO = debianize(u.SYSINFO)
MEX, MCT, MXF = (["initial_setup", k] for k in ("motd_exists", "motd_content", "motd_extra_files"))
_extra = f'every f in {ref(MXF)} {{ is_string(f.content); not regex.match({json.dumps(SYSINFO)}, f.content) }}'
_s = put("1.6.1", "/etc/motd is configured", custom(
    None, [[f'{ref(MEX)} == true', f'not regex.match({json.dumps(SYSINFO)}, {ref(MCT)})', _extra],
           [f'{ref(MEX)} == false', _extra]],
    "initial_setup.motd_exists/motd_content/motd_extra_files",
    merge(nest(MEX, True), nest(MCT, "Authorized uses only."), nest(MXF, [{"path": "/etc/motd.d/10-notice", "content": "Monitored."}])),
    merge(nest(MEX, False), nest(MXF, [{"path": "/etc/update-motd.d/10-uname", "content": "Debian GNU/Linux 12 \\r"}])),
    {}, reads=[MEX, MCT, MXF],
    ev_alts=[[f'{ref(MEX)} == false', f'is_array({ref(MXF)})'],
             [f'{ref(MEX)} == true', f'is_string({ref(MCT)})', f'is_array({ref(MXF)})']]))
_s.hollow_ok = True

# 2.2 client packages named by the Debian 12 audit
put("2.2.4", "telnet client", u.pkg_absent(["telnet", "inetutils-telnet"]))
put("2.2.6", "ftp client", u.pkg_absent(["ftp", "tnftp"]))

# 4.1.5: `disabled (routed)` or `deny (routed)` in `ufw status verbose`
put("4.1.5", "routed default", custom(
    [f'is_string({ref(UV)})'], [['ufw_default("routed") in {"deny", "disabled"}']], dotted(UV),
    nest(UV, u.UVOK.replace("deny (routed)", "disabled (routed)")), nest(UV, u.UVOK.replace("deny (routed)", "allow (routed)")),
    reads=[UV]))

# 5.1.24: every effective ListenAddress (`sshd -T`) is a private-network address (RFC 1918, IPv6 ULA) or
# loopback; the wildcard, a public address or a host name fails.
put("5.1.24", "ListenAddress", custom(
    ['ssh_collected', 'sshd_first("listenaddress")'],
    [['count(sshd_listen_addresses) > 0', 'every a in sshd_listen_addresses { listen_private(a) }']],
    "ssh.sshd_config_raw (effective listenaddress)",
    u.ssh_in(["port 22", "listenaddress 192.168.1.14:22"]),
    u.ssh_in(["port 22", "listenaddress 192.168.1.14:22", "listenaddress [::]:22"]), u.ssh_in(["port 22"]),
    reads=[u.SSH_RAW]))

# 5.1.23 is Automated in Debian 12: the effective KexAlgorithms offer sntrup761x25519-sha512 and, from
# OpenSSH 9.9 on, mlkem768x25519-sha256 as well (ssh.openssh_version: "9.2" or "OpenSSH_9.2p1")
OSV = ["ssh", "openssh_version"]
_kex = "curve25519-sha256,sntrup761x25519-sha512@openssh.com"
put("5.1.23", "post-quantum", custom(
    ['ssh_collected', 'sshd_first("kexalgorithms")', 'openssh_ver[0] >= 0'],
    [['kex_has("sntrup761x25519-sha512")', 'not openssh_ge_9_9'],
     ['kex_has("sntrup761x25519-sha512")', 'kex_has("mlkem768x25519-sha256")']],
    "ssh.sshd_config_raw (effective kexalgorithms)/ssh.openssh_version",
    {"ssh": {"sshd_config_raw": "port 22\nkexalgorithms " + _kex, "openssh_version": "OpenSSH_9.2p1"}},
    {"ssh": {"sshd_config_raw": "port 22\nkexalgorithms " + _kex, "openssh_version": "10.0"}},
    {"ssh": {"sshd_config_raw": "port 22\nkexalgorithms " + _kex}}, reads=[u.SSH_RAW, OSV]))

# 5.2 privilege escalation (classic sudo; Debian 12 has no sudo-rs)
put("5.2.1", "sudo is installed", custom(
    ['is_boolean(input.packages.sudo)', 'is_boolean(input.packages["sudo-ldap"])'],
    [['input.packages.sudo == true'], ['input.packages["sudo-ldap"] == true']], "packages[sudo,sudo-ldap]",
    {"packages": {"sudo": False, "sudo-ldap": True}}, {"packages": {"sudo": False, "sudo-ldap": False}},
    reads=[["packages", "sudo"], ["packages", "sudo-ldap"]]))
put("5.2.3", "sudo log file", custom(
    [f'is_string({ref(SU)})'], [['sudo_logfile']], dotted(SU),
    nest(SU, 'Defaults logfile="/var/log/sudo.log"'), nest(SU, "Defaults use_pty"), reads=[SU]))
put("5.2.4", "password for escalation", u.text_has(SU, "NOPASSWD", False, "%sudo ALL=(ALL:ALL) ALL",
                                                   "%sudo ALL=(ALL:ALL) NOPASSWD: ALL"))
# 5.2.6: every configured timestamp_timeout within 0..15; when none is configured, the compiled default
# (`sudo -V`, minutes, sudo.default_timestamp_timeout) must be within 0..15
SDT = ["sudo", "default_timestamp_timeout"]
put("5.2.6", "timestamp_timeout", custom(
    None,
    [['count(sudo_timeouts) > 0', 'every t in sudo_timeouts { t >= 0; t <= 15 }'],
     ['count(sudo_timeouts) == 0', f'{ref(SDT)} >= 0', f'{ref(SDT)} <= 15']],
    "sudo.sudoers_content/sudo.default_timestamp_timeout",
    nest(SU, "Defaults env_reset, timestamp_timeout=15"), nest(SU, "Defaults timestamp_timeout=-1"), {},
    reads=[SU, SDT],
    ev_alts=[[f'is_string({ref(SU)})', 'count(sudo_timeouts) > 0'],
             [f'is_string({ref(SU)})', 'count(sudo_timeouts) == 0', f'is_number({ref(SDT)})']]))

# 5.4.3.3: a umask is set under /etc/profile.d and every one is 027 or tighter; login.defs UMASK likewise
PDR = u.PDR
put("5.4.3.3", "default user umask", custom(
    [f'is_string({ref(PDR)})', 'input.pam.default_umask != null'],
    [[f'count(umask_values({ref(PDR)})) > 0', f'every v in umask_values({ref(PDR)}) {{ umask_ok(v) }}',
      'umask_ok(sprintf("%v", [input.pam.default_umask]))']],
    "pam.profile_d_raw/pam.default_umask", {"pam": {"profile_d_raw": "umask 027", "default_umask": "027"}},
    {"pam": {"profile_d_raw": "umask 022", "default_umask": "027"}}, reads=[PDR, ["pam", "default_umask"]]))

# 6.1.2.6: the Debian 12 audit looks for TCP reception only (imtcp, $InputTCPServerRun)
put("6.1.2.6", "receive logs", u.text_has(u.RC,
    "(?i)(^module\\(\\s*load\\s*=\\s*\"?imtcp\"?[\\s,)]|^input\\(\\s*type\\s*=\\s*\"?imtcp\"?|^\\$ModLoad\\s+imtcp\\b|^\\$InputTCPServerRun\\b)",
    False, "*.* /var/log/syslog", 'module(load="imtcp")'))

# 6.2.3 audit rules. Every Debian 12 audit procedure reads the running rules (auditd.active_rules) AND the on-disk
# rules (auditd.rules); u.audit requires a rule in both. Debian 12 expects syscall rules for both arch=b32 and
# arch=b64 (6.2.3.28: both on disk, the arch=b64 module rule in the running rules), and the execution watches
# (chcon, setfacl, chacl, usermod, kmod) as `-a always,exit` rules carrying the auid filters.
EXEC = "-a always,exit -F path={p} -F perm=x -F auid>=1000 -F auid!=unset -k k"
SRCS = json.dumps(list(u.SRCS))


def audit_exec(path, extra_conds=(), extra_good=(), extra_good_running=None):
    good = list(extra_good) + [EXEC.format(p=path)]
    run = good if extra_good_running is None else list(extra_good_running) + [EXEC.format(p=path)]
    return custom(u.AUDIT_EV, [list(extra_conds) + [f'every src in {SRCS} {{ audit_src_exec(src, {json.dumps(path)}) }}']],
                  u.AUDIT_FIELD, {"auditd": {"rules": good, "active_rules": run}},
                  u.both(list(extra_good) + [u.W.format(p=path, perm="x")]), nest(AR, run), reads=[u.ARD, AR])


take("6.2.3.1", kw="sudoers")
put("6.2.3.2", "another user", audit(syscalls=[(["execve"], ["euid"])], arches=True))
put("6.2.3.4", "date and time", audit([("/etc/localtime", "wa")],
                                      [(["adjtimex", "settimeofday", "clock_settime"], [])], arches=True))
put("6.2.3.5", "sethostname", audit(syscalls=[(["sethostname", "setdomainname"], [])], arches=True))
put("6.2.3.8", "/etc/network and /etc/networks", audit([("/etc/networks", "wa"), ("/etc/network", "wa")]))
# 6.2.3.9: passes when /etc/netplan does not exist (auditd.netplan_dir_exists false)
NPD = ["auditd", "netplan_dir_exists"]
_np = f'every src in {SRCS} {{ audit_src_watch(src, "/etc/netplan", "wa") }}'
put("6.2.3.9", "/etc/netplan", custom(
    None, [[f'{ref(NPD)} == false'], [_np]], "auditd.netplan_dir_exists/auditd.rules/active_rules",
    merge(nest(NPD, True), u.both([u.W.format(p="/etc/netplan", perm="wa")])),
    merge(nest(NPD, True), u.both([u.W.format(p="/etc/network", perm="wa")])),
    nest(AR, [u.W.format(p="/etc/netplan", perm="wa")]),
    reads=[NPD, u.ARD, AR],
    ev_alts=[[f'{ref(NPD)} == false'], [f'{ref(NPD)} == true'] + u.AUDIT_EV, [_np]]))
_acc = ["creat", "open", "openat", "truncate", "ftruncate"]
put("6.2.3.17", "unsuccessful file access", audit(syscalls=[(_acc, ["eacces"]), (_acc, ["eperm"])], arches=True))
put("6.2.3.18", "discretionary access control", audit(syscalls=[
    (["chmod", "fchmod", "fchmodat"], ["auid"]), (["chown", "fchown", "lchown", "fchownat"], ["auid"]),
    (["setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr"], ["auid"])], arches=True))
put("6.2.3.19", "mounts", audit(syscalls=[(["mount"], ["auid"])], arches=True))
put("6.2.3.22", "file deletion", audit(syscalls=[(["unlink", "unlinkat", "rename", "renameat", "renameat2"], ["auid"])],
                                       arches=True))
for _rid, _kw, _p in [("6.2.3.24", "chcon", "/usr/bin/chcon"), ("6.2.3.25", "setfacl", "/usr/bin/setfacl"),
                      ("6.2.3.26", "chacl", "/usr/bin/chacl"), ("6.2.3.27", "usermod", "/usr/sbin/usermod")]:
    put(_rid, _kw, audit_exec(_p))
# 6.2.3.28: the module syscalls that exist on current kernels (the loaded-rules listing the benchmark shows
# is the arch=b64 rule) plus the kmod execution rule
_km = ["init_module", "finit_module", "delete_module"]
_KARCH = {"rules": ("b32", "b64"), "active_rules": ("b64",)}
put("6.2.3.28", "kernel module loading", audit_exec(
    "/usr/bin/kmod", u.syscall_conds(_km, ["auid"], _KARCH),
    [u.S64.format(arch=a, s=",".join(_km + ["create_module", "query_module"]), extra=u.AUID) for a in ("b64", "b32")],
    [u.S64.format(arch="b64", s=",".join(_km + ["create_module", "query_module"]), extra=u.AUID)]))

# 6.2.4.8-6.2.4.10: the six audit tools the Debian 12 audit stats (autrace included) must all be in
# auditd.tools ({path, mode, owner, group}); a tool not reported is missing evidence.
ATL = ["auditd", "tools"]
ATOOLS = ["auditctl", "aureport", "ausearch", "autrace", "auditd", "augenrules"]
_tools_ev = [f'is_array({ref(ATL)})',
             f'every t in {json.dumps(ATOOLS)} {{ some f in {ref(ATL)}; regex.replace(f.path, `^.*/`, "") == t }}']
_tgood = [{"path": "/sbin/" + t, "mode": "0755", "owner": "root", "group": "root"} for t in ATOOLS]
for _rid, _kw, _key, _cond, _bad in [("6.2.4.8", "tools mode", "mode", 'mode_within(f.mode, "0755")', "0777"),
                                     ("6.2.4.9", "tools owner", "owner", 'f.owner == "root"', "adm"),
                                     ("6.2.4.10", "tools group", "group", 'f.group == "root"', "adm")]:
    put(_rid, _kw, custom(_tools_ev, [[f'every f in {ref(ATL)} {{ {_cond} }}']], dotted(ATL) + " (all six tools)",
                          nest(ATL, _tgood), nest(ATL, _tgood[:-1] + [dict(_tgood[-1], **{_key: _bad})]),
                          nest(ATL, _tgood[:3] + _tgood[4:]), reads=[ATL]))

# 6.3.3: Debian 12 lists autrace among the audit tools
TOOLS = ["auditctl", "auditd", "ausearch", "aureport", "autrace", "augenrules"]
put("6.3.3", "integrity of audit tools", custom(
    ['is_object(input.aide.audit_tool_options)'],
    [[f'every t in {json.dumps(TOOLS)} {{ aide_opts_ok(input.aide.audit_tool_options[t]) }}']],
    "aide.audit_tool_options",
    {"aide": {"audit_tool_options": {t: u.AIDE_OPTS for t in TOOLS}}},
    {"aide": {"audit_tool_options": {t: u.AIDE_OPTS for t in TOOLS if t != "autrace"}}},
    reads=[["aide", "audit_tool_options"]]))

# ── Rego helpers Debian 12 adds to the Ubuntu generator's per-module helpers ───────────────────
EXTRA = dict(u.EXTRA)
EXTRA["ssh"] += r'''
# every effective ListenAddress (`sshd -T` prints one line per address)
sshd_listen_addresses := [lower(p[1]) | some p in sshd_pairs; p[0] == "listenaddress"]

# host part of a ListenAddress: "[fd00::5]:22" -> fd00::5, "10.0.0.5:22" -> 10.0.0.5, bare IPv6 unchanged
listen_host(a) := m[1] if {
	some m in regex.find_all_string_submatch_n(`^\[([0-9a-f:.]+)\](:[0-9]+)?$`, a, 1)
} else := m[1] if {
	some m in regex.find_all_string_submatch_n(`^([0-9.]+)(:[0-9]+)?$`, a, 1)
} else := a if regex.match(`^[0-9a-f]*:[0-9a-f:]*$`, a)

# private networks and loopback (0.0.0.0 and :: are the wildcard, not private)
listen_private_nets := ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"]

listen_private(a) if {
	h := listen_host(a)
	regex.match(`^[0-9a-f:.]+$`, h)
	some n in listen_private_nets
	net.cidr_contains(n, h)
}

# [major, minor] of the OpenSSH server ("9.2", "OpenSSH_9.2p1")
openssh_ver := [to_number(m[1]), to_number(m[2])] if {
	some m in regex.find_all_string_submatch_n(`^(?:openssh_)?([0-9]+)\.([0-9]+)`, lower(trim_space(input.ssh.openssh_version)), 1)
}

openssh_ge_9_9 if openssh_ver[0] > 9

openssh_ge_9_9 if {
	openssh_ver[0] == 9
	openssh_ver[1] >= 9
}

kex_has(prefix) if {
	some x in sshd_list("kexalgorithms")
	startswith(x, prefix)
}
'''
_DOT_OLD = 'not b in {".forward", ".rhosts"}'
if EXTRA["user_group"].count(_DOT_OLD) != 1:
    raise SystemExit("gen_ubuntu_26_04.py no longer holds the dot-file line the Debian 12 generator replaces")
EXTRA["user_group"] = EXTRA["user_group"].replace(_DOT_OLD, 'not b in {".forward", ".rhosts", ".rhost"}')  # the audit script's spelling too

# Regression tests carried over from the Ubuntu 26.04 semantic review (renumbered), plus the Debian 12 logic.
# emit_rollup_tests looks the roll-up tests up under the reference module's key.
REGRESSION_TESTS = {
    "logging": u.REGRESSION_TESTS["logging"],
    "services": r'''
# 0.0.0.0 is the wildcard address, 127.0.0.1 is loopback, every token must be loopback.
test_mta_inet_interfaces_wildcard_address_flagged if {
	vs := data.cis_debian_12.services.violations with input as {"mta": {"non_loopback_listeners": [], "inet_interfaces": "0.0.0.0"}}
	count([v | some v in vs; startswith(v, "2.1.2: not met")]) > 0
}

test_mta_inet_interfaces_127_0_0_1_accepted if {
	vs := data.cis_debian_12.services.violations with input as {"mta": {"non_loopback_listeners": [], "inet_interfaces": "127.0.0.1"}}
	count([v | some v in vs; startswith(v, "2.1.2: ")]) == 0
}

test_mta_inet_interfaces_mixed_list_flagged if {
	vs := data.cis_debian_12.services.violations with input as {"mta": {"non_loopback_listeners": [], "inet_interfaces": "localhost, 192.0.2.10"}}
	count([v | some v in vs; startswith(v, "2.1.2: not met")]) > 0
}
''',
    "ssh": r'''
# The `+` append syntax enables the named weak algorithm.
test_weak_algorithm_append_syntax_flagged if {
	every id, line in {"5.1.6": "ciphers +aes128-cbc", "5.1.15": "macs +hmac-md5", "5.1.12": "kexalgorithms +diffie-hellman-group1-sha1"} {
		vs := data.cis_debian_12.ssh.violations with input as {"ssh": {"sshd_config_raw": concat("\n", ["port 22", line])}}
		count([v | some v in vs; startswith(v, concat("", [id, ": not met"]))]) > 0
	}
}

# 5.1.24: the default wildcard listeners fail; named addresses pass.
test_5_1_24_default_wildcards_flagged if {
	vs := data.cis_debian_12.ssh.violations with input as {"ssh": {"sshd_config_raw": "port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22"}}
	count([v | some v in vs; startswith(v, "5.1.24: not met")]) > 0
}

# 5.1.23: 9.10 is newer than 9.9 (numeric compare), and needs mlkem768x25519-sha256 as well.
test_5_1_23_version_compared_numerically if {
	vs := data.cis_debian_12.ssh.violations with input as {"ssh": {"sshd_config_raw": "kexalgorithms sntrup761x25519-sha512", "openssh_version": "9.10"}}
	count([v | some v in vs; startswith(v, "5.1.23: not met")]) > 0
	vs2 := data.cis_debian_12.ssh.violations with input as {"ssh": {"sshd_config_raw": "kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512", "openssh_version": "9.10"}}
	count([v | some v in vs2; startswith(v, "5.1.23: ")]) == 0
}

test_5_1_24_private_addresses_pass if {
	vs := data.cis_debian_12.ssh.violations with input as {"ssh": {"sshd_config_raw": "port 22\nlistenaddress 10.0.0.5:22\nlistenaddress [fd00::5]:22\nlistenaddress 172.20.1.1"}}
	count([v | some v in vs; startswith(v, "5.1.24: ")]) == 0
}

test_5_1_24_public_address_flagged if {
	vs := data.cis_debian_12.ssh.violations with input as {"ssh": {"sshd_config_raw": "port 22\nlistenaddress 10.0.0.5:22\nlistenaddress 203.0.113.5:22"}}
	count([v | some v in vs; startswith(v, "5.1.24: not met")]) > 0
}

test_5_1_24_public_ipv6_flagged if {
	vs := data.cis_debian_12.ssh.violations with input as {"ssh": {"sshd_config_raw": "port 22\nlistenaddress [2001:db8::5]:22"}}
	count([v | some v in vs; startswith(v, "5.1.24: not met")]) > 0
}

test_5_1_24_172_32_is_not_private if {
	vs := data.cis_debian_12.ssh.violations with input as {"ssh": {"sshd_config_raw": "port 22\nlistenaddress 172.32.0.1:22"}}
	count([v | some v in vs; startswith(v, "5.1.24: not met")]) > 0
}

test_5_1_24_host_name_flagged if {
	vs := data.cis_debian_12.ssh.violations with input as {"ssh": {"sshd_config_raw": "port 22\nlistenaddress sshgw.example.com:22"}}
	count([v | some v in vs; startswith(v, "5.1.24: not met")]) > 0
}
''',
    "sudo": r'''
# 5.2.6: no timestamp_timeout configured => the compiled default decides; a missing default is missing evidence.
test_5_2_6_default_timeout_accepted if {
	vs := data.cis_debian_12.sudo.violations with input as {"sudo": {"sudoers_content": "Defaults use_pty", "default_timestamp_timeout": 5}}
	count([v | some v in vs; startswith(v, "5.2.6: ")]) == 0
}

test_5_2_6_default_timeout_too_long if {
	vs := data.cis_debian_12.sudo.violations with input as {"sudo": {"sudoers_content": "Defaults use_pty", "default_timestamp_timeout": 30}}
	count([v | some v in vs; startswith(v, "5.2.6: not met")]) > 0
}

test_5_2_6_default_timeout_not_collected if {
	vs := data.cis_debian_12.sudo.violations with input as {"sudo": {"sudoers_content": "Defaults use_pty"}}
	count([v | some v in vs; startswith(v, "5.2.6: evidence missing")]) > 0
}

test_5_2_6_configured_value_beats_default if {
	vs := data.cis_debian_12.sudo.violations with input as {"sudo": {"sudoers_content": "Defaults timestamp_timeout=60", "default_timestamp_timeout": 5}}
	count([v | some v in vs; startswith(v, "5.2.6: not met")]) > 0
}

# 5.2.4: a commented-out NOPASSWD line is not a finding.
test_5_2_4_commented_nopasswd_ignored if {
	vs := data.cis_debian_12.sudo.violations with input as {"sudo": {"sudoers_content": "# %admin ALL=(ALL) NOPASSWD: ALL\n%sudo ALL=(ALL:ALL) ALL"}}
	count([v | some v in vs; startswith(v, "5.2.4: ")]) == 0
}
''',
    "auditd": r'''
# Debian 12 expects both architectures on syscall rules: a b64-only rule is not enough.
test_6_2_3_19_b64_only_flagged if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts"], "active_rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts"]}}
	count([v | some v in vs; startswith(v, "6.2.3.19: not met")]) > 0
}

# The loaded-rules spelling (auid!=-1, -F key=) is the same rule.
test_6_2_3_19_auditctl_spelling_accepted if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"], "active_rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"]}}
	count([v | some v in vs; startswith(v, "6.2.3.19: ")]) == 0
}

# An execution watch without the auid filters (legacy -w form) does not satisfy the Debian 12 audit.
test_6_2_3_24_legacy_watch_flagged if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": ["-w /usr/bin/chcon -p x -k perm_chng"], "active_rules": ["-w /usr/bin/chcon -p x -k perm_chng"]}}
	count([v | some v in vs; startswith(v, "6.2.3.24: not met")]) > 0
}

test_6_2_3_24_auditctl_listing_accepted if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng"], "active_rules": ["-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng"]}}
	count([v | some v in vs; startswith(v, "6.2.3.24: ")]) == 0
}

# 6.2.3.9: no /etc/netplan directory is a pass; an unknown directory state without the rule is missing evidence.
test_6_2_3_9_no_netplan_directory_passes if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"netplan_dir_exists": false}}
	count([v | some v in vs; startswith(v, "6.2.3.9: ")]) == 0
}

test_6_2_3_9_legacy_watch_accepted if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": ["-w /etc/netplan -p wa -k system-locale"], "active_rules": ["-w /etc/netplan -p wa -k system-locale"]}}
	count([v | some v in vs; startswith(v, "6.2.3.9: ")]) == 0
}

# 6.2.3.23: the directory watches may be written with a trailing slash.
test_6_2_3_23_trailing_slash_accepted if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": ["-w /etc/apparmor/ -p wa -k MAC-policy", "-w /etc/apparmor.d/ -p wa -k MAC-policy"], "active_rules": ["-w /etc/apparmor/ -p wa -k MAC-policy", "-w /etc/apparmor.d/ -p wa -k MAC-policy"]}}
	count([v | some v in vs; startswith(v, "6.2.3.23: ")]) == 0
}

# 6.2.3: a rule is required in the on-disk rules (auditd.rules) AND the running rules (auditd.active_rules).
test_6_2_3_19_running_only_flagged if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": [], "active_rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"]}}
	count([v | some v in vs; startswith(v, "6.2.3.19: not met")]) > 0
}

test_6_2_3_19_on_disk_only_flagged if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"], "active_rules": []}}
	count([v | some v in vs; startswith(v, "6.2.3.19: not met")]) > 0
}

test_6_2_3_9_running_rule_only_is_missing if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"active_rules": ["-w /etc/netplan -p wa -k system-locale"]}}
	count([v | some v in vs; startswith(v, "6.2.3.9: evidence missing")]) > 0
}

# 6.2.3.28: both architectures on disk, the arch=b64 module rule in the running rules.
test_6_2_3_28_b64_running_both_on_disk_passes if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"], "active_rules": ["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"]}}
	count([v | some v in vs; startswith(v, "6.2.3.28: ")]) == 0
}

test_6_2_3_28_b64_only_on_disk_flagged if {
	vs := data.cis_debian_12.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"], "active_rules": ["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"]}}
	count([v | some v in vs; startswith(v, "6.2.3.28: not met")]) > 0
}
''',
    "banners": r'''
# 1.6.x: the os-release ID the banner checks look for is "debian".
test_1_6_2_debian_named_in_issue_flagged if {
	vs := data.cis_debian_12.banners.violations with input as {"initial_setup": {"issue_exists": true, "issue_content": "Debian GNU/Linux 12"}}
	count([v | some v in vs; startswith(v, "1.6.2: not met")]) > 0
}

test_1_6_1_motd_d_file_flagged_when_etc_motd_clean if {
	vs := data.cis_debian_12.banners.violations with input as {"initial_setup": {"motd_exists": true, "motd_content": "Authorized use only.", "motd_extra_files": [{"path": "/etc/motd.d/os", "content": "kernel \\r on \\m"}]}}
	count([v | some v in vs; startswith(v, "1.6.1: not met")]) > 0
}

test_1_6_1_extra_files_not_collected_is_missing_evidence if {
	vs := data.cis_debian_12.banners.violations with input as {"initial_setup": {"motd_exists": false}}
	count([v | some v in vs; startswith(v, "1.6.1: evidence missing")]) > 0
}
''',
    "firewall": r'''
test_4_1_5_deny_and_disabled_pass_reject_fails if {
	base := "Status: active\nDefault: deny (incoming), deny (outgoing), %s (routed)"
	every p in ["deny", "disabled"] {
		vs := data.cis_debian_12.firewall.violations with input as {"ufw": {"status_verbose": sprintf(base, [p])}}
		count([v | some v in vs; startswith(v, "4.1.5: ")]) == 0
	}
	vs2 := data.cis_debian_12.firewall.violations with input as {"ufw": {"status_verbose": sprintf(base, ["allow"])}}
	count([v | some v in vs2; startswith(v, "4.1.5: not met")]) > 0
}
''',
    "cis_ubuntu_26_04_main": u.REGRESSION_TESTS["cis_ubuntu_26_04_main"],
}


# ── emit: the reference emitters, with the module identity rewritten ───────────────────────────
NO_WS_RE = re.compile(r"and three\n# recommendations \([^)]*\) have no Workstation profile at all\.")


def configure():
    u.L, u.KW, u.EXTRA, u.REGRESSION_TESTS = L, KW, EXTRA, REGRESSION_TESTS
    u.BENCH, u.EXPECTED_MANUAL = BENCH, EXPECTED_MANUAL


def rewrite(text, must=("cis_ubuntu_26_04",)):
    for m in must:
        if m not in text:
            raise SystemExit(f"gen_ubuntu_26_04.py emitters changed: {m!r} not found in emitted text")
    text = (text.replace("cis_ubuntu_26_04", PKG).replace("gen_ubuntu_26_04.py", "gen_debian_12.py")
            .replace("domains: [linux, ubuntu]", "domains: [linux, debian]"))
    if "ubuntu" in text.lower():
        raise SystemExit("Ubuntu wording left in the emitted Debian 12 text")
    return text


def swap(text, old, new):
    """one exact replacement in reference-emitted text; anything else means the reference emitter changed"""
    if text.count(old) != 1:
        raise SystemExit(f"gen_ubuntu_26_04.py emitters changed: expected exactly one {old!r}")
    return text.replace(old, new)


def rollup_note(recs):
    """ids and profiles are workbook facts: the recommendations with no Workstation profile"""
    none = [r for r in sorted(recs, key=u.sort_key) if u.level(recs[r]["profiles"], "Workstation") is None]
    if u.level(recs["1.1.1.9"]["profiles"], "Server") != 1 or u.level(recs["1.1.1.9"]["profiles"], "Workstation") != 2:
        raise SystemExit("1.1.1.9 is no longer Level 1 Server / Level 2 Workstation: update the roll-up comment")
    return f"and {len(none)}\n# recommendations ({', '.join(none)}) have no Workstation profile at all."


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    recs, _ = u.read_workbook(sys.argv[1])
    a = sum(1 for r in recs.values() if r["assessment"] == "Automated")
    m = sum(1 for r in recs.values() if r["assessment"] == "Manual")
    if (len(recs), a, m) != (EXPECTED_TOTAL, EXPECTED_AUTOMATED, EXPECTED_MANUAL) or a + m != len(recs):
        raise SystemExit(f"workbook has {len(recs)} recommendations ({a} Automated, {m} Manual)")
    if set(L) != set(recs):
        raise SystemExit(f"logic/workbook mismatch: no logic {sorted(set(recs) - set(L), key=u.sort_key)}; "
                         f"no recommendation {sorted(set(L) - set(recs), key=u.sort_key)}")
    for rid, r in recs.items():
        if (r["assessment"] == "Manual") != L[rid].manual:
            raise SystemExit(f"{rid}: workbook says {r['assessment']}, logic table disagrees")
        title = " ".join(r["title"].split()).lower() + " "
        if " ".join(KW[rid].split()).lower() not in title and KW[rid].lower() not in title:
            raise SystemExit(f"{rid}: logic keyword {KW[rid]!r} not in workbook title {r['title']!r}")
    note = rollup_note(recs)
    recs = publish_titles(recs)
    configure()
    by_mod = {n: [] for n, _, _ in u.SECTIONS}
    for rid in sorted(recs, key=u.sort_key):
        by_mod[u.section_of(rid)].append(rid)
    (OUT / "tests").mkdir(parents=True, exist_ok=True)
    written = []

    def write(path, text):
        path.write_text(text)
        written.append(str(path))

    for name, title, _ in u.SECTIONS:
        write(OUT / f"{name}.rego", rewrite(u.emit_module(name, title, by_mod[name], recs)))
        write(OUT / "tests" / f"test_{name}.rego", rewrite(u.emit_tests(name, by_mod[name], recs)))
    rollup = u.emit_rollup(recs, by_mod)
    if len(NO_WS_RE.findall(rollup)) != 1:
        raise SystemExit("gen_ubuntu_26_04.py roll-up comment changed: the no-Workstation sentence was not found")
    write(OUT / f"{PKG}.rego", rewrite(NO_WS_RE.sub(lambda _: note, rollup)))
    bridge = u.emit_main(recs)
    bridge = swap(bridge, '"version": "v1.0.0"', f'"version": "{VERSION}"')
    # the report also carries violation_count (the reference bridge has the violations list only)
    bridge = swap(bridge, '\t"violations": _violations,\n',
                  '\t"violations": _violations,\n\t"violation_count": count(_violations),\n')
    write(OUT / f"{PKG}_main.rego", rewrite(bridge))
    tests = swap(u.emit_rollup_tests(recs), "count(object.keys(r)) == 17", "count(object.keys(r)) == 18")
    tests = swap(tests, '"violations", "section_results"', '"violations", "violation_count", "section_results"')
    tests = swap(tests, '\tr.passed_controls == 0\n', '\tr.passed_controls == 0\n\tr.violation_count == count(r.violations)\n')
    write(OUT / "tests" / f"test_{PKG}_main.rego", rewrite(tests))
    if len(sys.argv) > 2:  # input paths each control reads (for collector/mapper gap analysis)
        pathlib.Path(sys.argv[2]).write_text(json.dumps(
            {rid: [".".join(p) for p in L[rid].reads] for rid in sorted(recs, key=u.sort_key)}, indent=1))
    # the committed module is `opa fmt` output; format only the files written here
    if shutil.which("opa"):
        subprocess.run(["opa", "fmt", "-w"] + written, check=True)
    else:
        print(f"opa not on PATH: run `opa fmt -w {OUT}` before committing")
    print(f"{len(recs)} recommendations ({a} Automated, {m} Manual) -> {OUT}")


if __name__ == "__main__":
    main()
