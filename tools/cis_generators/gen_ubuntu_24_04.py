#!/usr/bin/env python3
"""CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.1: every recommendation, from the benchmark's own workbook.

    python3 tools/cis_generators/gen_ubuntu_24_04.py CIS_Ubuntu_Linux_24.04_LTS_Benchmark_v2.0.1.xlsx [fields.json]

Needs openpyxl. The reader, the Spec builders, the Rego helpers and every emitter are gen_ubuntu_26_04.py's
(imported, not copied); this script holds only what differs in 24.04:

  * RENUMBERED: 24.04 id -> 26.04 id for recommendations whose check is the same under another number;
  * NOT_IN_24: 26.04 recommendations this benchmark does not have;
  * the logic entries written from the 24.04 audit procedures where they differ from 26.04 (put24 below).

Every other recommendation carries the 26.04 logic under the same id. Each entry keeps its title keyword,
checked against the 24.04 workbook title, so logic cannot attach to a renumbered id: the run aborts on any
count, id, Automated/Manual status or keyword mismatch.

Emits benchmarks/cis/ubuntu_24_04/ in the ubuntu_26_04 layout (cis_ubuntu_24_04.<section>, roll-up
cis_ubuntu_24_04, bridge cis_ubuntu_24_04.main) on the same input contract, so one collector feeds both.
The framework-key bridge cis_ubuntu_2404_key_main.rego in that directory is hand-written and is not touched:
this script only writes the files it generates and never deletes anything.
"""
import copy
import json
import sys

import gen_ubuntu_26_04 as base
from gen_ubuntu_26_04 import AR, GL, LINUX, RC, SU, UV, UVOK, custom, dotted, nest, ref, ssh_in

PKG = "cis_ubuntu_24_04"
BENCH = "CIS Ubuntu Linux 24.04 LTS Benchmark v2.0.1"

# 24.04 id -> 26.04 id (same check, different number)
RENUMBERED = {
    "1.5.10": "1.5.11", "1.5.11": "1.5.12",
    "2.1.2": "2.1.22", "2.1.3": "2.1.2", "2.1.4": "2.1.23", "2.1.5": "2.1.3", "2.1.6": "2.1.19", "2.1.7": "2.1.4",
    "2.1.8": "2.1.6", "2.1.9": "2.1.5", "2.1.10": "2.1.7", "2.1.11": "2.1.8", "2.1.12": "2.1.9", "2.1.13": "2.1.10",
    "2.1.14": "2.1.11", "2.1.15": "2.1.12", "2.1.16": "2.1.13", "2.1.17": "2.1.14", "2.1.18": "2.1.15",
    "2.1.19": "2.1.16", "2.1.20": "2.1.17", "2.1.21": "2.1.18", "2.1.22": "2.1.20", "2.1.23": "2.1.21",
    "5.1.2": "5.1.3", "5.1.3": "5.1.4", "5.1.4": "5.1.5", "5.1.5": "5.1.6", "5.1.6": "5.1.7", "5.1.7": "5.1.8",
    "5.1.8": "5.1.9", "5.1.9": "5.1.10", "5.1.10": "5.1.11", "5.1.11": "5.1.12", "5.1.12": "5.1.13",
    "5.1.13": "5.1.15", "5.1.14": "5.1.16", "5.1.15": "5.1.17", "5.1.16": "5.1.18", "5.1.17": "5.1.20",
    "5.1.18": "5.1.19", "5.1.19": "5.1.21", "5.1.20": "5.1.22", "5.1.21": "5.1.23", "5.1.22": "5.1.24",
    "6.2.3.11": "6.2.3.12", "6.2.3.12": "6.2.3.13", "6.2.3.13": "6.2.3.14", "6.2.3.14": "6.2.3.15",
    "6.2.3.15": "6.2.3.16", "6.2.3.16": "6.2.3.17", "6.2.3.20": "6.2.3.22", "6.2.3.21": "6.2.3.23",
    "6.2.3.23": "6.2.3.26", "6.2.3.29": "6.2.3.35", "6.2.3.30": "6.2.3.36",
    "6.2.4.1": "6.2.4.4", "6.2.4.2": "6.2.4.1", "6.2.4.3": "6.2.4.2", "6.2.4.4": "6.2.4.3",
}

# 26.04 recommendations with no 24.04 counterpart, or whose 24.04 counterpart is written here from its own
# audit procedure (the second group is listed under put24 below).
NOT_IN_24 = {
    "1.2.1.10", "1.2.1.11", "1.2.1.12", "1.2.1.13", "1.2.1.14", "1.2.1.15", "1.5.10", "1.6.11", "1.6.12", "3.2.7",
    "3.3.1.19", "5.1.2", "6.2.3.34", "7.2.11",
    # one 24.04 rule covers what 26.04 splits (or the reverse), so the 24.04 entry is its own
    "5.1.14", "6.2.3.1", "6.2.3.8", "6.2.3.9", "6.2.3.11", "6.2.3.18", "6.2.3.19", "6.2.3.20", "6.2.3.21",
    "6.2.3.24", "6.2.3.25", "6.2.3.27", "6.2.3.28", "6.2.3.29", "6.2.3.30", "6.2.3.31", "6.2.3.32", "6.2.3.33",
}

L, KW = {}, {}


def retag(x):
    """test fixtures of a carried entry name the release in banner text"""
    if isinstance(x, dict):
        return {k: retag(v) for k, v in x.items()}
    if isinstance(x, list):
        return [retag(v) for v in x]
    if isinstance(x, str):
        return x.replace("26.04", "24.04")
    return x


def carry():
    """the 26.04 logic table under 24.04 ids"""
    back = {}
    for id24, id26 in RENUMBERED.items():
        if id26 in back or id26 not in base.L or id26 in NOT_IN_24:
            raise SystemExit(f"RENUMBERED: {id24} -> {id26} is not a usable 26.04 entry")
        back[id26] = id24
    for id26, spec in base.L.items():
        if id26 in NOT_IN_24:
            continue
        id24 = back.get(id26, id26)
        if id24 in L:
            raise SystemExit(f"{id24} defined twice (from {id26})")
        s = copy.copy(spec)
        if not s.manual:
            s.tp, s.tf, s.tm = retag(s.tp), retag(s.tf), retag(s.tm)
        L[id24], KW[id24] = s, base.KW[id26]
    missing = NOT_IN_24 - set(base.L)
    if missing:
        raise SystemExit(f"NOT_IN_24 names unknown 26.04 ids: {sorted(missing)}")


def put24(rid, kw, spec):
    """an entry written from the 24.04 audit procedure; replaces a carried one of the same id"""
    if rid in WRITTEN:
        raise SystemExit(f"{rid} written twice")
    WRITTEN.add(rid)
    L[rid], KW[rid] = spec, kw
    return spec


WRITTEN = set()
carry()

# 1.3.1.2: the 24.04 audit reads the kernel command line only (no `apparmor=0` on any linux line)
put24("1.3.1.2", "AppArmor is enabled", custom(
    [f'is_array({ref(GL)})', 'count(grub_linux_lines) > 0'],
    [['every l in grub_linux_lines { not regex.match(`(^|\\s)apparmor=0(\\s|$)`, l) }']], dotted(GL),
    nest(GL, [LINUX]), nest(GL, [LINUX + " apparmor=0"]), reads=[GL]))

# 1.6.1: /etc/motd (the shared fields) plus the other message-of-the-day files the 24.04 audit names
# (/run/motd, /usr/lib/motd, /etc/motd.d/*, /run/motd.d/*, /usr/lib/motd.d/*, /etc/update-motd.d/*).
MEX, MCT = ["initial_setup", "motd_exists"], ["initial_setup", "motd_content"]
MXF = ["initial_setup", "motd_extra_files"]
_extra_ok = (f'every f in {ref(MXF)} {{ is_string(f.content); '
             f'not regex.match({json.dumps(base.SYSINFO)}, f.content) }}')
_s = put24("1.6.1", "/etc/motd is configured", custom(
    None,
    [[f'{ref(MEX)} == false', _extra_ok],
     [f'{ref(MEX)} == true', f'not regex.match({json.dumps(base.SYSINFO)}, {ref(MCT)})', _extra_ok]],
    "initial_setup.motd_exists/motd_content/motd_extra_files",
    {"initial_setup": {"motd_exists": True, "motd_content": "Authorized uses only. All activity may be monitored.",
                       "motd_extra_files": [{"path": "/etc/motd.d/10-site", "content": "Authorized uses only."}]}},
    {"initial_setup": {"motd_exists": True, "motd_content": "Authorized uses only.",
                       "motd_extra_files": [{"path": "/etc/update-motd.d/00-header", "content": "Welcome to Ubuntu 24.04 LTS"}]}},
    {}, reads=[MEX, MCT, MXF],
    ev_alts=[[f'{ref(MEX)} == false', f'is_array({ref(MXF)})'],
             [f'{ref(MEX)} == true', f'is_string({ref(MCT)})', f'is_array({ref(MXF)})']]))
_s.hollow_ok = True   # an empty banner and an empty file list are real values

# 2.2.4 / 2.2.6: the packages the 24.04 audit names (26.04 names more)
put24("2.2.4", "telnet client", base.pkg_absent(["telnet", "inetutils-telnet"]))
put24("2.2.6", "ftp client", base.pkg_absent(["ftp", "tnftp"]))

# 4.1.5: 24.04 accepts `deny` or `disabled` for routed traffic as reported by `ufw status verbose`
put24("4.1.5", "routed default", custom(
    [f'is_string({ref(UV)})'], [['ufw_default("routed") in {"deny", "disabled"}']], dotted(UV),
    nest(UV, UVOK), nest(UV, UVOK.replace("deny (routed)", "allow (routed)")), reads=[UV]))

# 5.1.23: Automated in 24.04. sntrup761x25519-sha512 must be offered; from OpenSSH 9.9 mlkem768x25519-sha256 too.
# ssh.openssh_version is the version string of `sshd -V` ("9.6", "9.6p1", "OpenSSH_9.6p1").
_kex = "port 22\nkexalgorithms {}"
put24("5.1.23", "post-quantum", custom(
    ['ssh_collected', 'sshd_first("kexalgorithms")', 'openssh_version[0] >= 0'],
    [['kex_offered("sntrup761x25519-sha512")', 'not openssh_at_least_9_9'],
     ['kex_offered("sntrup761x25519-sha512")', 'kex_offered("mlkem768x25519-sha256")']],
    "ssh.sshd_config_raw (effective kexalgorithms)/ssh.openssh_version",
    {"ssh": {"sshd_config_raw": _kex.format("sntrup761x25519-sha512@openssh.com,curve25519-sha256"), "openssh_version": "9.6p1"}},
    {"ssh": {"sshd_config_raw": _kex.format("curve25519-sha256,ecdh-sha2-nistp256"), "openssh_version": "9.6p1"}},
    ssh_in(["port 22"]), reads=[base.SSH_RAW, ["ssh", "openssh_version"]]))

# 5.1.24: the audit asks that sshd listen on a private network interface. Decided from the effective
# configuration: at least one listenaddress, and every one a private (10/8, 172.16/12, 192.168/16, fc00::/7)
# or loopback address. The wildcard (0.0.0.0, [::], what sshd reports when the directive is unset), a public
# address or a name sshd did not resolve fails. Loopback is accepted: it exposes less than a private interface.
put24("5.1.24", "ListenAddress", custom(
    ['ssh_collected', 'sshd_first("listenaddress")'],
    [['count(sshd_all("listenaddress")) > 0', 'every v in sshd_all("listenaddress") { listen_private(v) }']],
    "ssh.sshd_config_raw (effective listenaddress)",
    ssh_in(["port 22", "listenaddress 192.168.1.14:22"]),
    ssh_in(["port 22", "listenaddress 192.168.1.14:22", "listenaddress [::]:22"]), ssh_in(["port 22"]),
    reads=[base.SSH_RAW]))

# 5.2.1: sudo or sudo-ldap (no sudo-rs in 24.04)
put24("5.2.1", "sudo is installed", custom(
    None, [['input.packages.sudo == true'], ['input.packages["sudo-ldap"] == true']], "packages[sudo,sudo-ldap]",
    {"packages": {"sudo": True, "sudo-ldap": False}}, {"packages": {"sudo": False, "sudo-ldap": False}}, {},
    reads=[["packages", "sudo"], ["packages", "sudo-ldap"]],
    ev_alts=[['input.packages.sudo == true'], ['input.packages["sudo-ldap"] == true'],
             ['is_boolean(input.packages.sudo)', 'is_boolean(input.packages["sudo-ldap"])']]))

# 5.2.3: a Defaults logfile= entry in sudoers (24.04 has no journald alternative)
put24("5.2.3", "sudo log file", custom(
    [f'is_string({ref(SU)})'], [['sudo_logfile']], dotted(SU),
    nest(SU, 'Defaults logfile="/var/log/sudo.log"'), nest(SU, "Defaults use_pty"), reads=[SU]))

# 5.2.6: every configured timestamp_timeout within 0..15 minutes; with none configured the compiled-in
# default applies, which the audit reads from `sudo -V` (sudo.default_timestamp_timeout, minutes).
DTT = ["sudo", "default_timestamp_timeout"]
put24("5.2.6", "timestamp_timeout", custom(
    None,
    [['count(sudo_timeouts) > 0', 'every t in sudo_timeouts { t >= 0; t <= 15 }'],
     ['count(sudo_timeouts) == 0', f'{ref(DTT)} >= 0', f'{ref(DTT)} <= 15']],
    "sudo.sudoers_content/sudo.default_timestamp_timeout",
    nest(SU, "Defaults env_reset, timestamp_timeout=15"), nest(SU, "Defaults timestamp_timeout=-1"),
    nest(SU, "Defaults use_pty"), reads=[SU, DTT],
    ev_alts=[[f'is_string({ref(SU)})', 'count(sudo_timeouts) > 0'],
             [f'is_string({ref(SU)})', f'is_number({ref(DTT)})']]))

# 6.1.2.6: the 24.04 audit looks for TCP reception only (imtcp, $InputTCPServerRun)
put24("6.1.2.6", "receive logs", base.text_has(
    RC, "(?i)(^module\\(\\s*load\\s*=\\s*\"?imtcp\"?[\\s,)]|^input\\(\\s*type\\s*=\\s*\"?imtcp\"?|"
        "^\\$ModLoad\\s+imtcp\\b|^\\$InputTCPServerRun\\b)",
    False, "*.* /var/log/syslog", 'module(load="imtcp")'))

# 6.2.3 audit rules. Every 24.04 audit procedure reads the running rules (auditd.active_rules) AND the on-disk rules
# (auditd.rules); base.audit requires a rule in both. The 24.04 audit lists every syscall rule for arch=b64 and
# arch=b32, so both are required (6.2.3.28: both on disk, the arch=b64 rule in the running rules); file watches may
# be written `-w <path> -p wa` or `-F path=<path> -F perm=wa`.
audit = base.audit
SRCS = json.dumps(list(base.SRCS))
put24("6.2.3.1", "sudoers", audit([("/etc/sudoers", "wa"), ("/etc/sudoers.d", "wa")]))
put24("6.2.3.2", "another user", audit(syscalls=[(["execve"], ["euid"])], arches=True))
put24("6.2.3.4", "date and time", audit([("/etc/localtime", "wa")],
                                        [(["adjtimex", "settimeofday", "clock_settime"], [])], arches=True))
put24("6.2.3.5", "sethostname", audit(syscalls=[(["sethostname", "setdomainname"], [])], arches=True))
put24("6.2.3.8", "/etc/network and /etc/networks", audit([("/etc/networks", "wa"), ("/etc/network", "wa")]))
# "IF the directory /etc/netplan does not exist, this is a passing state": netplan.dir_exists false passes
_s = put24("6.2.3.9", "/etc/netplan", audit([("/etc/netplan", "wa")]))
_s.ev_alts = _s.ev_alts + [['input.netplan.dir_exists == false']]
_s.passes = _s.passes + [['input.netplan.dir_exists == false']]
_s.reads = _s.reads + [["netplan", "dir_exists"]]
_s.field = f"{_s.field} (or netplan.dir_exists)"
_ACCESS = ["creat", "open", "openat", "truncate", "ftruncate"]
put24("6.2.3.17", "unsuccessful file access", audit(syscalls=[(_ACCESS, ["eacces"]), (_ACCESS, ["eperm"])], arches=True))
put24("6.2.3.18", "discretionary access control", audit(syscalls=[(
    ["chmod", "fchmod", "fchmodat", "chown", "fchown", "lchown", "fchownat", "setxattr", "lsetxattr", "fsetxattr",
     "removexattr", "lremovexattr", "fremovexattr"], ["auid"])], arches=True))
put24("6.2.3.19", "mounts", audit(syscalls=[(["mount"], ["auid"])], arches=True))
put24("6.2.3.22", "file deletion", audit(syscalls=[(["unlink", "unlinkat", "rename", "renameat", "renameat2"], ["auid"])],
                                         arches=True))
EXEC_OK = "-a always,exit -F path={p} -F perm=x -F auid>=1000 -F auid!=unset -F key=k"


def audit_exec(path):
    """use of one command: an always,exit rule on its path with perm=x and the auid filters, in both rule sources"""
    return custom(base.AUDIT_EV, [[f'every src in {SRCS} {{ audit_src_exec(src, {json.dumps(path)}) }}']],
                  base.AUDIT_FIELD, base.both([EXEC_OK.format(p=path)]), base.both([f"-w {path} -p x -k k"]),
                  nest(AR, [EXEC_OK.format(p=path)]), reads=[base.ARD, AR])


put24("6.2.3.24", "chcon", audit_exec("/usr/bin/chcon"))
put24("6.2.3.25", "setfacl", audit_exec("/usr/bin/setfacl"))
put24("6.2.3.26", "chacl", audit_exec("/usr/bin/chacl"))
put24("6.2.3.27", "usermod", audit_exec("/usr/sbin/usermod"))
# 6.2.3.28: one recommendation for the module syscalls (both arches) and the kmod binary. create_module and
# query_module, which the example output also lists, are not required: they no longer exist in the kernel and
# auditctl refuses them on arm64.
_KMOD = ["init_module", "finit_module", "delete_module"]
_KARCH = {"rules": ("b32", "b64"), "active_rules": ("b64",)}
_kmod_rules = base.syscall_good(_KMOD, ["auid"], _KARCH)
put24("6.2.3.28", "kernel module loading", custom(
    base.AUDIT_EV,
    [base.syscall_conds(_KMOD, ["auid"], _KARCH) + [f'every src in {SRCS} {{ audit_src_exec(src, "/usr/bin/kmod") }}']],
    base.AUDIT_FIELD, base.both(_kmod_rules + [EXEC_OK.format(p="/usr/bin/kmod")]), base.both(_kmod_rules),
    nest(AR, _kmod_rules + [EXEC_OK.format(p="/usr/bin/kmod")]), reads=[base.ARD, AR]))

# 6.3.3: 24.04 still ships autrace, so six audit tools
TOOLS = ["auditctl", "auditd", "ausearch", "aureport", "autrace", "augenrules"]
put24("6.3.3", "integrity of audit tools", custom(
    ['is_object(input.aide.audit_tool_options)'],
    [[f'every t in {json.dumps(TOOLS)} {{ aide_opts_ok(input.aide.audit_tool_options[t]) }}']],
    "aide.audit_tool_options",
    {"aide": {"audit_tool_options": {t: base.AIDE_OPTS for t in TOOLS}}},
    {"aide": {"audit_tool_options": {t: base.AIDE_OPTS for t in TOOLS if t != "autrace"}}},
    reads=[["aide", "audit_tool_options"]]))

# 1.3.1.3: the 24.04 audit reads profiles loaded (> 0), in enforce mode (all of them), in complain mode (0)
# and processes unconfined (0); the other apparmor_status counters are not part of it.
_prof = {"loaded": 34, "enforce": 34, "complain": 0}
put24("1.3.1.3", "AppArmor Profiles are enforcing", custom(
    ['input.apparmor.profiles.loaded != null', 'input.apparmor.profiles.enforce != null',
     'input.apparmor.profiles.complain != null', 'input.apparmor.processes.unconfined != null'],
    [['num(input.apparmor.profiles.loaded) > 0', 'num(input.apparmor.profiles.enforce) == num(input.apparmor.profiles.loaded)',
      'num(input.apparmor.profiles.complain) == 0', 'num(input.apparmor.processes.unconfined) == 0']],
    "apparmor.profiles/apparmor.processes",
    {"apparmor": {"profiles": _prof, "processes": {"unconfined": 0}}},
    {"apparmor": {"profiles": dict(_prof, enforce=32, complain=2), "processes": {"unconfined": 0}}},
    reads=[["apparmor", "profiles"], ["apparmor", "processes"]]))

# 6.2.4.8-10: the six tools the 24.04 audit names (/sbin paths; matched on the file name because /sbin is a
# symlink to /usr/sbin), each of which must be in auditd.tools; a tool not reported is missing evidence.
ATOOLS = ["auditctl", "aureport", "ausearch", "autrace", "auditd", "augenrules"]
ATL = ["auditd", "tools"]
_tool = {"mode": "0755", "owner": "root", "group": "root"}
for rid, kw, key, cond, badv in [
        ("6.2.4.8", "tools mode", "mode", 'mode_within(f.mode, "0755")', "0777"),
        ("6.2.4.9", "tools owner", "owner", 'f.owner == "root"', "adm"),
        ("6.2.4.10", "tools group", "group", 'f.group == "root"', "adm")]:
    good = [dict(_tool, path=f"/usr/sbin/{n}") for n in ATOOLS]
    put24(rid, kw, custom(
        [f'is_array({ref(ATL)})', f'every n in {json.dumps(ATOOLS)} {{ audit_tool_reported(n) }}'],
        [[f'every f in {ref(ATL)} {{ {cond} }}']], dotted(ATL) + "[" + ",".join(ATOOLS) + "]",
        nest(ATL, good), nest(ATL, good[:-1] + [dict(good[-1], **{key: badv})]), nest(ATL, good[:3] + good[4:]),
        reads=[ATL]))

# ── helpers used by one module only: the 26.04 ones plus what the entries above call ─────────────
EXTRA = dict(base.EXTRA)
del EXTRA["process_hardening"]   # core file size limit: not a 24.04 recommendation
EXTRA["ssh"] = base.EXTRA["ssh"].rstrip("\n") + r'''

# every value of a directive that may repeat (`sshd -T` prints one line per ListenAddress)
sshd_all(key) := [p[1] | some p in sshd_pairs; p[0] == key]

# the address of a ListenAddress value: "10.0.0.5:22" / "[fd00::5]:22" / "fd00::5" / "10.0.0.5"
listen_host(v) := m[1] if {
	some m in regex.find_all_string_submatch_n(`^\[([^\]]+)\](:[0-9]+)?$`, trim_space(v), 1)
} else := m[1] if {
	some m in regex.find_all_string_submatch_n(`^([0-9.]+)(:[0-9]+)?$`, trim_space(v), 1)
} else := trim_space(v)

private_nets := ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"]

listen_private(v) if {
	h := listen_host(v)
	regex.match(`^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)$`, h)
	some n in private_nets
	net.cidr_contains(n, h)
}

# [major, minor] from input.ssh.openssh_version ("9.6", "9.6p1", "OpenSSH_9.6p1")
openssh_version := [to_number(m[1]), to_number(m[2])] if {
	is_string(input.ssh.openssh_version)
	some m in regex.find_all_string_submatch_n(`([0-9]+)\.([0-9]+)`, input.ssh.openssh_version, 1)
}

openssh_at_least_9_9 if openssh_version[0] > 9

openssh_at_least_9_9 if {
	openssh_version[0] == 9
	openssh_version[1] >= 9
}

# a key exchange algorithm offered under its own name or its @openssh.com name
kex_offered(name) if {
	some x in sshd_list("kexalgorithms")
	x in {name, concat("", [name, "@openssh.com"])}
}
'''
EXTRA["auditd"] = base.EXTRA["auditd"].rstrip("\n") + r'''

# auditd.tools holds an entry for the named tool (any directory: /sbin is /usr/sbin on Ubuntu)
audit_tool_reported(n) if {
	some f in input.auditd.tools
	regex.replace(f.path, `^.*/`, "") == n
}

'''

# ── regression tests appended to the generated test files (keyed by module; 24.04 ids) ───────────
REGRESSION_TESTS = {
    "banners": r'''
# 1.6.1 reads every message-of-the-day file the audit names, not only /etc/motd.
test_motd_extra_file_with_release_text_flagged if {
	vs := data.cis_ubuntu_24_04.banners.violations with input as {"initial_setup": {"motd_exists": false, "motd_extra_files": [{"path": "/run/motd.d/x", "content": "kernel \\r on \\m"}]}}
	count([v | some v in vs; startswith(v, "1.6.1: not met")]) > 0
}

test_motd_absent_and_no_extra_files_passes if {
	vs := data.cis_ubuntu_24_04.banners.violations with input as {"initial_setup": {"motd_exists": false, "motd_extra_files": []}}
	count([v | some v in vs; startswith(v, "1.6.1: ")]) == 0
}

test_motd_extra_files_not_collected_is_missing_evidence if {
	vs := data.cis_ubuntu_24_04.banners.violations with input as {"initial_setup": {"motd_exists": false}}
	count([v | some v in vs; startswith(v, "1.6.1: evidence missing")]) > 0
}
''',
    "logging": r'''
# module(load="imtcp" ...params) and `input( type=` are remote-receive configuration.
test_remote_receive_module_with_params_flagged if {
	vs := data.cis_ubuntu_24_04.logging.violations with input as {"rsyslog": {"installed": true, "config_raw": "module(load=\"imtcp\" MaxSessions=\"500\")\n"}}
	count([v | some v in vs; startswith(v, "6.1.2.6: not met")]) > 0
}

test_remote_receive_input_with_space_flagged if {
	vs := data.cis_ubuntu_24_04.logging.violations with input as {"rsyslog": {"installed": true, "config_raw": "input( type=\"imtcp\" port=\"514\")\n"}}
	count([v | some v in vs; startswith(v, "6.1.2.6: not met")]) > 0
}

test_remote_receive_commented_out_not_flagged if {
	vs := data.cis_ubuntu_24_04.logging.violations with input as {"rsyslog": {"installed": true, "config_raw": "#module(load=\"imtcp\")\n*.* /var/log/messages\n"}}
	count([v | some v in vs; startswith(v, "6.1.2.6: ")]) == 0
}
''',
    "services": r'''
# 0.0.0.0 is the wildcard address, 127.0.0.1 is loopback, every token must be loopback.
test_mta_inet_interfaces_wildcard_address_flagged if {
	vs := data.cis_ubuntu_24_04.services.violations with input as {"mta": {"non_loopback_listeners": [], "inet_interfaces": "0.0.0.0"}}
	count([v | some v in vs; startswith(v, "2.1.2: not met")]) > 0
}

test_mta_inet_interfaces_127_0_0_1_accepted if {
	vs := data.cis_ubuntu_24_04.services.violations with input as {"mta": {"non_loopback_listeners": [], "inet_interfaces": "127.0.0.1"}}
	count([v | some v in vs; startswith(v, "2.1.2: ")]) == 0
}

test_mta_inet_interfaces_mixed_list_flagged if {
	vs := data.cis_ubuntu_24_04.services.violations with input as {"mta": {"non_loopback_listeners": [], "inet_interfaces": "localhost, 192.0.2.10"}}
	count([v | some v in vs; startswith(v, "2.1.2: not met")]) > 0
}
''',
    "ssh": r'''
# The `+` append syntax enables the named weak algorithm.
test_ciphers_plus_append_syntax_flagged if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "port 22\nciphers +aes128-cbc"}}
	count([v | some v in vs; startswith(v, "5.1.6: not met")]) > 0
}

test_kex_plus_append_syntax_flagged if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "port 22\nkexalgorithms +diffie-hellman-group1-sha1"}}
	count([v | some v in vs; startswith(v, "5.1.12: not met")]) > 0
}

test_macs_plus_append_syntax_flagged if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "port 22\nmacs +hmac-md5"}}
	count([v | some v in vs; startswith(v, "5.1.15: not met")]) > 0
}

# 5.1.23: from OpenSSH 9.9 the ML-KEM hybrid is required as well; a version that is not collected is missing evidence.
test_post_quantum_kex_openssh_9_9_needs_mlkem if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "kexalgorithms sntrup761x25519-sha512,curve25519-sha256", "openssh_version": "OpenSSH_9.9p1"}}
	count([v | some v in vs; startswith(v, "5.1.23: not met")]) > 0
}

test_post_quantum_kex_openssh_10_with_both_passes if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "kexalgorithms mlkem768x25519-sha256,sntrup761x25519-sha512", "openssh_version": "10.0"}}
	count([v | some v in vs; startswith(v, "5.1.23: ")]) == 0
}

test_post_quantum_kex_version_not_collected if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "kexalgorithms sntrup761x25519-sha512"}}
	count([v | some v in vs; startswith(v, "5.1.23: evidence missing")]) > 0
}

test_post_quantum_kex_longer_name_is_not_a_match if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "kexalgorithms xsntrup761x25519-sha512-legacy", "openssh_version": "9.6"}}
	count([v | some v in vs; startswith(v, "5.1.23: not met")]) > 0
}

# 5.1.24: only private or loopback addresses; 0.0.0.0 and [::] are what sshd reports when ListenAddress is unset.
test_listenaddress_public_address_flagged if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "listenaddress 203.0.113.5:22"}}
	count([v | some v in vs; startswith(v, "5.1.24: not met")]) > 0
}

test_listenaddress_unresolved_name_flagged if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "listenaddress bastion.example.com:22"}}
	count([v | some v in vs; startswith(v, "5.1.24: not met")]) > 0
}

test_listenaddress_bare_private_ipv6_accepted if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "listenaddress fd00::14"}}
	count([v | some v in vs; startswith(v, "5.1.24: ")]) == 0
}

test_listenaddress_ipv4_wildcard_flagged if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "listenaddress 0.0.0.0:22"}}
	count([v | some v in vs; startswith(v, "5.1.24: not met")]) > 0
}

test_listenaddress_loopback_and_private_accepted if {
	vs := data.cis_ubuntu_24_04.ssh.violations with input as {"ssh": {"sshd_config_raw": "listenaddress 127.0.0.1:22\nlistenaddress [fd00::14]:22"}}
	count([v | some v in vs; startswith(v, "5.1.24: ")]) == 0
}
''',
    "sudo": r'''
# 5.2.6: with no timestamp_timeout in sudoers the compiled-in default decides; -1 disables the timeout.
test_timestamp_timeout_default_within_limit_passes if {
	vs := data.cis_ubuntu_24_04.sudo.violations with input as {"sudo": {"sudoers_content": "Defaults use_pty", "default_timestamp_timeout": 15}}
	count([v | some v in vs; startswith(v, "5.2.6: ")]) == 0
}

test_timestamp_timeout_default_too_long_flagged if {
	vs := data.cis_ubuntu_24_04.sudo.violations with input as {"sudo": {"sudoers_content": "Defaults use_pty", "default_timestamp_timeout": 30}}
	count([v | some v in vs; startswith(v, "5.2.6: not met")]) > 0
}

test_timestamp_timeout_one_bad_entry_among_good_flagged if {
	vs := data.cis_ubuntu_24_04.sudo.violations with input as {"sudo": {"sudoers_content": "Defaults timestamp_timeout=5\nDefaults:alice timestamp_timeout=-1", "default_timestamp_timeout": 15}}
	count([v | some v in vs; startswith(v, "5.2.6: not met")]) > 0
}

test_timestamp_timeout_commented_entry_is_not_configuration if {
	vs := data.cis_ubuntu_24_04.sudo.violations with input as {"sudo": {"sudoers_content": "#Defaults timestamp_timeout=5\nDefaults use_pty"}}
	count([v | some v in vs; startswith(v, "5.2.6: evidence missing")]) > 0
}
''',
    "auditd": r'''
# Syscall rules are required for both architectures.
test_mount_rule_for_b64_only_flagged if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=mounts"], "active_rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -F key=mounts"]}}
	count([v | some v in vs; startswith(v, "6.2.3.19: not met")]) > 0
}

test_mount_rule_for_both_arches_passes if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"], "active_rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"]}}
	count([v | some v in vs; startswith(v, "6.2.3.19: ")]) == 0
}

# A longer path is a different watch: /etc/networks does not cover /etc/network.
test_networks_watch_alone_flagged if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": ["-w /etc/networks -p wa -k system-locale"], "active_rules": ["-w /etc/networks -p wa -k system-locale"]}}
	count([v | some v in vs; startswith(v, "6.2.3.8: not met")]) > 0
}

test_network_watches_in_w_form_pass if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": ["-w /etc/networks -p wa -k system-locale", "-w /etc/network -p wa -k system-locale"], "active_rules": ["-w /etc/networks -p wa -k system-locale", "-w /etc/network -p wa -k system-locale"]}}
	count([v | some v in vs; startswith(v, "6.2.3.8: ")]) == 0
}

# /etc/netplan absent is a passing state, on a collected fact only.
test_netplan_directory_absent_passes if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"netplan": {"dir_exists": false}}
	count([v | some v in vs; startswith(v, "6.2.3.9: ")]) == 0
}

test_netplan_directory_present_without_rule_flagged if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"netplan": {"dir_exists": true}, "auditd": {"rules": ["-w /etc/hosts -p wa"], "active_rules": ["-w /etc/hosts -p wa"]}}
	count([v | some v in vs; startswith(v, "6.2.3.9: not met")]) > 0
}

# Command-use rules carry the auid filters; the running configuration prints `-S all`.
test_chcon_rule_as_printed_by_auditctl_passes if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng"], "active_rules": ["-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng"]}}
	count([v | some v in vs; startswith(v, "6.2.3.24: ")]) == 0
}

test_chcon_rule_without_auid_filters_flagged if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F path=/usr/bin/chcon -F perm=x -F key=perm_chng"], "active_rules": ["-a always,exit -F path=/usr/bin/chcon -F perm=x -F key=perm_chng"]}}
	count([v | some v in vs; startswith(v, "6.2.3.24: not met")]) > 0
}

# 6.2.3: a rule is required in the on-disk rules (auditd.rules) AND the running rules (auditd.active_rules).
test_mount_rules_running_only_flagged if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": [], "active_rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"]}}
	count([v | some v in vs; startswith(v, "6.2.3.19: not met")]) > 0
}

test_mount_rules_on_disk_only_flagged if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"], "active_rules": []}}
	count([v | some v in vs; startswith(v, "6.2.3.19: not met")]) > 0
}

test_mount_rules_on_disk_not_collected_is_missing if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"active_rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"]}}
	"6.2.3.19: evidence missing — auditd.rules/active_rules not collected" in vs
}

# 6.2.3.28: both architectures on disk, the arch=b64 module rule in the running rules.
test_module_rules_b64_running_both_on_disk_passes if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"], "active_rules": ["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"]}}
	count([v | some v in vs; startswith(v, "6.2.3.28: ")]) == 0
}

test_module_rules_b64_only_on_disk_flagged if {
	vs := data.cis_ubuntu_24_04.auditd.violations with input as {"auditd": {"rules": ["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"], "active_rules": ["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel_modules", "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"]}}
	count([v | some v in vs; startswith(v, "6.2.3.28: not met")]) > 0
}
''',
    "apparmor": r'''
# 1.3.1.3: the counters the 24.04 audit does not name are not required.
test_profiles_enforcing_without_prompt_kill_counters_passes if {
	vs := data.cis_ubuntu_24_04.apparmor.violations with input as {"apparmor": {"profiles": {"loaded": 10, "enforce": 10, "complain": 0}, "processes": {"unconfined": 0}}}
	count([v | some v in vs; startswith(v, "1.3.1.3: ")]) == 0
}

test_profiles_unconfined_process_flagged if {
	vs := data.cis_ubuntu_24_04.apparmor.violations with input as {"apparmor": {"profiles": {"loaded": 10, "enforce": 10, "complain": 0}, "processes": {"unconfined": 1}}}
	count([v | some v in vs; startswith(v, "1.3.1.3: not met")]) > 0
}
''',
    "integrity": r'''
# 24.04 lists autrace among the audit tools.
test_audit_tools_without_autrace_flagged if {
	vs := data.cis_ubuntu_24_04.integrity.violations with input as {"aide": {"audit_tool_options": {"auditctl": "p+i+n+u+g+s+b+acl+xattrs+sha512", "auditd": "p+i+n+u+g+s+b+acl+xattrs+sha512", "ausearch": "p+i+n+u+g+s+b+acl+xattrs+sha512", "aureport": "p+i+n+u+g+s+b+acl+xattrs+sha512", "augenrules": "p+i+n+u+g+s+b+acl+xattrs+sha512"}}}
	count([v | some v in vs; startswith(v, "6.3.3: not met")]) > 0
}
''',
    f"{PKG}_main": base.REGRESSION_TESTS[f"{base.FILE_STEM}_main"].replace(base.PKG, PKG),
}


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    base.OUT = base.HERE.parent.parent / "benchmarks" / "cis" / "ubuntu_24_04"
    base.PKG = base.FILE_STEM = PKG
    base.GEN = "tools/cis_generators/gen_ubuntu_24_04.py"
    base.BENCH, base.VERSION = BENCH, "v2.0.1"
    base.EXPECTED_TOTAL, base.EXPECTED_AUTOMATED, base.EXPECTED_MANUAL = 332, 317, 15
    base.PROFILE_NOTE = """Levels differ by platform (e.g. 1.1.1.9 is
# Level 1 Server but Level 2 Workstation), so each control carries its own server/workstation level, and eight
# recommendations (1.2.1.3, 1.2.1.4, 1.2.1.5, 1.2.1.7, 1.2.1.8, 1.2.1.9, 2.1.23, 3.1.2) are on no Workstation sheet."""
    base.L, base.KW, base.EXTRA, base.REGRESSION_TESTS = L, KW, EXTRA, REGRESSION_TESTS
    base.MAIN_VIOLATION_COUNT = True   # the report contract of the framework keys asks for it
    base.main()


if __name__ == "__main__":
    main()
