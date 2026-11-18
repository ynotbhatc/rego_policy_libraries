#!/usr/bin/env python3
"""CIS Amazon Linux 2023 Benchmark v1.0.0: every recommendation, from the benchmark's own workbook.

    python3 tools/cis_generators/gen_amazon_linux_2023.py CIS_Amazon_Linux_2023_Benchmark_v1.0.0.xlsx [fields.json]

Needs openpyxl. Reads id, title, Assessment Status and profiles (Level 1 / Level 2 - Server sheets) out of
the CIS workbook (CIS-licensed, never committed), checks them against the hand-authored logic table below
and emits benchmarks/cis/amazon_linux_2023/. The run aborts on any count, Automated/Manual status, profile,
logic or title-keyword mismatch with the workbook: put(id, keyword, spec) requires the keyword to occur in
the workbook title of that id, so a logic entry attached to a renumbered id cannot slip through.

Built on gen_rhel_9.py (imported, never modified): its workbook reader, Spec builders, shared Rego helpers
and per-control emitter are reused, and wherever an Amazon Linux 2023 recommendation checks the same thing
as a RHEL 9 v3.0.0 recommendation the RHEL 9 logic entry itself is reused through rh(<rhel id>, <keyword>),
which also checks the RHEL 9 keyword so a change in that table cannot silently swap the logic. The mapping is
by what each audit procedure checks, never by id: the two benchmarks number their sections differently.
The input contract is the shared Linux mapper's (the one cis_rhel9 reads); facts this benchmark needs beyond
it are marked "new" where they are introduced.

Layout (the rhel_9 one): fourteen section packages cis_amazon_linux_2023.<section>, the roll-up package
cis_amazon_linux_2023 and the bridge cis_amazon_linux_2023.main (compliance_report). The deprecated package
cis.amazon_linux_2023 is emitted as a thin view of the bridge because a caller still reads its
violations / compliance_summary.

Rules of the generated code:
  * every Automated recommendation evaluates real facts; facts not collected =>
    "<id>: evidence missing — <field> not collected" (fail closed, never a pass);
  * every Manual recommendation is an attestation boolean input.attest.<name> (not attested => violation);
  * messages are our words. The control id is carried from the workbook; the wording is original
    (neutralize.publish_titles) and the benchmark title is not copied;
  * the tests give every recommendation a pass and a fail case, plus an evidence-missing case for every
    Automated one.

The generator writes only the files listed in main(); it never deletes anything.
"""
import copy
import json
import pathlib
import re
import sys

import gen_rhel_9 as R
from neutralize import publish_titles

_NEED = ["Spec", "custom", "attest", "kmod", "mnt_sep", "mnt_opt", "mo_sep", "mo_opt", "sysctl", "pkg_present",
         "pkg_absent", "units_off", "boolean", "crit", "sshd", "gate", "audit", "shadow_rule", "ref", "nest", "merge",
         "dotted", "HELPERS", "EXTRA", "L", "KW", "read_workbook", "level", "J", "idkey", "sort_key", "emit_control",
         "merge_good", "hollow", "FSM", "NETM", "AR", "AC", "KA", "GRUB", "PQ", "W", "S64", "RNI", "ssh_in", "SSH_RAW",
         "PAMOK", "AS_OF"]
_missing = [n for n in _NEED if not hasattr(R, n)]
if _missing:
    raise SystemExit(f"gen_rhel_9.py no longer provides {_missing}; gen_amazon_linux_2023.py imports them")

Spec, custom, attest, ref, nest, merge, dotted, J = R.Spec, R.custom, R.attest, R.ref, R.nest, R.merge, R.dotted, R.J
idkey, sort_key = R.idkey, R.sort_key

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent.parent / "benchmarks" / "cis" / "amazon_linux_2023"
PKG = "cis_amazon_linux_2023"
LEGACY_PKG = "cis.amazon_linux_2023"
GEN = "tools/cis_generators/gen_amazon_linux_2023.py"
BENCH = "CIS Amazon Linux 2023 Benchmark v1.0.0"
VERSION = "v1.0.0"
EXPECTED_TOTAL = 243
EXPECTED_AUTOMATED = 217
EXPECTED_MANUAL = 26
EXPECTED_LEVEL1 = 179
EXPECTED_LEVEL2 = 64
README_DATE = "2026-11-14"

# module name, file, section key (the keys the previous module's roll-up used: callers read them), title,
# id prefixes (an id belongs to a prefix when it equals it or continues it with ".")
SECTIONS = [
    ("filesystem", "filesystem_validation.rego", "section_1_1_filesystem",
     "Section 1.1: Filesystem Configuration", ["1.1"]),
    ("initial_setup", "initial_setup_validation.rego", "section_1_2_1_7_1_8_initial_setup",
     "Sections 1.2, 1.7-1.9: Software Updates, Banners, Patching, Crypto Policy", ["1.2", "1.7", "1.8", "1.9"]),
    ("boot_security", "boot_security_validation.rego", "section_1_3_1_4_1_5_boot_security",
     "Sections 1.3-1.5: Integrity Checking (AIDE), Bootloader, Process Hardening", ["1.3", "1.4", "1.5"]),
    ("selinux", "selinux_validation.rego", "section_1_6_selinux",
     "Section 1.6: Mandatory Access Control (SELinux)", ["1.6"]),
    ("services", "service_validation.rego", "section_2_services",
     "Section 2: Time Synchronization, Special Purpose Services, Service Clients", ["2"]),
    ("network", "network_validation.rego", "section_3_network",
     "Section 3: Network Configuration, Host Based Firewall", ["3"]),
    ("auditd", "auditd_validation.rego", "section_4_1_auditd",
     "Section 5.2: System Auditing (auditd)", ["5.2"]),
    ("logging", "logging_validation.rego", "section_4_2_logging",
     "Sections 5.1, 5.3: System Logging (rsyslog, journald), logrotate", ["5.1", "5.3"]),
    ("cron", "cron_validation.rego", "section_5_1_cron",
     "Section 4.1: Job Schedulers", ["4.1"]),
    ("ssh", "ssh_validation.rego", "section_5_2_ssh",
     "Section 4.2: SSH Server", ["4.2"]),
    ("sudo", "sudo_validation.rego", "section_5_3_sudo",
     "Section 4.3: Privilege Escalation", ["4.3"]),
    ("pam", "pam_validation.rego", "section_5_4_5_5_pam",
     "Sections 4.4-4.6: authselect, PAM, User Accounts and Environment", ["4.4", "4.5", "4.6"]),
    ("file_permissions", "file_permissions_validation.rego", "section_6_1_file_permissions",
     "Section 6.1: System File Permissions", ["6.1"]),
    ("user_group", "user_group_validation.rego", "section_6_2_user_group",
     "Section 6.2: Local User and Group Settings", ["6.2"]),
]
SEC = {n: (f, key, title, pre) for n, f, key, title, pre in SECTIONS}

# NOT ASSESSED: a section is assessed when any of these input keys is present. ansible_facts, services,
# packages and attest are deliberately absent (read by many sections; a payload carrying only those is not
# an assessment of the section). main() aborts when a key listed here is read by no control of the section.
SECTION_INPUTS = {
    "filesystem": ["mount_options", "disabled_filesystem_modules", "usb_storage"],
    "initial_setup": ["initial_setup"],
    "boot_security": ["boot_security"],
    "selinux": ["selinux"],
    "services": ["chronyd", "mta", "x11", "client_packages"],
    "network": ["sysctl_parameters", "ipv6", "firewall", "disabled_network_modules"],
    "auditd": ["auditd"],
    "logging": ["rsyslog", "journald", "log_file_permissions"],
    "cron": ["cron"],
    "ssh": ["ssh"],
    "sudo": ["sudo"],
    "pam": ["pam"],
    "file_permissions": ["critical_files", "world_writable", "unowned_files", "ungrouped_files", "sticky_bit"],
    "user_group": ["user_group"],
}

# roll-up recommendations (the shape the previous module exposed): priority, caller-facing name, action
RECOMMEND = {
    "ssh": ("critical", "SSH Server Configuration", "Harden the sshd configuration"),
    "auditd": ("critical", "System Auditing", "Configure the auditd service and the required audit rules"),
    "selinux": ("critical", "SELinux Configuration", "Enable SELinux with a targeted or mls policy"),
    "pam": ("high", "Password Authentication", "Configure password policy, lockout and account defaults"),
    "sudo": ("high", "Privilege Escalation", "Harden sudo configuration and restrict su access"),
    "logging": ("high", "Logging Configuration", "Configure journald and rsyslog"),
    "boot_security": ("high", "Boot Security & AIDE", "Protect the bootloader files, enable AIDE, harden process settings"),
    "network": ("high", "Network & Firewall", "Set the kernel network parameters and a single host firewall"),
    "cron": ("medium", "Cron Configuration", "Set permissions on cron files and restrict cron/at access"),
    "user_group": ("medium", "User and Group Settings", "Fix account, duplicate id and home directory findings"),
    "initial_setup": ("medium", "Initial Setup & Banners", "Configure package signature checks, banners and crypto policy"),
}


def section_of(rid):
    for name, _, _, _, prefixes in SECTIONS:
        if any(rid == p or rid.startswith(p + ".") for p in prefixes):
            return name
    raise SystemExit(f"no section for {rid}")


# ════════════════════════════════════════════════════════════════════════════════════════════
# LOGIC TABLE — one entry per recommendation, written from each audit procedure of the Amazon Linux 2023
# v1.0.0 workbook. put(id, keyword, spec): the keyword must occur in the workbook title of that id.
# ════════════════════════════════════════════════════════════════════════════════════════════
L = {}
KW = {}


def put(rid, kw, spec):
    if rid in L:
        raise SystemExit(f"{rid} defined twice")
    L[rid] = spec
    KW[rid] = kw
    return spec


def rh(rid, kw):
    """A private copy of the RHEL 9 v3.0.0 logic entry <rid>, whose own title keyword must contain kw. The
    RHEL 9 section it came from is recorded so its section helpers are emitted with it."""
    if rid not in R.L or kw.lower() not in R.KW[rid].lower():
        raise SystemExit(f"gen_rhel_9.py: logic entry {rid} is no longer the {kw!r} check")
    s = copy.deepcopy(R.L[rid])
    s.rhel_section = R.section_of(rid)
    return s


def uniq(xs):
    out = []
    for x in xs:
        if x not in out:
            out.append(x)
    return out


def overlay(base, top):
    """objects merged recursively, lists united, any other value of top replaces base's"""
    if isinstance(base, dict) and isinstance(top, dict):
        out = dict(base)
        for k, v in top.items():
            out[k] = overlay(out[k], v) if k in out else v
        return out
    if isinstance(base, list) and isinstance(top, list):
        return R.merge_good(base, top)
    return top


def all_of(*specs):
    """One recommendation that needs every given check: evidence and pass alternatives are multiplied out."""
    ev, ps = [[]], [[]]
    for s in specs:
        if getattr(s, "alts", None) or s.manual:
            raise SystemExit("all_of: plain Automated specs only")
        ev = [uniq(a + b) for a in ev for b in s.ev_alts]
        ps = [uniq(a + b) for a in ps for b in s.passes]
    tp = {}
    for s in specs:
        tp = R.merge_good(tp, s.tp)
    tf = {}  # the other checks satisfied, the first one's failing values laid over them (they win)
    for s in specs[1:]:
        tf = R.merge_good(tf, s.tp)
    tf = overlay(tf, specs[0].tf)
    reads = uniq([p for s in specs for p in s.reads])
    return Spec(None, ps, " / ".join(uniq([s.field for s in specs])), tp, tf, specs[0].tm, reads=reads, ev_alts=ev)


def hollow_ok(spec):
    spec.hollow_ok = True
    return spec


def gated(spec, pkg):
    """the check applies only when <pkg> is installed: a collected packages.<pkg> == false passes"""
    return R.gate(spec, ["packages", pkg], False, f"packages.{pkg}")


OTHER_UNIT = {"sshd.service": {"state": "running", "status": "enabled"}}


def pkg_or_units(pkg, units, fn):
    """package not installed, OR (installed) every named unit reported and fn(unit): unit_masked /
    unit_not_enabled"""
    p, us = ref(["packages", pkg]), json.dumps(units)
    rep = [f'{p} == true', 'services_collected', f'every u in {us} {{ unit_reported(u) }}']
    good = {u: {"state": "inactive", "status": "masked"} for u in units}
    return custom(None, [[f'{p} == false'], rep + [f'every u in {us} {{ {fn}(u) }}']],
                  f"packages[{pkg}] / services[" + ",".join(units) + "]",
                  {"packages": {pkg: True}, "services": merge(OTHER_UNIT, good)},
                  {"packages": {pkg: True},
                   "services": merge(OTHER_UNIT, good, {units[0]: {"state": "running", "status": "enabled"}})},
                  {"packages": {pkg: True}, "services": OTHER_UNIT},
                  reads=[["packages", pkg], ["services"]], ev_alts=[[f'{p} == false'], rep])


# ── 1.1 filesystem: kernel modules, /tmp and /dev/shm from mount_options, the rest from ansible_mounts ──
for rid, mod in [("1.1.1.1", "squashfs"), ("1.1.1.2", "udf"), ("1.1.1.3", "cramfs"), ("1.1.1.4", "freevxfs"),
                 ("1.1.1.5", "jffs2"), ("1.1.1.6", "hfs "), ("1.1.1.7", "hfsplus")]:
    put(rid, f"mounting of {mod}", R.kmod(R.FSM, mod.strip()))
put("1.1.2.1", "/tmp is a separate partition", R.mo_sep("tmp", tmp_unit=True))
for rid, o in [("1.1.2.2", "nodev"), ("1.1.2.3", "noexec"), ("1.1.2.4", "nosuid")]:
    put(rid, f"{o} option set on /tmp partition", R.mo_opt("tmp", o))
for base, part, opts in [("1.1.3", "/var", ["nodev", "nosuid"]),
                         ("1.1.4", "/var/tmp", ["noexec", "nosuid", "nodev"]),
                         ("1.1.5", "/var/log", ["nodev", "noexec", "nosuid"]),
                         ("1.1.6", "/var/log/audit", ["noexec", "nodev", "nosuid"]),
                         ("1.1.7", "/home", ["nodev", "nosuid"])]:
    put(base + ".1", "separate partition exists for " + part + " ", R.mnt_sep(part))
    for i, o in enumerate(opts, start=2):
        put(f"{base}.{i}", f"{o} option set on {part} partition", R.mnt_opt(part, o))
put("1.1.8.1", "/dev/shm is a separate partition", R.mo_sep("dev_shm"))
for rid, o in [("1.1.8.2", "nodev"), ("1.1.8.3", "noexec"), ("1.1.8.4", "nosuid")]:
    put(rid, f"{o} option set on /dev/shm partition", R.mo_opt("dev_shm", o))
put("1.1.9", "usb-storage is disabled", rh("1.1.1.10", "usb-storage"))

# ── 1.2 package management, 1.7 banners, 1.8 patching, 1.9 crypto policy ──
put("1.2.1", "GPG keys", attest("gpg_keys_reviewed"))
put("1.2.2", "gpgcheck is globally activated", rh("1.2.1.2", "gpgcheck"))
put("1.2.3", "repositories", attest("repositories_reviewed"))
put("1.2.4", "repo_gpgcheck", attest("repo_gpgcheck_reviewed"))
put("1.7.1", "message of the day", rh("1.7.1", "/etc/motd"))
put("1.7.2", "local login warning banner", rh("1.7.2", "/etc/issue"))
put("1.7.3", "remote login warning banner", rh("1.7.3", "/etc/issue.net"))
put("1.7.4", "permissions on /etc/motd", rh("1.7.4", "/etc/motd"))
put("1.7.5", "permissions on /etc/issue are", rh("1.7.5", "/etc/issue"))
put("1.7.6", "permissions on /etc/issue.net", rh("1.7.6", "/etc/issue.net"))
put("1.8", "updates, patches", attest("updates_installed"))
put("1.9", "crypto policy is not legacy", rh("1.6.1", "not legacy"))

# ── 1.3 AIDE, 1.4 bootloader files, 1.5 process hardening ──
put("1.3.1", "AIDE is installed", rh("6.3.1", "AIDE is installed"))
put("1.3.2", "regularly checked", rh("6.3.2", "regularly checked"))
put("1.3.3", "integrity of audit tools", rh("6.3.3", "integrity of audit tools"))
put("1.4.1", "permissions on bootloader config", rh("1.4.2", "bootloader config"))
put("1.5.1", "address space layout randomization", rh("1.5.6", "randomize_va_space"))
# this benchmark's audit script compares for equality with 1 (RHEL 9 v3.0.0 also accepts 2 and 3)
put("1.5.2", "ptrace_scope", R.sysctl("kernel.yama.ptrace_scope", ["1"]))
put("1.5.3", "core dump storage", rh("1.5.10", "Storage"))
put("1.5.4", "core dump backtraces", rh("1.5.9", "ProcessSizeMax"))

# ── 1.6 SELinux ──
put("1.6.1.1", "SELinux is installed", rh("1.3.1.1", "installed"))
put("1.6.1.2", "not disabled in bootloader", rh("1.3.1.2", "bootloader"))
put("1.6.1.3", "SELinux policy", rh("1.3.1.3", "policy"))
put("1.6.1.4", "mode is not disabled", rh("1.3.1.4", "not disabled"))
put("1.6.1.5", "mode is enforcing", rh("1.3.1.5", "enforcing"))
put("1.6.1.6", "unconfined services", attest("no_unconfined_services"))
put("1.6.1.7", "SETroubleshoot", rh("1.3.1.8", "SETroubleshoot"))
put("1.6.1.8", "mcstrans", rh("1.3.1.7", "mcstrans"))

# ── 2 services: this benchmark asks for the package to be absent (no "or the service is off"), except
#    where its title offers the service alternative ──
put("2.1.1", "time synchronization is in use", rh("2.3.1", "time synchronization"))
put("2.1.2", "chrony is configured", rh("2.3.2", "chrony is configured"))
put("2.2.1", "xorg-x11-server-common", rh("2.1.21", "X window"))
for rid, kw, pkgs in [("2.2.2", "avahi", ["avahi"]), ("2.2.3", "print server", ["cups"]),
                      ("2.2.4", "dhcp server", ["dhcp-server"]), ("2.2.5", "dns server", ["bind"]),
                      ("2.2.6", "an ftp server", ["vsftpd"]), ("2.2.7", "a tftp server", ["tftp-server"]),
                      ("2.2.8", "web server", ["httpd", "nginx"]), ("2.2.9", "imap and pop3", ["dovecot", "cyrus-imapd"]),
                      ("2.2.10", "samba", ["samba"]), ("2.2.11", "http proxy", ["squid"]),
                      ("2.2.13", "telnet-server", ["telnet-server"]), ("2.2.14", "dnsmasq", ["dnsmasq"])]:
    put(rid, kw, R.pkg_absent(pkgs))
put("2.2.12", "snmpd service is not enabled", pkg_or_units("net-snmp", ["snmpd.service"], "unit_not_enabled"))
put("2.2.15", "local-only mode", rh("2.1.19", "mail transfer"))
put("2.2.16", "nfs-server service is masked", pkg_or_units("nfs-utils", ["nfs-server.service"], "unit_masked"))
put("2.2.17", "rpcbind services are masked", pkg_or_units("rpcbind", ["rpcbind.service", "rpcbind.socket"], "unit_masked"))
put("2.2.18", "rsyncd service is masked", pkg_or_units("rsync-daemon", ["rsyncd.service"], "unit_masked"))
put("2.3.1", "telnet client", rh("2.2.3", "telnet client"))
put("2.3.2", "ldap client", rh("2.2.2", "ldap client"))
put("2.3.3", "ftp client", rh("2.2.1", "ftp client"))
put("2.4", "nonessential services", attest("listening_services_approved"))
for _rid in ("2.2.15",):
    L[_rid].hollow_ok = True

# ── 3.1-3.3 network: kernel modules and kernel parameters (running and persisted value of each) ──
put("3.1.1", "IPv6 status", attest("ipv6_status_identified"))
for rid, kw, mod in [("3.1.2", "DCCP", "dccp"), ("3.1.3", "SCTP", "sctp"), ("3.1.4", "RDS", "rds"), ("3.1.5", "TIPC", "tipc")]:
    put(rid, kw + " is disabled", R.kmod(R.NETM, mod))


def sysctls(pairs):
    """every listed parameter; net.ipv6.* ones apply only where IPv6 is enabled (the audit script's rule)"""
    return all_of(*[R.sysctl(p, [v], ipv6=p.startswith("net.ipv6.")) for p, v in pairs])


def both(name, v):
    return [(f"net.ipv4.conf.all.{name}", v), (f"net.ipv4.conf.default.{name}", v)]


def both6(name, v):
    return [(f"net.ipv6.conf.all.{name}", v), (f"net.ipv6.conf.default.{name}", v)]


put("3.2.1", "IP forwarding", sysctls([("net.ipv4.ip_forward", "0"), ("net.ipv6.conf.all.forwarding", "0")]))
put("3.2.2", "packet redirect sending", sysctls(both("send_redirects", "0")))
put("3.3.1", "source routed packets", sysctls(both("accept_source_route", "0") + both6("accept_source_route", "0")))
put("3.3.2", "ICMP redirects are not accepted", sysctls(both("accept_redirects", "0") + both6("accept_redirects", "0")))
put("3.3.3", "secure ICMP redirects", sysctls(both("secure_redirects", "0")))
put("3.3.4", "suspicious packets are logged", sysctls(both("log_martians", "1")))
put("3.3.5", "broadcast ICMP requests", sysctls([("net.ipv4.icmp_echo_ignore_broadcasts", "1")]))
put("3.3.6", "bogus ICMP responses", sysctls([("net.ipv4.icmp_ignore_bogus_error_responses", "1")]))
put("3.3.7", "Reverse Path Filtering", sysctls(both("rp_filter", "1")))
put("3.3.8", "TCP SYN Cookies", sysctls([("net.ipv4.tcp_syncookies", "1")]))
put("3.3.9", "IPv6 router advertisements", sysctls(both6("accept_ra", "0")))

# ── 3.4 host firewall: packages.<name>, services[<unit>] (service_facts), and two new facts:
#    firewall.nft_ruleset_raw (text of `nft list ruleset`) and firewall.default_zone (`firewall-cmd
#    --get-default-zone`) ──
FW = "input.firewall."
NFT = ["firewall", "nft_ruleset_raw"]   # new
FWZ = ["firewall", "default_zone"]      # new
PF, PN = 'input.packages.firewalld', 'input.packages.nftables'
UF, UN = '"firewalld.service"', '"nftables.service"'
ON = {"state": "running", "status": "enabled"}
NFT_OK = "\n".join([
    "table inet filter {",
    "\tchain input {",
    "\t\ttype filter hook input priority filter; policy drop;",
    "\t\tiif \"lo\" accept",
    "\t\tip saddr 127.0.0.0/8 counter packets 0 bytes 0 drop",
    "\t\tip6 saddr ::1 counter packets 0 bytes 0 drop",
    "\t\tct state established,related accept",
    "\t}",
    "\tchain forward {",
    "\t\ttype filter hook forward priority filter; policy drop;",
    "\t}",
    "\tchain output {",
    "\t\ttype filter hook output priority filter; policy accept;",
    "\t}",
    "}"])


def nft_in(text, extra=None):
    return merge({"firewall": {"nft_ruleset_raw": text}}, extra or {})


put("3.4.1.1", "nftables is installed", R.pkg_present("nftables"))
# firewalld enabled+active with nftables.service off, or nftables.service enabled+active with firewalld off
# or not installed; nftables must be installed in every passing case (the audit script's case table)
put("3.4.1.2", "single firewall configuration utility", custom(
    [f'is_boolean({PF})', f'is_boolean({PN})', f'fw_unit_evidence("firewalld", {UF})', f'fw_unit_evidence("nftables", {UN})'],
    [[f'{PF} == true', f'unit_enabled_active({UF})', f'{PN} == true', f'fw_unit_off({UN})'],
     [f'{PF} == true', f'fw_unit_off({UF})', f'{PN} == true', f'unit_enabled_active({UN})'],
     [f'{PF} == false', f'{PN} == true', f'unit_enabled_active({UN})']],
    "packages[firewalld,nftables] / services[firewalld.service,nftables.service]",
    {"packages": {"firewalld": False, "nftables": True}, "services": {"nftables.service": ON}},
    {"packages": {"firewalld": True, "nftables": True}, "services": {"firewalld.service": ON, "nftables.service": ON}},
    {"packages": {"firewalld": True}},
    reads=[["packages", "firewalld"], ["packages", "nftables"], ["services"]]))
_fwd_on = f'input.services[{UF}].status == "enabled"'
put("3.4.2.1", "firewalld default zone", custom(
    None,
    [[f'{PF} == false'], [f'{PF} == true', f'unit_not_enabled({UF})'],
     [f'{PF} == true', _fwd_on, f'trim_space({ref(FWZ)}) != ""']],
    "packages.firewalld / services[firewalld.service] / firewall.default_zone",
    {"packages": {"firewalld": False}},
    {"packages": {"firewalld": True}, "services": {"firewalld.service": ON}, "firewall": {"default_zone": ""}},
    {"packages": {"firewalld": True}, "services": {"firewalld.service": ON}},
    reads=[["packages", "firewalld"], ["services"], FWZ],
    ev_alts=[[f'{PF} == false'], [f'{PF} == true', f'unit_not_enabled({UF})'],
             [f'{PF} == true', _fwd_on, f'{ref(FWZ)} != null']]))
put("3.4.2.2", "at least one nftables table", custom(
    ['nft_ruleset_reported'], [['some l in nft_lines', 'regex.match(`^\\s*table\\s+\\S+\\s+\\S+`, l)']], dotted(NFT),
    nft_in(NFT_OK), nft_in(""), {"firewall": {"type": "nftables"}}, reads=[NFT]))
put("3.4.2.3", "base chains exist", custom(
    ['nft_ruleset_reported'], [['every h in ["input", "forward", "output"] { count(nft_hook_lines(h)) > 0 }']],
    dotted(NFT), nft_in(NFT_OK), nft_in("\n".join(NFT_OK.split("\n")[:8] + ["}"])), {"firewall": {"type": "nftables"}},
    reads=[NFT]))
put("3.4.2.4", "loopback traffic", custom(
    ['nft_ruleset_reported', 'is_boolean(input.ipv6.disabled)'],
    [['nft_lo_accept', 'nft_lo_v4_drop', 'input.ipv6.disabled == true'],
     ['nft_lo_accept', 'nft_lo_v4_drop', 'input.ipv6.disabled == false', 'nft_lo_v6_drop']],
    "firewall.nft_ruleset_raw / ipv6.disabled",
    nft_in(NFT_OK, {"ipv6": {"disabled": False}}),
    nft_in("\n".join(l for l in NFT_OK.split("\n") if '"lo"' not in l), {"ipv6": {"disabled": False}}),
    nft_in(NFT_OK), reads=[NFT, ["ipv6", "disabled"]]))
put("3.4.2.5", "firewalld drops unnecessary services", attest("firewalld_services_ports_reviewed"))
put("3.4.2.6", "established connections", attest("nftables_established_connections_reviewed"))
# applies where nftables.service is enabled; then the input and forward base chains must exist with policy drop
# (the audit's grep is satisfied by a ruleset without those chains: that is not accepted here)
_nft_on = f'input.services[{UN}].status == "enabled"'
put("3.4.2.7", "default deny firewall policy", custom(
    None,
    [[f'{PN} == false'], [f'{PN} == true', f'unit_not_enabled({UN})'], [f'{PN} == true', _nft_on, 'nft_default_drop']],
    "packages.nftables / services[nftables.service] / firewall.nft_ruleset_raw",
    merge({"packages": {"nftables": True}, "services": {"nftables.service": ON}}, nft_in(NFT_OK)),
    merge({"packages": {"nftables": True}, "services": {"nftables.service": ON}},
          nft_in(NFT_OK.replace("hook forward priority filter; policy drop;", "hook forward priority filter; policy accept;"))),
    {"packages": {"nftables": True}, "services": {"nftables.service": ON}},
    reads=[["packages", "nftables"], ["services"], NFT],
    ev_alts=[[f'{PN} == false'], [f'{PN} == true', f'unit_not_enabled({UN})'],
             [f'{PN} == true', _nft_on, 'nft_ruleset_reported']]))

# ── 4.1 job schedulers ("IF cron is used": a collected packages.cronie == false passes). The cron.* fields
#    are the rhel_9 mapper's; *_allow_* / *_deny_exists are the rhel_9 module's names for the allow/deny files ──
CR = "input.cron."
put("4.1.1", "cron daemon is installed and enabled", gated(custom(
    [f'is_boolean({CR}crond_enabled)'], [[f'{CR}crond_enabled == true']], "cron.crond_enabled",
    {"cron": {"crond_enabled": True}}, {"cron": {"crond_enabled": False}}, reads=[["cron", "crond_enabled"]]), "cronie"))
# the audit: Uid and Gid 0/root and no permission for group or other (0700 at most, crontab included)
for rid, d, kw in [("4.1.2", "crontab", "/etc/crontab"), ("4.1.3", "cron_hourly", "/etc/cron.hourly"),
                   ("4.1.4", "cron_daily", "/etc/cron.daily"), ("4.1.5", "cron_weekly", "/etc/cron.weekly"),
                   ("4.1.6", "cron_monthly", "/etc/cron.monthly"), ("4.1.7", "cron_d", "/etc/cron.d ")]:
    put(rid, "permissions on " + kw, gated(R.access(["cron", f"{d}_mode"], ["cron", f"{d}_owner"], ["cron", f"{d}_group"],
                                                     "0700", ["root"], ["root"]), "cronie"))


def allow_only(svc, pkg):
    """<svc>.deny must not exist; <svc>.allow must exist, mode 0600 at most, owned root:root"""
    a = [f"{svc}_allow_{k}" for k in ("exists", "mode", "owner", "group")]
    d = f"{svc}_deny_exists"
    ok = [f'{CR}{d} == false', f'{CR}{a[0]} == true', f'mode_within({CR}{a[1]}, "0600")', f'{CR}{a[2]} == "root"',
          f'{CR}{a[3]} == "root"']
    good = {a[0]: True, a[1]: "0600", a[2]: "root", a[3]: "root", d: False}
    ev = [[f'is_boolean({CR}{d})', f'{CR}{a[0]} == false'],
          [f'is_boolean({CR}{d})', f'{CR}{a[0]} == true', f'{CR}{a[1]} != null', f'{CR}{a[2]} != null', f'{CR}{a[3]} != null']]
    return gated(custom(None, [ok], f"cron.{svc}_allow_*/{d}", {"cron": good}, {"cron": dict(good, **{d: True})},
                        {"cron": {a[0]: True}}, reads=[["cron", k] for k in a + [d]], ev_alts=ev), pkg)


put("4.1.8", "cron is restricted", allow_only("cron", "cronie"))
put("4.1.9", "at is restricted", allow_only("at", "at"))

# ── 4.2 SSH server (ssh.sshd_config_raw = `sshd -T`; the rhel_9 permission fields) ──
SS = "input.ssh."
_cp = {"mode": "0600", "pw_name": "root", "gr_name": "root"}
put("4.2.1", "/etc/ssh/sshd_config", custom(
    [f'{SS}config_permissions.mode != null', f'{SS}config_permissions.pw_name != null', f'{SS}config_permissions.gr_name != null'],
    [[f'perm_ok({SS}config_permissions, "0600")']], "ssh.config_permissions",
    {"ssh": {"config_permissions": _cp}}, {"ssh": {"config_permissions": dict(_cp, mode="0644")}},
    reads=[["ssh", "config_permissions"]]))
put("4.2.2", "private host key", rh("5.1.3", "private host key"))
_pub = {"path": "/etc/ssh/ssh_host_ed25519_key.pub", "mode": "0644", "pw_name": "root", "gr_name": "root"}
put("4.2.3", "public host key", custom(
    [f'is_array({SS}public_key_permissions)', f'count({SS}public_key_permissions) > 0'],
    [[f'every k in {SS}public_key_permissions {{ perm_ok(k, "0644") }}']], "ssh.public_key_permissions",
    {"ssh": {"public_key_permissions": [_pub]}}, {"ssh": {"public_key_permissions": [dict(_pub, gr_name="ssh_keys")]}},
    reads=[["ssh", "public_key_permissions"]]))
for rid, kw, src, skw in [("4.2.4", "SSH access is limited", "5.1.8", "sshd access"),
                          ("4.2.5", "LogLevel", "5.1.16", "LogLevel"), ("4.2.6", "SSH PAM", "5.1.23", "UsePAM"),
                          ("4.2.7", "root login", "5.1.21", "PermitRootLogin"),
                          ("4.2.8", "HostbasedAuthentication", "5.1.13", "HostbasedAuthentication"),
                          ("4.2.9", "PermitEmptyPasswords", "5.1.20", "PermitEmptyPasswords"),
                          ("4.2.10", "PermitUserEnvironment", "5.1.22", "PermitUserEnvironment"),
                          ("4.2.11", "IgnoreRhosts", "5.1.14", "IgnoreRhosts"),
                          ("4.2.16", "MaxAuthTries", "5.1.17", "MaxAuthTries"),
                          ("4.2.17", "MaxStartups", "5.1.18", "MaxStartups"),
                          ("4.2.18", "MaxSessions", "5.1.19", "MaxSessions"),
                          ("4.2.19", "LoginGraceTime", "5.1.15", "LoginGraceTime"),
                          ("4.2.20", "Idle Timeout", "5.1.10", "ClientAliveInterval")]:
    put(rid, kw, rh(src, skw))
put("4.2.12", "X11 forwarding", R.sshd("x11forwarding", 'v == "no"', "no", "yes"))
put("4.2.13", "AllowTcpForwarding", R.sshd("allowtcpforwarding", 'v == "no"', "no", "yes"))
CPO = ["ssh", "crypto_policy_override_raw"]   # new: text of /etc/sysconfig/sshd + /etc/ssh/sshd_config.d/*.conf
R.EMPTY_TEXT_OK = tuple(R.EMPTY_TEXT_OK) + ("crypto_policy_override_raw)",)  # both may be absent: "" is a value
put("4.2.14", "crypto policy is not over-ridden", hollow_ok(R.text_has(
    CPO, "(?i)^CRYPTO_POLICY\\s*=", False, "OPTIONS=\"-u0\"", "CRYPTO_POLICY='-oCiphers=aes256-ctr'")))
put("4.2.15", "SSH warning banner", R.sshd("banner", 'startswith(v, "/")', "/etc/issue.net", "none"))

# ── 4.3 privilege escalation (the rhel_9 sudo.* fields) ──
for rid, kw, src, skw in [("4.3.1", "sudo is installed", "5.2.1", "sudo is installed"),
                          ("4.3.2", "use pty", "5.2.4", "use pty"), ("4.3.3", "sudo log file", "5.2.5", "sudo log file"),
                          ("4.3.4", "re-authentication", "5.2.7", "re-authentication"),
                          ("4.3.5", "authentication timeout", "5.2.10", "timestamp_timeout")]:
    put(rid, kw, rh(src, skw))
SUP = ["pam", "su_config_raw"]          # new: text of /etc/pam.d/su
GM = ["user_group", "group_members"]    # new: {group name: [member user names]} from /etc/group
put("4.3.6", "su command is restricted", custom(
    [f'text_collected({ref(SUP)})', f'is_object({ref(GM)})'],
    [['some g in su_wheel_groups', f'is_array({ref(GM)}[g])', f'count({ref(GM)}[g]) == 0']],
    "pam.su_config_raw/user_group.group_members",
    {"pam": {"su_config_raw": "auth required pam_wheel.so use_uid group=sugroup"}, "user_group": {"group_members": {"sugroup": []}}},
    {"pam": {"su_config_raw": "auth required pam_wheel.so use_uid group=sugroup"},
     "user_group": {"group_members": {"sugroup": ["alice"]}}},
    {"pam": {"su_config_raw": "auth required pam_wheel.so use_uid group=sugroup"}}, reads=[SUP, GM]))

# ── 4.4-4.6 authselect, PAM, accounts (the rhel_9 pam.* / user_group.* fields) ──
PA = "input.pam."
put("4.4.1", "custom authselect profile", attest("custom_authselect_profile_used"))
put("4.4.2", "with-faillock", rh("5.3.2.2", "pam_faillock"))
# pam_pwquality on the password stack of both files and minlen >= 14 (retry and complexity are site policy)
put("4.5.1", "password creation requirements", all_of(rh("5.3.2.3", "pam_pwquality"), rh("5.3.3.2.2", "password length")))
put("4.5.2", "lockout for failed password attempts", all_of(rh("5.3.3.1.1", "lockout"), rh("5.3.3.1.2", "unlock time")))
put("4.5.3", "password reuse is limited", custom(
    [f'text_collected({PA}system_auth)'],
    [['some l in array.concat(pam_lines(pam_system_auth_text, "password", "pam_pwhistory.so"), '
      'pam_lines(pam_system_auth_text, "password", "pam_unix.so"))',
      'regex.match(`\\sremember=([5-9]|[1-9][0-9]+)(\\s|$)`, l)']],
    "pam.system_auth", {"pam": {"system_auth": R.PAMOK.replace("pam_pwhistory.so use_authtok", "pam_pwhistory.so use_authtok remember=5")}},
    {"pam": {"system_auth": R.PAMOK.replace("pam_pwhistory.so use_authtok", "pam_pwhistory.so use_authtok remember=3")}},
    reads=[["pam", "system_auth"]]))
LU = ["pam", "libuser_conf_raw"]   # new: text of /etc/libuser.conf
_lu = R.conf(LU, "crypt_style", 'lower(v) in {"sha512", "yescrypt"}', "[defaults]\ncrypt_style = sha512",
             "[defaults]\ncrypt_style = md5")
put("4.5.4", "hashing algorithm is SHA-512", all_of(_lu, rh("5.4.1.4", "hashing algorithm"), rh("5.3.3.4.3", "pam_unix includes a strong")))
put("4.6.1.1", "expiration is 365 days", rh("5.4.1.1", "password expiration"))
# min_days in each user_group.shadow_entries record is new (the rhel_9 shape has max/warn/inactive)
put("4.6.1.2", "minimum days between password changes", R.shadow_rule(
    ["pam", "pass_min_days"], ['v >= 1'], 'num(u.min_days) >= 1', 1, 0, {"min_days": 1}))
put("4.6.1.3", "warning days is 7", rh("5.4.1.3", "warning days"))
put("4.6.1.4", "inactive password lock is 30", R.shadow_rule(
    ["pam", "inactive_days"], ['v >= 0', 'v <= 30'], 'num(u.inactive) >= 0; num(u.inactive) <= 30', 30, 45, {"inactive": 30}))
put("4.6.1.5", "last password change date", rh("5.4.1.6", "last password change"))
put("4.6.2", "system accounts are secured", all_of(rh("5.4.2.7", "valid login shell"), rh("5.4.2.8", "are locked")))
L["4.6.2"].hollow_ok = True
put("4.6.3", "shell timeout", rh("5.4.3.2", "shell timeout"))
put("4.6.4", "root account is GID 0", custom(
    [f'{PA}root_gid != null'], [[f'num({PA}root_gid) == 0']], "pam.root_gid",
    {"pam": {"root_gid": 0}}, {"pam": {"root_gid": 10}}, reads=[["pam", "root_gid"]]))
put("4.6.5", "default user umask", rh("5.4.3.4", "default user umask"))
put("4.6.6", "root password is set", attest("root_password_set"))

# ── 5.1 logging. Amazon Linux 2023 ships journald only: rsyslog checks treat a collected
#    rsyslog.installed == false as evidence ──
put("5.1.1.1", "rsyslog is installed", attest("rsyslog_installed_if_used"))
put("5.1.1.2", "rsyslog service is enabled", attest("rsyslog_enabled_if_used"))
put("5.1.1.3", "journald is configured to send logs to rsyslog", attest("journald_forwards_to_rsyslog_if_used"))
put("5.1.1.4", "rsyslog default file permissions", custom(
    None, [['input.rsyslog.installed == true', 'mode_within(input.rsyslog.file_create_mode, "0640")']],
    "rsyslog.installed/file_create_mode", {"rsyslog": {"installed": True, "file_create_mode": "0640"}},
    {"rsyslog": {"installed": False}}, {"rsyslog": {"file_create_mode": "0640"}},
    reads=[["rsyslog", "installed"], ["rsyslog", "file_create_mode"]],
    ev_alts=[['input.rsyslog.installed == true'], ['input.rsyslog.installed == false']]))
put("5.1.1.5", "logging is configured", attest("rsyslog_logging_rules_reviewed"))
put("5.1.1.6", "remote log host", attest("rsyslog_remote_host_configured"))
put("5.1.1.7", "rsyslog is not configured to receive logs", rh("6.1.2.7", "log server"))
put("5.1.2.1.1", "systemd-journal-remote is installed", attest("journal_remote_installed_if_used"))
put("5.1.2.1.2", "systemd-journal-remote is configured", attest("journal_remote_configured"))
put("5.1.2.1.3", "systemd-journal-remote is enabled", attest("journal_upload_enabled"))
put("5.1.2.1.4", "journald is not configured to receive logs", pkg_or_units(
    "systemd-journal-remote", ["systemd-journal-remote.socket"], "unit_masked"))
JD = "input.journald."
put("5.1.2.2", "journald service is enabled", custom(
    ['services_collected', 'unit_reported("systemd-journald.service")'],
    [['input.services["systemd-journald.service"].status == "static"']], 'services["systemd-journald.service"]',
    {"services": merge(OTHER_UNIT, {"systemd-journald.service": {"state": "running", "status": "static"}})},
    {"services": merge(OTHER_UNIT, {"systemd-journald.service": {"state": "running", "status": "masked"}})},
    {"services": OTHER_UNIT}, reads=[["services"]]))
put("5.1.2.3", "compress large log files", custom(
    [f'is_string({JD}compress_enabled)'], [[f'lower({JD}compress_enabled) == "yes"']], "journald.compress_enabled",
    {"journald": {"compress_enabled": "yes"}}, {"journald": {"compress_enabled": "no"}}, reads=[["journald", "compress_enabled"]]))
put("5.1.2.4", "persistent disk", custom(
    [f'is_string({JD}storage_mode)'], [[f'lower({JD}storage_mode) == "persistent"']], "journald.storage_mode",
    {"journald": {"storage_mode": "persistent"}}, {"journald": {"storage_mode": "auto"}}, reads=[["journald", "storage_mode"]]))
put("5.1.2.5", "journald is not configured to send logs to rsyslog", attest("journald_not_forwarding_if_journald_used"))
put("5.1.2.6", "journald log rotation", attest("journald_rotation_reviewed"))
put("5.1.2.7", "journald default file permissions", attest("journald_file_access_reviewed"))
# the rhel_9 log_file_permissions.analysis list, judged by this benchmark's own case table (al_log_rule below):
# it has no 0644 allowance for cloud-init.log / localmessages / waagent.log as RHEL 9 v3.0.0 does
LF = ["log_file_permissions", "analysis"]
put("5.1.3", "all logfiles", custom(
    [f'is_array({ref(LF)})', f'count({ref(LF)}) > 0'], [[f'every f in {ref(LF)} {{ al_log_file_ok(f) }}']], dotted(LF),
    nest(LF, [{"file": "/var/log/messages", "actual_mode": "0600", "actual_owner": "root", "actual_group": "root"},
              {"file": "/var/log/wtmp", "actual_mode": "0664", "actual_owner": "root", "actual_group": "utmp"}]),
    nest(LF, [{"file": "/var/log/cloud-init.log", "actual_mode": "0644", "actual_owner": "root", "actual_group": "root"}]),
    reads=[LF]))
put("5.3", "logrotate", attest("logrotate_reviewed"))

# ── 5.2 auditd (the rhel_9 auditd.* fields; kernel arguments of every boot entry = boot_security.kernel_args) ──
KA = R.KA
put("5.2.1.1", "auditd is installed", R.pkg_present("audit"))
put("5.2.1.2", "prior to auditd", custom(
    [f'is_array({ref(KA)})', f'count({ref(KA)}) > 0'],
    [[f'every a in {ref(KA)} {{ "audit=1" in regex.split(`\\s+`, trim_space(a)) }}']], dotted(KA),
    nest(KA, ["ro audit=1 audit_backlog_limit=8192"]), nest(KA, ["ro audit=1", "ro quiet"]), reads=[KA]))
put("5.2.1.3", "audit_backlog_limit", custom(
    [f'is_array({ref(KA)})', f'count({ref(KA)}) > 0'],
    [[f'every a in {ref(KA)} {{ backlog_ok(a) }}']], dotted(KA),
    nest(KA, ["ro audit=1 audit_backlog_limit=8192"]), nest(KA, ["ro audit=1 audit_backlog_limit=64"]), reads=[KA]))
put("5.2.1.4", "auditd service is enabled", custom(
    ['services_collected', 'unit_reported("auditd.service")'], [['input.services["auditd.service"].status == "enabled"']],
    'services["auditd.service"]', {"services": merge(OTHER_UNIT, {"auditd.service": {"state": "running", "status": "enabled"}})},
    {"services": merge(OTHER_UNIT, {"auditd.service": {"state": "stopped", "status": "disabled"}})},
    {"services": OTHER_UNIT}, reads=[["services"]]))
put("5.2.2.1", "audit log storage size", rh("6.2.2.1", "log storage size"))
put("5.2.2.2", "not automatically deleted", rh("6.2.2.2", "not automatically deleted"))
AC = R.AC
put("5.2.2.3", "disabled when audit logs are full", custom(
    [f'text_collected({ref(AC)})'],
    [['lower(conf_last(input.auditd.config, "space_left_action")) == "email"',
      'lower(conf_last(input.auditd.config, "action_mail_acct")) == "root"',
      'lower(conf_last(input.auditd.config, "admin_space_left_action")) in {"halt", "single"}']],
    dotted(AC), nest(AC, "space_left_action = email\naction_mail_acct = root\nadmin_space_left_action = single"),
    nest(AC, "space_left_action = email\naction_mail_acct = root\nadmin_space_left_action = suspend"), reads=[AC]))
# 5.2.3: every audit procedure reads the on-disk rules (auditd.rules) AND the running rules (auditd.active_rules);
# R.audit requires a rule in both. Syscall rules: arch=b64 and arch=b32 wherever the procedure lists both (all
# syscall ids but 5.2.3.19, whose module syscalls are listed for arch=b64 only).
audit, B, SRC = R.audit, R.B, R.SRC
put("5.2.3.1", "sudoers", rh("6.2.3.1", "/etc/sudoers"))
put("5.2.3.2", "actions as another user", audit(syscalls=[(["execve"], ["euid"], B)]))
put("5.2.3.3", "modify the sudo log file", rh("6.2.3.3", "sudo log file"))
put("5.2.3.4", "date and time", rh("6.2.3.4", "date and time"))
put("5.2.3.5", "network environment", audit(
    [("/etc/issue", "wa"), ("/etc/issue.net", "wa"), ("/etc/hosts", "wa"), ("/etc/sysconfig/network", "wa"),
     ("/etc/sysconfig/network-scripts", "wa")], [(["sethostname", "setdomainname"], [], B)]))
# 5.2.3.6: both scripts only look for each privileged program's path in the rules (no field filters, unlike RHEL 9
# 6.2.3.10); the earlier check's perm x watch is kept, now in both rule sources
_s = put("5.2.3.6", "privileged commands", rh("6.2.3.10", "privileged commands"))
_s.passes = [[f'every c in {ref(R.PC)} {{ every src in {SRC} {{ audit_src_watch(src, c, "x") }} }}']]
put("5.2.3.7", "unsuccessful file access", rh("6.2.3.11", "unsuccessful file access"))
put("5.2.3.8", "user/group information", audit([("/etc/group", "wa"), ("/etc/passwd", "wa"), ("/etc/gshadow", "wa"),
                                                 ("/etc/shadow", "wa"), ("/etc/security/opasswd", "wa")]))
put("5.2.3.9", "discretionary access control", audit(syscalls=[
    (["chmod", "fchmod", "fchmodat"], ["auid"], B), (["chown", "fchown", "lchown", "fchownat"], ["auid"], B),
    (["setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr"], ["auid"], B)]))
put("5.2.3.10", "file system mounts", audit(syscalls=[(["mount"], ["auid"], B)]))
put("5.2.3.11", "session initiation", rh("6.2.3.22", "session initiation"))
put("5.2.3.12", "login and logout", rh("6.2.3.23", "login and logout"))
put("5.2.3.13", "file deletion events", audit(syscalls=[(["unlink", "unlinkat", "rename", "renameat"], ["auid"], B)]))
put("5.2.3.14", "Mandatory Access Controls", audit([("/etc/selinux", "wa"), ("/usr/share/selinux", "wa")]))
# 5.2.3.15-5.2.3.19: an always,exit rule on the executable with perm x, auid>=1000 and auid!=unset on the same
# line (R.audit execs), in both rule sources
for rid, cmd, path in [("5.2.3.15", "chcon", "/usr/bin/chcon"), ("5.2.3.16", "setfacl", "/usr/bin/setfacl"),
                       ("5.2.3.17", "chacl", "/usr/bin/chacl"), ("5.2.3.18", "usermod", "/usr/sbin/usermod")]:
    put(rid, f"use the {cmd} command", audit(execs=[path]))
put("5.2.3.19", "kernel module loading", audit(
    execs=["/usr/bin/kmod"],
    syscalls=[(["init_module", "finit_module", "delete_module", "create_module", "query_module"], ["auid"], ("b64",))]))
put("5.2.3.20", "immutable", rh("6.2.3.35", "immutable"))
put("5.2.3.21", "running and on disk", attest("audit_rules_running_match_disk"))
put("5.2.4.1", "audit log files are mode 0640", rh("6.2.4.2", "log files mode"))
put("5.2.4.2", "own audit log files", rh("6.2.4.3", "log files owner"))
LP = "input.auditd.log_permissions."
put("5.2.4.3", "groups are assigned ownership of audit log", custom(
    [f'{LP}gr_name != null', f'text_collected({ref(AC)})'],
    [[f'{LP}gr_name in {{"adm", "root"}}', 'lower(conf_last(input.auditd.config, "log_group")) in {"adm", "root"}']],
    "auditd.log_permissions.gr_name/auditd.config",
    {"auditd": {"log_permissions": {"gr_name": "root"}, "config": "log_group = root"}},
    {"auditd": {"log_permissions": {"gr_name": "root"}, "config": "log_group = audit"}},
    {"auditd": {"log_permissions": {"gr_name": "root"}}}, reads=[["auditd", "log_permissions", "gr_name"], AC]))
put("5.2.4.4", "audit log directory", rh("6.2.4.1", "log file directory"))
for rid, kw, src, skw in [("5.2.4.5", "configuration files are 640", "6.2.4.5", "configuration files mode"),
                          ("5.2.4.6", "configuration files are owned by root", "6.2.4.6", "configuration files owner"),
                          ("5.2.4.7", "configuration files belong to group root", "6.2.4.7", "configuration files group"),
                          ("5.2.4.8", "audit tools are 755", "6.2.4.8", "audit tools mode"),
                          ("5.2.4.9", "audit tools are owned by root", "6.2.4.9", "audit tools owner"),
                          ("5.2.4.10", "audit tools belong to group root", "6.2.4.10", "audit tools group")]:
    put(rid, kw, rh(src, skw))

# ── 6.1 system files (the rhel_9 critical_files.analysis entries) and 6.2 users and groups ──
for rid, kw, path, mx in [("6.1.1", "/etc/passwd are", "/etc/passwd", "0644"), ("6.1.2", "/etc/passwd are", "/etc/passwd", "0644"),
                          ("6.1.3", "/etc/passwd-", "/etc/passwd-", "0644"), ("6.1.4", "/etc/group are", "/etc/group", "0644"),
                          ("6.1.5", "/etc/group-", "/etc/group-", "0644"), ("6.1.6", "/etc/shadow are", "/etc/shadow", "0000"),
                          ("6.1.7", "/etc/shadow-", "/etc/shadow-", "0000"), ("6.1.8", "/etc/gshadow are", "/etc/gshadow", "0000"),
                          ("6.1.9", "/etc/gshadow-", "/etc/gshadow-", "0000")]:
    put(rid, "permissions on " + kw, R.crit(path, mx, ["root"]))
put("6.1.10", "system file permissions", attest("system_file_permissions_reviewed"))
put("6.1.11", "world writable", rh("7.1.11", "world writable"))
put("6.1.12", "unowned or ungrouped", rh("7.1.12", "without an owner"))
put("6.1.13", "SUID and SGID", attest("suid_sgid_files_reviewed"))
for rid, kw, src, skw in [("6.2.1", "shadowed passwords", "7.2.1", "shadowed"),
                          ("6.2.2", "password fields are not empty", "7.2.2", "not empty"),
                          ("6.2.3", "groups in /etc/passwd exist", "7.2.3", "groups in /etc/passwd"),
                          ("6.2.4", "duplicate UIDs", "7.2.4", "UIDs"), ("6.2.5", "duplicate GIDs", "7.2.5", "GIDs"),
                          ("6.2.6", "duplicate user names", "7.2.6", "user names"),
                          ("6.2.7", "duplicate group names", "7.2.7", "group names"),
                          ("6.2.8", "root PATH", "5.4.2.5", "root path"), ("6.2.9", "only UID 0", "5.4.2.1", "UID 0"),
                          ("6.2.10", "home directories", "7.2.8", "home directories")]:
    put(rid, kw, rh(src, skw))
# new: user_group.home_dotfiles = every dot file in each local interactive user's home
# [{user, primary_group, path, mode, owner, group}]. A .netrc with correct access is only a warning in this
# benchmark's audit (RHEL 9's users_with_netrc fails any), .bash_history must be 0600, the rest 0644.
DF = ["user_group", "home_dotfiles"]
_df = {"user": "alice", "primary_group": "alice", "path": "/home/alice/.bashrc", "mode": "0644", "owner": "alice", "group": "alice"}
put("6.2.11", "dot files", hollow_ok(custom(
    [f'is_array({ref(DF)})'], [[f'every f in {ref(DF)} {{ dotfile_ok(f) }}']], dotted(DF),
    nest(DF, [_df, dict(_df, path="/home/alice/.netrc", mode="0600")]),
    nest(DF, [_df, dict(_df, path="/home/alice/.bash_history", mode="0644")]), reads=[DF])))

# ── Rego helpers this benchmark adds (emitted into the section modules named) ──
UNIT_HELPERS = r'''
# reported and not enabled (disabled, masked, static, not-found ... all count as not enabled)
unit_not_enabled(u) if {
	unit_reported(u)
	input.services[u].status != "enabled"
}

unit_masked(u) if input.services[u].status == "masked"
'''
AL_EXTRA = {
    "services": UNIT_HELPERS,
    "logging": UNIT_HELPERS + r'''
# 5.1.3: [max mode, owners, groups] by file name, from this benchmark's audit script
al_log_rule(b) := ["0664", {"root"}, {"root", "utmp"}] if {
	regex.match(`^(lastlog(\..*)?|wtmp([.-].*)?|btmp([.-].*)?)$`, b)
} else := ["0640", {"root", "syslog"}, {"root", "adm"}] if {
	b in {"secure", "auth.log", "syslog", "messages"}
} else := ["0660", {"root", "SSSD", "sssd"}, {"root", "SSSD", "sssd"}] if {
	b in {"SSSD", "sssd"}
} else := ["0660", {"root"}, {"root", "gdm", "gdm3"}] if {
	b in {"gdm", "gdm3"}
} else := ["0640", {"root"}, {"root", "systemd-journal"}] if {
	regex.match(`\.journal~?$`, b)
} else := ["0640", {"root", "syslog"}, {"root", "adm"}]

al_log_file_ok(f) if {
	r := al_log_rule(regex.replace(f.file, `^.*/`, ""))
	mode_within(f.actual_mode, r[0])
	f.actual_owner in r[1]
	f.actual_group in r[2]
}
''',
    "network": UNIT_HELPERS + r'''
# 3.4.1.2: a firewall package not installed needs no unit state; an installed one must report its unit
fw_unit_evidence(pkg, _) if input.packages[pkg] == false

fw_unit_evidence(pkg, u) if {
	input.packages[pkg] == true
	unit_reported(u)
}

# disabled or masked, and not running
fw_unit_off(u) if {
	input.services[u].status in {"disabled", "masked"}
	not lower(input.services[u].state) in {"running", "active"}
}

# `nft list ruleset` text; an empty ruleset is a collected value
nft_ruleset_reported if is_string(input.firewall.nft_ruleset_raw)

nft_lines := [l |
	some raw in split(input.firewall.nft_ruleset_raw, "\n")
	l := trim_space(raw)
	l != ""
	not startswith(l, "#")
]

# indexes of the base-chain lines of one hook (input / forward / output)
nft_hook_lines(h) := [i |
	some i, l in nft_lines
	regex.match(concat("", [`\bhook\s+`, h, `\b`]), l)
]

# a block runs from its start line to the next line that closes it (the audit's awk range)
nft_block_end(i) := e if {
	ends := [j | some j, l in nft_lines; j > i; regex.match(`^\}\s*(#.*)?$`, l)]
	count(ends) > 0
	e := min(ends)
} else := count(nft_lines)

nft_block(i) := [l | some j, l in nft_lines; j >= i; j < nft_block_end(i)]

nft_input_rules := [l | some i in nft_hook_lines("input"); some l in nft_block(i)]

# firewalld keeps its loopback-source drops in the public zone's deny chain
nft_deny_chain_starts := [i | some i, l in nft_lines; regex.match(`^chain\s+filter_IN_public_deny\b`, l)]

nft_saddr_rules := array.concat(nft_input_rules, [l | some i in nft_deny_chain_starts; some l in nft_block(i)])

nft_lo_accept if {
	some l in nft_input_rules
	regex.match(`\S+\s+"lo"\s+accept`, l)
}

nft_lo_v4_drop if {
	some l in nft_saddr_rules
	regex.match(`ip\s+saddr\s+127\.0\.0\.0/8\s+(counter\s+packets\s+\d+\s+bytes\s+\d+\s+)?drop`, l)
}

nft_lo_v4_drop if {
	some l in nft_saddr_rules
	regex.match(`ip\s+daddr\s+!=\s+127\.0\.0\.1\s+ip\s+saddr\s+127\.0\.0\.1\s+drop`, l)
}

nft_lo_v6_drop if {
	some l in nft_saddr_rules
	regex.match(`ip6\s+saddr\s+::1\s+(counter\s+packets\s+\d+\s+bytes\s+\d+\s+)?drop`, l)
}

nft_lo_v6_drop if {
	some l in nft_saddr_rules
	regex.match(`ip6\s+daddr\s+!=\s+::1\s+ip6\s+saddr\s+::1\s+drop`, l)
}

# input and forward base chains exist and every one of them has policy drop
nft_default_drop if {
	every h in ["input", "forward"] {
		count(nft_hook_lines(h)) > 0
		every i in nft_hook_lines(h) { regex.match(`\bpolicy\s+drop\b`, nft_lines[i]) }
	}
}
''',
    "sudo": r'''
# groups named by an active `auth required|requisite pam_wheel.so use_uid group=<g>` line of /etc/pam.d/su
su_wheel_groups contains g if {
	some l in active_lines(input.pam.su_config_raw)
	regex.match(`^auth\s+(required|requisite)\s+pam_wheel\.so(\s|$)`, l)
	regex.match(`\suse_uid(\s|$)`, l)
	some m in regex.find_all_string_submatch_n(`\sgroup=(\S+)`, l, 1)
	g := m[1]
}
''',
    "user_group": r'''
# 6.2.11: .forward / .rhost must not exist; .netrc and .bash_history 0600, other dot files 0644; owned by the
# user and group-owned by the user's primary group
dotfile_base(f) := regex.replace(f.path, `^.*/`, "")

dotfile_max(f) := "0600" if dotfile_base(f) in {".netrc", ".bash_history"}

dotfile_max(f) := "0644" if not dotfile_base(f) in {".netrc", ".bash_history"}

dotfile_ok(f) if {
	not dotfile_base(f) in {".forward", ".rhost"}
	mode_within(f.mode, dotfile_max(f))
	f.owner == f.user
	f.group == f.primary_group
}
''',
    "auditd": r'''
# one boot entry's kernel arguments carry audit_backlog_limit >= 8192
backlog_ok(a) if {
	some t in regex.split(`\s+`, trim_space(a))
	startswith(t, "audit_backlog_limit=")
	num(substring(t, 20, -1)) >= 8192
}
''',
}


def rhel_extra(sec):
    """a RHEL 9 section's helpers, with its id-bound pieces renumbered for this benchmark"""
    t = R.EXTRA.get(sec, "")
    if sec == "ssh":  # the 4.2.1-4.2.3 file-access findings (5.1.1-5.1.4 in RHEL 9)
        old = "regex.match(`^5\\.1\\.[1-4]: `, v)"
        if old not in t:
            raise SystemExit("gen_rhel_9.py: ssh permission_violations changed")
        t = t.replace(old, "regex.match(`^4\\.2\\.[1-3]: `, v)").replace("5.1.1 / 5.1.3 / 5.1.4", "4.2.1-4.2.3")
    return t


# ════════════════════════════════════════════════════════════════════════════════════════════
# emit
# ════════════════════════════════════════════════════════════════════════════════════════════
def header(title, checks, entry="none", density="sized", basis="size", extra=""):
    return f'''# METADATA
# title: {J(title)}
# custom:
{extra}#   class: security
#   framework: {PKG}
#   source: cis
#   domains: [linux, amazon-linux]
#   coverage:
#     checks: {checks}
#     cited: {checks}
#     density: {density}
#     basis: {basis}
#     tested: true
#     entrypoint: {entry}
#     guard: self
#     as_of: {R.AS_OF}
'''


def lvl(rec):
    return R.level(rec["profiles"], "Server")


def emit_module(name, ids, recs):
    f, key, title, _ = SEC[name]
    lines = [header(f"{BENCH} — {title}", len(ids), entry="report").rstrip("\n"), f"package {PKG}.{name}", "",
             f"# {BENCH}, {title}.",
             f"# Generated by {GEN} from the CIS workbook; do not edit by hand.",
             "# Each recommendation: e_<id> (facts collected), p_<id> (requirement met). Automated checks fail",
             "# closed with '<id>: evidence missing — <field> not collected'; Manual ones need input.attest.<name>.",
             f"# Roll-up: package {PKG} (section key {key}); profile scoping happens there, this package reports",
             "# every recommendation of the section.", "",
             "import rego.v1", "",
             "default compliant := false", "",
             "compliant if count(violations) == 0", "",
             f"controls := {json.dumps(sorted(ids, key=sort_key))}", "",
             "# section report (callers read report.compliant / total_violations / violations)",
             "report := {",
             '\t"compliant": compliant,',
             '\t"total_violations": count(violations),',
             '\t"violations": violations,',
             '\t"controls": controls,',
             '\t"compliance_summary": {"overall_compliant": compliant, "controls_evaluated": count(controls)},',
             '\t"collection_timestamp": object.get(input, ["collection_timestamp"], null),',
             "}", ""]
    lines += R.HELPERS.strip("\n").split("\n") + [""]
    for sec in sorted({getattr(L[r], "rhel_section", None) for r in ids} - {None}):
        t = rhel_extra(sec)
        if t:
            lines += [f"# ── helpers of the RHEL 9 checks reused here ({sec}) ──"] + t.strip("\n").split("\n") + [""]
    if name in AL_EXTRA:
        lines += AL_EXTRA[name].strip("\n").split("\n") + [""]
    for rid in ids:
        lines += R.emit_control(rid, recs[rid], L[rid])
    return "\n".join(lines).rstrip("\n") + "\n"


def good_input(ids):
    g = {}
    for rid in ids:
        s = L[rid]
        g = R.merge_good(g, {"attest": {s.name: True}} if s.manual else s.tp)
    return g


def emit_tests(name, ids):
    lines = [f"package {PKG}.{name}_test", "", "import rego.v1", "",
             f"# Generated by {GEN}: a pass and a fail case for every recommendation, plus an evidence-missing",
             "# case for every Automated one. Assertions key on '<id>: ' (colon included).", ""]
    mod = f"data.{PKG}.{name}.violations"
    for rid in ids:
        s, k = L[rid], idkey(rid)
        pre = json.dumps(rid + ": ")
        if s.manual:
            tp, tf, miss = {"attest": {s.name: True}}, {"attest": {s.name: False}}, None
        else:
            tp, tf = s.tp, s.tf
            miss = J(f"{rid}: evidence missing — {s.field} not collected")
        lines += [f"test_{k}_pass if {{", f"\tvs := {mod} with input as {J(tp)}",
                  f"\tcount([v | some v in vs; startswith(v, {pre})]) == 0", "}", ""]
        lines += [f"test_{k}_fail if {{", f"\tvs := {mod} with input as {J(tf)}",
                  f"\tcount([v | some v in vs; startswith(v, {pre})]) > 0"]
        if miss:
            lines.append(f"\tnot {miss} in vs")
        lines += ["}", ""]
        if miss:
            lines += [f"test_{k}_evidence_missing if {{", f"\tvs := {mod} with input as {J(s.tm)}",
                      f"\t{miss} in vs", "}", ""]
        if miss and not s.hollow_ok and R.hollow(s.tp) != s.tp:
            lines += [f"test_{k}_hollow_evidence_not_a_pass if {{", f"\tvs := {mod} with input as {J(R.hollow(s.tp))}",
                      f"\tcount([v | some v in vs; startswith(v, {pre})]) > 0", "}", ""]
    g = good_input(ids)
    lines += ["# every recommendation of the section satisfied at once (the inputs above merged)",
              f"test_{name}_section_compliant_on_merged_good_input if {{",
              f"\tvs := {mod} with input as {J(g)}", "\tcount(vs) == 0", "}", "",
              "# every violation names a recommendation of this section",
              f"test_{name}_violations_carry_section_ids if {{",
              f"\tvs := {mod} with input as {{}}",
              f"\tevery v in vs {{ split(v, \":\")[0] in {json.dumps(sorted(ids, key=sort_key))} }}", "}", ""]
    if name in REGRESSION_TESTS:
        lines += REGRESSION_TESTS[name].strip("\n").split("\n") + [""]
    return "\n".join(lines).rstrip("\n") + "\n"


# Regression tests appended to the generated test file of the module they are keyed by.
_M = "-a always,exit -F arch={a} -S mount -F auid>=1000 -F auid!=unset -k mounts"
_K = ["-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules",
      "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules"]


def _rt(name, inp, rid, want):
    cond = {"pass": f'count([v | some v in vs; startswith(v, "{rid}: ")]) == 0',
            "fail": f'count([v | some v in vs; startswith(v, "{rid}: not met")]) > 0'}[want]
    return f"test_{name} if {{\n\tvs := data.{{PKG}}.auditd.violations with input as {J(inp)}\n\t{cond}\n}}\n"


# Generated regression tests: collected empty rule lists fail; a sweep's truncated flag only matters when
# nothing was found.
AL2023_EMPTY_RULES = r'''
# a collected, empty rule list (auditctl -l printing "No rules", an empty rules.d) is a failure, not missing evidence
test_5_2_3_1_collected_empty_rules_fail if {
	vs := data.cis_amazon_linux_2023.auditd.violations with input as {"auditd": {"rules": [], "active_rules": []}}
	count([v | some v in vs; startswith(v, "5.2.3.1: not met")]) > 0
	count([v | some v in vs; startswith(v, "5.2.3.1: evidence missing")]) == 0
}

test_5_2_3_20_collected_empty_on_disk_rules_fail if {
	vs := data.cis_amazon_linux_2023.auditd.violations with input as {"auditd": {"rules": []}}
	count([v | some v in vs; startswith(v, "5.2.3.20: not met")]) > 0
	count([v | some v in vs; startswith(v, "5.2.3.20: evidence missing")]) == 0
}

'''

AL2023_SWEEP = r'''
# 6.1.11 / 6.1.12: files found fail whether or not the sweep finished; only nothing found and an unfinished sweep is
# missing evidence
test_6_1_11_more_than_100_files_not_truncated_fails if {
	vs := data.cis_amazon_linux_2023.file_permissions.violations with input as {"world_writable": {"files": ["/srv/ww/0", "/srv/ww/1", "/srv/ww/2", "/srv/ww/3", "/srv/ww/4", "/srv/ww/5", "/srv/ww/6", "/srv/ww/7", "/srv/ww/8", "/srv/ww/9", "/srv/ww/10", "/srv/ww/11", "/srv/ww/12", "/srv/ww/13", "/srv/ww/14", "/srv/ww/15", "/srv/ww/16", "/srv/ww/17", "/srv/ww/18", "/srv/ww/19", "/srv/ww/20", "/srv/ww/21", "/srv/ww/22", "/srv/ww/23", "/srv/ww/24", "/srv/ww/25", "/srv/ww/26", "/srv/ww/27", "/srv/ww/28", "/srv/ww/29", "/srv/ww/30", "/srv/ww/31", "/srv/ww/32", "/srv/ww/33", "/srv/ww/34", "/srv/ww/35", "/srv/ww/36", "/srv/ww/37", "/srv/ww/38", "/srv/ww/39", "/srv/ww/40", "/srv/ww/41", "/srv/ww/42", "/srv/ww/43", "/srv/ww/44", "/srv/ww/45", "/srv/ww/46", "/srv/ww/47", "/srv/ww/48", "/srv/ww/49", "/srv/ww/50", "/srv/ww/51", "/srv/ww/52", "/srv/ww/53", "/srv/ww/54", "/srv/ww/55", "/srv/ww/56", "/srv/ww/57", "/srv/ww/58", "/srv/ww/59", "/srv/ww/60", "/srv/ww/61", "/srv/ww/62", "/srv/ww/63", "/srv/ww/64", "/srv/ww/65", "/srv/ww/66", "/srv/ww/67", "/srv/ww/68", "/srv/ww/69", "/srv/ww/70", "/srv/ww/71", "/srv/ww/72", "/srv/ww/73", "/srv/ww/74", "/srv/ww/75", "/srv/ww/76", "/srv/ww/77", "/srv/ww/78", "/srv/ww/79", "/srv/ww/80", "/srv/ww/81", "/srv/ww/82", "/srv/ww/83", "/srv/ww/84", "/srv/ww/85", "/srv/ww/86", "/srv/ww/87", "/srv/ww/88", "/srv/ww/89", "/srv/ww/90", "/srv/ww/91", "/srv/ww/92", "/srv/ww/93", "/srv/ww/94", "/srv/ww/95", "/srv/ww/96", "/srv/ww/97", "/srv/ww/98", "/srv/ww/99"], "count": 250, "truncated": false}, "sticky_bit": {"world_writable_without_sticky": []}}
	count([v | some v in vs; startswith(v, "6.1.11: not met")]) > 0
	count([v | some v in vs; startswith(v, "6.1.11: evidence missing")]) == 0
}

test_6_1_11_nothing_found_in_an_unfinished_sweep_is_evidence_missing if {
	vs := data.cis_amazon_linux_2023.file_permissions.violations with input as {"world_writable": {"files": [], "count": 0, "truncated": true}, "sticky_bit": {"world_writable_without_sticky": []}}
	count([v | some v in vs; startswith(v, "6.1.11: evidence missing")]) > 0
	count([v | some v in vs; startswith(v, "6.1.11: not met")]) == 0
}

test_6_1_12_found_in_an_unfinished_sweep_fails if {
	vs := data.cis_amazon_linux_2023.file_permissions.violations with input as {"unowned_files": {"files": ["/srv/orphan"], "count": 1, "truncated": true}, "ungrouped_files": {"files": [], "count": 0}}
	count([v | some v in vs; startswith(v, "6.1.12: not met")]) > 0
	count([v | some v in vs; startswith(v, "6.1.12: evidence missing")]) == 0
}
'''


REGRESSION_TESTS = {"auditd": "\n".join([
    "# 5.2.3: a rule is required in the on-disk rules (auditd.rules) AND the running rules (auditd.active_rules),",
    "# a syscall rule for arch=b64 AND arch=b32 where the audit lists both (5.2.3.19: b64 only).",
    _rt("mount_rule_both_sources_both_arches_passes", {"auditd": {"rules": [_M.format(a="b64"), _M.format(a="b32")], "active_rules": [_M.format(a="b64"), _M.format(a="b32")]}}, "5.2.3.10", "pass"),
    _rt("mount_rule_running_only_fails", {"auditd": {"rules": ["-e 2"], "active_rules": [_M.format(a="b64"), _M.format(a="b32")]}}, "5.2.3.10", "fail"),
    _rt("mount_rule_on_disk_only_fails", {"auditd": {"rules": [_M.format(a="b64"), _M.format(a="b32")], "active_rules": ["-e 2"]}}, "5.2.3.10", "fail"),
    _rt("mount_rule_b64_only_fails", {"auditd": {"rules": [_M.format(a="b64")], "active_rules": [_M.format(a="b64")]}}, "5.2.3.10", "fail"),
    _rt("module_syscalls_b64_only_passes", {"auditd": {"rules": _K, "active_rules": _K}}, "5.2.3.19", "pass"),
    _rt("privileged_command_watch_form_passes", {"auditd": {"privileged_commands": ["/usr/bin/su"], "rules": ["-w /usr/bin/su -p x -k privileged"], "active_rules": ["-w /usr/bin/su -p x -k privileged"]}}, "5.2.3.6", "pass"),
    _rt("privileged_command_running_only_fails", {"auditd": {"privileged_commands": ["/usr/bin/su"], "rules": ["-e 2"], "active_rules": ["-w /usr/bin/su -p x -k privileged"]}}, "5.2.3.6", "fail"),
]).replace("{PKG}", PKG) + AL2023_EMPTY_RULES, "file_permissions": AL2023_SWEEP}


PROFILES = {"level1_server": 1, "level2_server": 2}


def controls_table(recs):
    return {rid: {"title": recs[rid]["title"], "assessment": recs[rid]["assessment"], "profiles": recs[rid]["profiles"],
                  "level": lvl(recs[rid]), "section": SEC[section_of(rid)][1], "package": section_of(rid)}
            for rid in sorted(recs, key=sort_key)}


def emit_rollup(recs):
    controls = controls_table(recs)
    imports = "\n".join(f"import data.{PKG}.{n}" for n, *_ in SECTIONS)
    modv = ",\n".join(f'\t"{n}": {n}.violations' for n, *_ in SECTIONS)
    sec_inputs = {SEC[n][1]: SECTION_INPUTS[n] for n, *_ in SECTIONS}
    a = sum(1 for r in recs.values() if r["assessment"] == "Automated")
    prio = {SEC[n][1]: p for n, (p, _, _) in RECOMMEND.items()}
    recs_rules = []
    for n, (p, sname, action) in RECOMMEND.items():
        key = SEC[n][1]
        cis = ", ".join(x + ".x" for x in SEC[n][3])
        recs_rules.append(f'''generate_recommendations contains recommendation if {{
	section_compliance[{J(key)}].compliant == false
	recommendation := {{
		"priority": {J(p)},
		"section": {J(sname)},
		"issue": sprintf("%d {n} violations found", [section_compliance[{J(key)}].violation_count]),
		"action": {J(action)},
		"controls": {J("CIS " + cis)},
	}}
}}
''')
    return header(f"{BENCH} — roll-up", len(recs), density="orchestrator", basis="role") + f'''package {PKG}

# {BENCH}: roll-up of the {len(SECTIONS)} section packages.
# Generated by {GEN} from the CIS workbook; do not edit by hand.
# {len(recs)} recommendations ({a} Automated, {len(recs) - a} Manual), every one in the benchmark. Ids,
# Automated/Manual status and profiles are the workbook's. The benchmark has two profiles, Level 1 - Server
# and Level 2 - Server; each control carries its level.
#
# PROFILE: input.profile selects level1_server (default) or level2_server ("level1" / "level2" are accepted).
# Level 2 includes the Level 1 recommendations.
#
# FAIL CLOSED: every Automated recommendation emits its own evidence-missing violation when its facts were
# not collected, and every Manual one fails until attested, so a control is counted as passed only when
# real facts satisfy it. A section none of whose input keys is present is also NOT ASSESSED (listed in
# not_assessed_sections, never compliant). The section keys are the previous module's; each holds the
# sections listed in the package title of its module.

import rego.v1

{imports}

standard_total := {len(recs)}

controls := {json.dumps(controls, indent=1, ensure_ascii=False)}

profiles := {json.dumps({k: {"platform": "server", "level": v} for k, v in PROFILES.items()})}

profile_aliases := {{"level1": "level1_server", "level2": "level2_server"}}

default profile := "level1_server"

profile := input.profile if input.profile in object.keys(profiles)

profile := profile_aliases[input.profile] if not input.profile in object.keys(profiles)

applies(c) if c.level <= profiles[profile].level

applicable_ids := {{id | some id, c in controls; applies(c)}}

module_violations := {{
{modv},
}}

all_violations := sort([v |
	some _, vs in module_violations
	some v in vs
	split(v, ":")[0] in applicable_ids
])

failing_ids := {{split(v, ":")[0] | some v in all_violations}}

# =============================================================================
# ASSESSMENT COVERAGE — which sections received any of the input keys they read
# =============================================================================

section_inputs := {json.dumps(sec_inputs, indent=1)}

section_assessed(name) if {{
	some k in section_inputs[name]
	input[k]
}}

missing_inputs := {{name: [k | some k in section_inputs[name]; not input[k]] | some name, _ in section_inputs}}

not_assessed_sections := sort([name | some name, _ in section_inputs; not section_assessed(name)])

assessed_sections := count(section_inputs) - count(not_assessed_sections)

assessment_coverage_percentage := round((assessed_sections * 100) / count(section_inputs))

section_assessment := {{name: {{"assessed": section_assessed(name) == true, "missing_inputs": missing_inputs[name]}} |
	some name, _ in section_inputs
}}

# =============================================================================
# SECTIONS (controls applicable to the selected profile)
# =============================================================================

section_ids(name) := {{id | some id in applicable_ids; controls[id].section == name}}

section_compliance := {{name: {{
	"compliant": count(section_ids(name) & failing_ids) == 0,
	"controls_covered": count(section_ids(name)),
	"violation_count": count([v | some v in all_violations; split(v, ":")[0] in section_ids(name)]),
}} |
	some name, _ in section_inputs
	count(section_ids(name)) > 0
}}

total_sections := count(section_compliance)

# A section counts as compliant only if it was actually assessed (fail-closed).
compliant_sections := count([name | some name, s in section_compliance; s.compliant == true; section_assessed(name)])

default compliance_percentage := 0

compliance_percentage := (compliant_sections * 100) / total_sections if total_sections > 0

total_controls_covered := count(applicable_ids)

default compliant := false

compliant if {{
	count(object.keys(input)) > 0
	count(applicable_ids) > 0
	count(failing_ids) == 0
	count(not_assessed_sections) == 0
}}

# =============================================================================
# RISK ASSESSMENT AND RECOMMENDATIONS
# =============================================================================

section_priority := {json.dumps(prio, indent=1)}

critical_risks := [v | some v in all_violations; section_priority[controls[split(v, ":")[0]].section] == "critical"]

high_risks := [v | some v in all_violations; section_priority[controls[split(v, ":")[0]].section] == "high"]

overall_risk_level := "critical" if {{
	count(critical_risks) > 0
}} else := "high" if {{
	count(high_risks) > 5
}} else := "medium" if {{
	count(all_violations) > 10
}} else := "low"

{chr(10).join(recs_rules)}
overall_status := "compliant" if {{
	compliant
}} else := "non_compliant"

level2_ids := {{id | some id, c in controls; c.level == 2}}

l2_violations_active := [v | some v in all_violations; split(v, ":")[0] in level2_ids] if {{
	profiles[profile].level == 2
}} else := []

executive_summary := {{
	"overall_status": overall_status,
	"profile": profile,
	"compliance_score": compliance_percentage,
	"sections_evaluated": total_sections,
	"sections_compliant": compliant_sections,
	"total_violations": count(all_violations),
	"l1_violations": count(all_violations) - count(l2_violations_active),
	"l2_violations": count(l2_violations_active),
	"critical_issues": count(critical_risks),
	"top_priorities": [rec | some rec in generate_recommendations; rec.priority == "critical"],
}}
'''


def emit_main(recs):
    return header(f"Bridge: expose {PKG} under the /v1/data/<framework>/main/compliance_report", 0,
                  entry="compliance_report", density="orchestrator", basis="role") + f'''package {PKG}.main

# Bridge: expose {PKG} under the /v1/data/<framework>/main/compliance_report entrypoint convention, so a caller
# can evaluate this framework by key without knowing its internal package layout.
# Generated by {GEN}; do not edit by hand.
#
# 1. Every field is sourced through a DEFAULTED helper: an undefined field inside an object literal makes the
#    whole object undefined, which OPA returns as {{}} — a silently empty result instead of an error.
# 2. total_controls is the number of recommendations applicable to the selected profile (counted from the
#    controls table, never hard-coded); standard_total is the benchmark's {len(recs)}. failed_controls counts
#    distinct failing recommendation ids, including those whose evidence is missing.
#
# FAIL-CLOSED GATE: with no facts at all every control counts as failed and an explicit FAIL-CLOSED
# violation is reported. PARTIAL INPUT: a section that received none of its input keys is NOT ASSESSED
# ({PKG}.section_inputs): it is listed, it adds an explicit violation, and its controls fail on their own
# evidence-missing violations, never as passed.

import data.{PKG} as bench
import rego.v1

default _compliant := false

_compliant := bench.compliant

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["{PKG}"],
)

default _bench_violations := []

_bench_violations := bench.all_violations

default _not_assessed := []

_not_assessed := bench.not_assessed_sections

default _missing_inputs := {{}}

_missing_inputs := bench.missing_inputs

_not_assessed_msgs := [sprintf("NOT ASSESSED: %s — required input not collected: %s", [name, concat(", ", _missing_inputs[name])]) | some name in _not_assessed]

default _sections := {{}}

_sections := bench.section_compliance

default _section_percentage := 0

_section_percentage := bench.compliance_percentage

default _coverage := 0

_coverage := bench.assessment_coverage_percentage

default _profile := "level1_server"

_profile := bench.profile

default _total_controls := 0

_total_controls := count(bench.applicable_ids)

default _failing := 0

_failing := count(bench.failing_ids)

_violations := array.concat(_bench_violations, [_no_facts_msg]) if not _facts_supplied

_violations := array.concat(_bench_violations, _not_assessed_msgs) if _facts_supplied

# No facts => every control is unverified, which counts as failed, not passed.
_failed := _total_controls if not _facts_supplied

_failed := min([_total_controls, _failing]) if _facts_supplied

# Clamp: more failures than known controls must not yield a negative count.
_passed := max([0, _total_controls - _failed])

default _percentage := 0

_percentage := round((_passed * 100000) / _total_controls) / 1000 if _total_controls > 0

compliance_report := {{
	"framework": "{PKG}",
	"benchmark": "{BENCH}",
	"version": "{VERSION}",
	"profile": _profile,
	"total_controls": _total_controls,
	"standard_total": {len(recs)},
	"controls_basis": "CIS recommendations applicable to the selected profile (every one evaluated)",
	"passed_controls": _passed,
	"failed_controls": _failed,
	"compliance_percentage": _percentage,
	"section_compliance_percentage": _section_percentage,
	"compliant": _compliant,
	"violations": _violations,
	"violation_count": count(_violations),
	"section_results": _sections,
	"sections_not_assessed": _not_assessed,
	"missing_inputs": _missing_inputs,
	"assessment_coverage_percentage": _coverage,
}}
'''


def emit_legacy():
    extra = "#   deprecated: true\n#   superseded_by: cis_amazon_linux_2023.main\n"
    return header(f"{BENCH} — deprecated package {LEGACY_PKG} (view of {PKG}.main)", 0, density="orchestrator",
                  basis="role", extra=extra) + f'''package {LEGACY_PKG}

# DEPRECATED. Kept only because the compliance repo's cis_amazon_linux_2023_assessment.yml still POSTs to
# /v1/data/cis/amazon_linux_2023/violations and /compliance_summary. It holds no logic of its own: every value
# is read from {PKG}.main.compliance_report, so the two can never disagree. New callers query
# /v1/data/{PKG}/main/compliance_report. Remove this package once that playbook is migrated.
# Generated by {GEN}; do not edit by hand.

import data.{PKG}.main as bridge
import rego.v1

default _report := {{}}

_report := bridge.compliance_report

default _total := 0

_total := _report.total_controls

default _failed := 0

_failed := _report.failed_controls

default _passed := 0

_passed := _report.passed_controls

default _percentage := 0

_percentage := _report.compliance_percentage

default violations := []

violations := _report.violations

default compliant := false

compliant := _report.compliant

compliance_summary := {{
	"deprecated": true,
	"superseded_by": "{PKG}.main",
	"benchmark": "{BENCH}",
	"total_controls": _total,
	"controls_evaluated": _total,
	"passing_controls": _passed,
	"failing_controls": _failed,
	"compliance_percentage": _percentage,
}}
'''


def emit_rollup_tests(recs):
    counts = {p: sum(1 for r in recs.values() if lvl(r) <= v) for p, v in PROFILES.items()}
    keys = ["framework", "benchmark", "version", "profile", "total_controls", "standard_total", "controls_basis",
            "passed_controls", "failed_controls", "compliance_percentage", "section_compliance_percentage", "compliant",
            "violations", "violation_count", "section_results", "sections_not_assessed", "missing_inputs",
            "assessment_coverage_percentage"]
    m = f"data.{PKG}.main.compliance_report"
    lg = "data." + LEGACY_PKG
    lines = [f"package {PKG}.main_test", "", "import rego.v1", "",
             f"# Generated by {GEN}: roll-up, bridge and deprecated-view tests for {BENCH}.", "",
             "test_every_recommendation_in_table if {",
             f"\tcount(data.{PKG}.controls) == {len(recs)}",
             f"\tcount([c | some c in data.{PKG}.controls; c.assessment == \"Manual\"]) == {EXPECTED_MANUAL}",
             f"\tcount([c | some c in data.{PKG}.controls; c.level == 1]) == {EXPECTED_LEVEL1}",
             f"\tdata.{PKG}.standard_total == {len(recs)}", "}", "",
             "test_empty_input_fails_closed if {", f"\tr := {m} with input as {{}}",
             f"\tcount(object.keys(r)) == {len(keys)}",
             f"\tevery k in {json.dumps(keys)} {{ k in object.keys(r) }}",
             "\tr.compliant == false", f"\tr.total_controls == {counts['level1_server']}",
             "\tr.failed_controls == r.total_controls", "\tr.passed_controls == 0",
             "\tsome v in r.violations", "\tstartswith(v, \"FAIL-CLOSED: no facts supplied\")", "}", ""]
    for p, n in counts.items():
        lines += [f"test_profile_{p}_count if {{", f"\tr := {m} with input as {{\"profile\": \"{p}\"}}",
                  f"\tr.profile == \"{p}\"", f"\tr.total_controls == {n}", f"\tr.standard_total == {len(recs)}",
                  "\tr.failed_controls == r.total_controls", "}", ""]
    lines += ["test_short_profile_values_map_to_server_profiles if {",
              f"\tr1 := {m} with input as {{\"profile\": \"level1\"}}", "\tr1.profile == \"level1_server\"",
              f"\tr1.total_controls == {counts['level1_server']}",
              f"\tr2 := {m} with input as {{\"profile\": \"level2\"}}", "\tr2.profile == \"level2_server\"",
              f"\tr2.total_controls == {counts['level2_server']}", "}", "",
              "test_unknown_profile_defaults_to_level1_server if {",
              f"\tr := {m} with input as {{\"profile\": \"bogus\"}}",
              "\tr.profile == \"level1_server\"", f"\tr.total_controls == {counts['level1_server']}", "}", "",
              "test_one_attested_control_passes if {",
              f"\tr := {m} with input as {{\"attest\": {{\"gpg_keys_reviewed\": true}}}}",
              "\tr.passed_controls == 1", "\tr.failed_controls == r.total_controls - 1", "\tr.compliant == false", "}", "",
              "test_level2_violation_hidden_in_level1_profile if {",
              f"\tvs := data.{PKG}.all_violations with input as {{\"profile\": \"level1_server\"}}",
              "\tcount([v | some v in vs; startswith(v, \"5.2.1.1: \")]) == 0",
              f"\tvs2 := data.{PKG}.all_violations with input as {{\"profile\": \"level2_server\"}}",
              "\tcount([v | some v in vs2; startswith(v, \"5.2.1.1: \")]) > 0", "}", "",
              "test_every_violation_parses_to_a_control if {",
              f"\tvs := data.{PKG}.all_violations with input as {{\"profile\": \"level2_server\"}}",
              f"\tevery v in vs {{ split(v, \":\")[0] in object.keys(data.{PKG}.controls) }}",
              f"\tmvs := data.{PKG}.module_violations with input as {{}}",
              "\tevery _, mv in mvs {",
              f"\t\tevery v in mv {{ split(v, \":\")[0] in object.keys(data.{PKG}.controls) }}", "\t}", "}", "",
              "test_partial_input_lists_sections_not_assessed if {",
              f"\tr := {m} with input as {{\"ssh\": {{\"sshd_config_raw\": \"permitrootlogin no\"}}}}",
              "\tr.compliant == false", "\tnot \"section_5_2_ssh\" in r.sections_not_assessed",
              "\t\"section_4_1_auditd\" in r.sections_not_assessed", "\tr.failed_controls <= r.total_controls", "}", "",
              "# the deprecated cis.amazon_linux_2023 view (read by the compliance repo's assessment playbook)",
              "test_deprecated_view_mirrors_the_bridge if {",
              f"\ts := {lg}.compliance_summary with input as {{}}",
              f"\tr := {m} with input as {{}}",
              "\ts.deprecated == true", "\ts.total_controls == r.total_controls",
              "\ts.failing_controls == r.failed_controls", "\ts.passing_controls == r.passed_controls",
              "\ts.compliance_percentage == r.compliance_percentage",
              f"\tvs := {lg}.violations with input as {{}}", "\tcount(vs) == count(r.violations)",
              f"\tnot {lg}.compliant with input as {{}}", "}", ""]
    return "\n".join(lines).rstrip("\n") + "\n"


def emit_readme(recs, by_mod):
    a = sum(1 for r in recs.values() if r["assessment"] == "Automated")
    attested = sorted([r for r in recs if L[r].manual], key=sort_key)
    rows = []
    for n, f, key, title, _ in SECTIONS:
        ids = by_mod[n]
        mn = sum(1 for r in ids if L[r].manual)
        rows.append(f"| {title} | `{n}` (`{f}`) | {len(ids)}" + (f" ({mn} Manual)" if mn else "") + " |")
    l1 = sum(1 for r in recs.values() if lvl(r) == 1)
    return f'''# {BENCH}

**Version:** v1.0 · generated {README_DATE} by `{GEN}` from the CIS workbook

All {len(recs)} recommendations ({a} Automated, {len(recs) - a} Manual): every Automated one is decided from
collected facts and fails closed with `<id>: evidence missing — <field> not collected` when its facts are
absent; the {len(recs) - a} Manual ones need an operator attestation (`input.attest.<name>`). Ids, status and
profile are the workbook's; the messages are our own wording, not the benchmark text.

Query: `POST /v1/data/{PKG}/main/compliance_report`

This module replaces the earlier hand-written sample of the benchmark. The deprecated package
`{LEGACY_PKG}` (`violations`, `compliance_summary`) is now a view of the bridge for an existing caller.

## Sections

| Sections | Package (file) | Recommendations |
|---|---|---|
{chr(10).join(rows)}

The roll-up is package `{PKG}` (`cis_amazon_linux_2023_complete.rego`); the bridge is `{PKG}.main`.

## Profile

`input.profile`: `level1_server` (default, {l1} recommendations) or `level2_server` (all {len(recs)}; Level 2
includes Level 1). `level1` and `level2` are accepted. `total_controls` is the number in scope for the profile;
`standard_total` is {len(recs)}.

## Facts

The shared Linux fact contract `cis_rhel9` reads (the AAC mapper `cis_linux_build_opa_input.yml`), so one
collector feeds both. Where a check is the same as a CIS RHEL 9 v3.0.0 check, the RHEL 9 logic is reused as is.
Facts this module reads beyond that contract:

| Input | Shape | Read by |
|---|---|---|
| `firewall.nft_ruleset_raw` | text of `nft list ruleset` ("" is an empty ruleset) | 3.4.2.2-3.4.2.4, 3.4.2.7 |
| `firewall.default_zone` | `firewall-cmd --get-default-zone` | 3.4.2.1 |
| `ssh.crypto_policy_override_raw` | text of `/etc/sysconfig/sshd` and `/etc/ssh/sshd_config.d/*.conf` ("" when absent) | 4.2.14 |
| `pam.su_config_raw` | text of `/etc/pam.d/su` | 4.3.6 |
| `user_group.group_members` | `{{group: [member, ...]}}` from `/etc/group` | 4.3.6 |
| `pam.libuser_conf_raw` | text of `/etc/libuser.conf` | 4.5.4 |
| `user_group.shadow_entries[].min_days` | field 4 of `/etc/shadow`, beside the existing aging fields | 4.6.1.2 |
| `user_group.home_dotfiles` | `[{{user, primary_group, path, mode, owner, group}}]`, every dot file in each interactive user's home | 6.2.11 |
| `cron.<cron|at>_allow_*`, `cron.<cron|at>_deny_exists` | allow file exists/mode/owner/group, deny file exists | 4.1.8, 4.1.9 |
| `services["<unit>.socket"]` | socket units (`rpcbind.socket`, `systemd-journal-remote.socket`); Ansible `service_facts` lists `.service` units only | 2.2.17, 5.1.2.1.4 |

`boot_security.kernel_args` (the arguments of every boot entry, `grubby --info=ALL`) decides 5.2.1.2 and
5.2.1.3, as the audit procedure reads them.

## Where the logic differs from the RHEL 9 module

- 1.5.2 accepts `kernel.yama.ptrace_scope = 1` only (the audit script compares for equality).
- 2.2.x: the package must be absent; only 2.2.12, 2.2.16-2.2.18 accept the unit alternative their titles name.
- 4.1.2-4.1.7: owner and group root, no permission for group or other (0700 at most, `/etc/crontab` included).
- 4.1.8 / 4.1.9: the deny file must not exist; the allow file must exist, 0600 at most, root:root.
- 4.2.3: public host keys must be group `root`. 4.6.1.4: 30 days. 5.2.4.3: groups `adm` or `root`.
- 5.1.1.4 / 5.1.1.7: Amazon Linux 2023 ships without rsyslog; a collected `rsyslog.installed == false` is
  evidence (5.1.1.7 passes, 5.1.1.4 is not met until rsyslog with a 0640 `$FileCreateMode` is in use).
- 5.1.3: this benchmark's own file table (no 0644 allowance for `cloud-init.log`, `localmessages`, `waagent.log`).
- 5.2.3.6: each privileged program needs a perm x rule on its path (the audit greps for the path only), not
  the RHEL 9 always,exit rule with both auid filters.
- 5.2.3.15-5.2.3.19: the `perm=x` rules must carry both auid filters on the same line.
- 6.2.11: a `.netrc` with correct access passes (the audit only warns); `.bash_history` must be 0600.
- 3.4.2.7: where nftables.service is enabled, the input and forward base chains must exist with policy drop.

## Attested (Manual)

{", ".join(attested)}

## Regenerate

```
/usr/bin/python3 {GEN} CIS_Amazon_Linux_2023_Benchmark_v1.0.0.xlsx
opa fmt -w benchmarks/cis/amazon_linux_2023
```

Authored with Claude (Anthropic).
'''


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    recs = R.read_workbook(sys.argv[1])
    a = sum(1 for r in recs.values() if r["assessment"] == "Automated")
    m = sum(1 for r in recs.values() if r["assessment"] == "Manual")
    if (len(recs), a, m) != (EXPECTED_TOTAL, EXPECTED_AUTOMATED, EXPECTED_MANUAL):
        raise SystemExit(f"workbook has {len(recs)} recommendations ({a} Automated, {m} Manual)")
    for rid, r in recs.items():
        if len(r["profiles"]) != 1 or lvl(r) not in (1, 2):
            raise SystemExit(f"{rid}: unexpected profiles {r['profiles']}")
    l1 = sum(1 for r in recs.values() if lvl(r) == 1)
    if (l1, len(recs) - l1) != (EXPECTED_LEVEL1, EXPECTED_LEVEL2):
        raise SystemExit(f"workbook has {l1} Level 1 and {len(recs) - l1} Level 2 recommendations")
    if set(L) != set(recs):
        raise SystemExit(f"logic/workbook mismatch: no logic {sorted(set(recs) - set(L), key=sort_key)}; "
                         f"no recommendation {sorted(set(L) - set(recs), key=sort_key)}")
    for rid, r in recs.items():
        if (r["assessment"] == "Manual") != L[rid].manual:
            raise SystemExit(f"{rid}: workbook says {r['assessment']}, logic table disagrees")
        title = r["title"].lower() + " "
        kw = re.sub(r"\s+", " ", KW[rid]).lower().lstrip()
        if kw not in re.sub(r"\s+", " ", title):
            raise SystemExit(f"{rid}: logic keyword {KW[rid]!r} not in workbook title {r['title']!r}")
    by_mod = {n: [] for n, *_ in SECTIONS}
    for rid in sorted(recs, key=sort_key):
        by_mod[section_of(rid)].append(rid)
    for n, keys in SECTION_INPUTS.items():
        read = {p[0] for rid in by_mod[n] for p in L[rid].reads}
        if set(keys) - read:
            raise SystemExit(f"section {n}: section_inputs {sorted(set(keys) - read)} read by no control")
    recs = publish_titles(recs)
    (OUT / "tests").mkdir(parents=True, exist_ok=True)
    for name, fname, *_ in SECTIONS:
        (OUT / fname).write_text(emit_module(name, by_mod[name], recs))
        (OUT / "tests" / f"test_{name}_controls.rego").write_text(emit_tests(name, by_mod[name]))
    (OUT / "cis_amazon_linux_2023_complete.rego").write_text(emit_rollup(recs))
    (OUT / "cis_amazon_linux_2023_main.rego").write_text(emit_main(recs))
    (OUT / "cis_amazon_linux_2023.rego").write_text(emit_legacy())
    (OUT / "tests" / "test_cis_amazon_linux_2023_rollup.rego").write_text(emit_rollup_tests(recs))
    (OUT / "README.md").write_text(emit_readme(recs, by_mod))
    if len(sys.argv) > 2:  # input paths each control reads + merged passing inputs (collector gap analysis)
        pathlib.Path(sys.argv[2]).write_text(json.dumps(
            {"reads": {rid: [".".join(p) for p in L[rid].reads] for rid in sorted(recs, key=sort_key)},
             "good": {n: good_input(by_mod[n]) for n, *_ in SECTIONS}}, indent=1))
    print(f"{len(recs)} recommendations ({a} Automated, {m} Manual; {l1} Level 1) -> {OUT}")


if __name__ == "__main__":
    main()
