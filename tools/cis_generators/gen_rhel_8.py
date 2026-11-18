#!/usr/bin/env python3
"""CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0: every recommendation, from the benchmark's own workbook.

    python3 tools/cis_generators/gen_rhel_8.py CIS_Red_Hat_Enterprise_Linux_8_Benchmark_v4.0.0.xlsx [fields.json]

Needs openpyxl. Reads id, title, Assessment Status and profiles (Level 1/2 - Server/Workstation sheets) out of
the CIS workbook (CIS-licensed, never committed), checks them against the logic table below and emits
benchmarks/cis/rhel_8/, replacing the earlier hand-written module under the same package names (cis_rhel8.<section>,
roll-up cis_rhel8, bridge cis_rhel8.main, Level 2 view cis_rhel8.l2) and the same section keys.

Built on gen_rhel_9.py (imported, never modified): its workbook reader, Spec builders, shared Rego helpers and
emitters are reused. A RHEL 9 v3.0.0 logic entry is reused through same(<rhel 8 id>, <rhel 9 id>) only where the
RHEL 8 audit procedure checks the same thing (compared procedure by procedure, not by title); everything else is
written below from the RHEL 8 audit procedure. The run aborts unless

  * the workbook holds exactly 322 recommendations, 299 Automated and 23 Manual;
  * every id has a logic entry and every logic entry an id, with the same Automated/Manual status;
  * the title keyword of every logic entry occurs in the workbook title of that id (and, for a reused entry,
    the RHEL 9 keyword of the entry it copies is the expected one);
  * the audit procedures are the ones this table was written from (AUDIT_DIGEST: SHA-256 over id, status,
    profiles and whitespace-normalised audit procedure of every recommendation).

Facts: the shared Linux input contract of the rhel_9 module; facts this benchmark needs beyond it are marked
"new" where they are introduced. Rules of the generated code: Automated recommendations evaluate collected facts
and fail closed ("<id>: evidence missing — <field> not collected"); Manual ones are attestations
(input.attest.<name>); messages are our own wording (neutralize.publish_titles).

The generator writes only the files listed in main(); it never deletes anything.
"""
import copy
import hashlib
import json
import pathlib
import re
import sys

import openpyxl

import gen_rhel_9 as R
from neutralize import publish_titles

custom, attest, ref, nest, merge, dotted, J = R.custom, R.attest, R.ref, R.nest, R.merge, R.dotted, R.J

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent.parent / "benchmarks" / "cis" / "rhel_8"
PKG = "cis_rhel8"
GEN = "tools/cis_generators/gen_rhel_8.py"
BENCH = "CIS Red Hat Enterprise Linux 8 Benchmark v4.0.0"
VERSION = "v4.0.0"
FRAMEWORK = "cis_rhel_8"
DOMAINS = "linux, rhel"
EXPECTED_TOTAL, EXPECTED_AUTOMATED, EXPECTED_MANUAL = 322, 299, 23
L2_SAMPLE = "6.3.1.1"   # a Level 2 (Server and Workstation) id the roll-up tests use


def configure(**params):
    """Point the generator at a sibling benchmark that shares this logic table (gen_rocky_linux_8.py)."""
    for k, v in params.items():
        if k not in globals() or not k.isupper():
            raise SystemExit(f"configure: unknown parameter {k}")
        globals()[k] = v


# module name, file, section key (the earlier rhel_8 module's keys: callers read them), title, id prefixes
SECTIONS = [
    ("filesystem", "filesystem_validation.rego", "section_1_1_filesystem", "Section 1.1: Filesystem", ["1.1."]),
    ("initial_setup", "initial_setup_validation.rego", "section_1_initial_setup",
     "Sections 1.2, 1.6-1.8: Package Management, Crypto Policy, Banners, GNOME Display Manager",
     ["1.2.", "1.6.", "1.7.", "1.8."]),
    ("boot_security", "boot_security_validation.rego", "section_1_4_1_5_6_1_boot_security",
     "Sections 1.4, 1.5, 6.1: Bootloader, Process Hardening, Integrity Checking (AIDE)", ["1.4.", "1.5.", "6.1."]),
    ("selinux", "selinux_validation.rego", "section_1_6_selinux", "Section 1.3: Mandatory Access Control (SELinux)",
     ["1.3."]),
    ("services", "services_validation.rego", "section_2_services",
     "Sections 2.1-2.3: Server Services, Client Services, Time Synchronization", ["2.1.", "2.2.", "2.3."]),
    ("network", "network_validation.rego", "section_3_network", "Sections 3-4: Network, Host Based Firewall (firewalld)",
     ["3.", "4."]),
    ("auditd", "auditd_validation.rego", "section_4_1_auditd", "Section 6.3: System Auditing (auditd)", ["6.3."]),
    ("logging", "logging_validation.rego", "section_4_logging", "Section 6.2: System Logging (journald, rsyslog)",
     ["6.2."]),
    ("cron", "cron_validation.rego", "section_5_1_cron", "Section 2.4: Job Schedulers", ["2.4."]),
    ("ssh", "ssh_validation.rego", "section_5_2_ssh", "Section 5.1: SSH Server", ["5.1."]),
    ("sudo", "sudo_validation.rego", "section_5_3_sudo", "Section 5.2: Privilege Escalation", ["5.2."]),
    ("pam", "pam_validation.rego", "section_5_pam",
     "Sections 5.3-5.4: Pluggable Authentication Modules, User Accounts and Environment", ["5.3.", "5.4."]),
    ("file_permissions", "file_permissions_validation.rego", "section_6_1_file_permissions",
     "Section 7.1: System File Permissions", ["7.1."]),
    ("user_group", "user_group_validation.rego", "section_6_2_user_group", "Section 7.2: Local User and Group Settings",
     ["7.2."]),
]
SEC = {n: (f, key, title, pre) for n, f, key, title, pre in SECTIONS}

# NOT ASSESSED: a section is assessed when any of these input keys is present (ansible_facts, services, packages
# and attest are read by many sections and deliberately absent). main() aborts when a key listed here is read by
# no control of the section.
SECTION_INPUTS = {
    "filesystem": ["mount_options", "disabled_filesystem_modules", "usb_storage"],
    "initial_setup": ["initial_setup", "crypto_policy"],
    "boot_security": ["boot_security"],
    "selinux": ["selinux"],
    "services": ["chronyd", "client_packages", "autofs", "mta", "gui", "x11", "webserver"],
    "network": ["sysctl_parameters", "ipv6", "firewall", "wireless_interfaces", "disabled_network_modules"],
    "auditd": ["auditd"],
    "logging": ["rsyslog", "journald", "log_file_permissions"],
    "cron": ["cron"],
    "ssh": ["ssh"],
    "sudo": ["sudo"],
    "pam": ["pam"],
    "file_permissions": ["critical_files", "world_writable", "unowned_files", "ungrouped_files", "sticky_bit"],
    "user_group": ["user_group"],
}
RECOMMEND = dict(R.RECOMMEND)
RECOMMEND["logging"] = ("high", "Logging Configuration", "Configure journald or rsyslog (one logging method)")


def section_of(rid):
    for name, _, _, _, prefixes in SECTIONS:
        if any(rid.startswith(p) for p in prefixes):
            return name
    raise SystemExit(f"no section for {rid}")


# ════════════════════════════════════════════════════════════════════════════════════════════
# LOGIC TABLE — one entry per recommendation of the RHEL 8 v4.0.0 workbook.
# ════════════════════════════════════════════════════════════════════════════════════════════
L, KW = {}, {}


def put(rid, kw, spec):
    if rid in L:
        raise SystemExit(f"{rid} defined twice")
    L[rid], KW[rid] = spec, kw
    return spec


def same(rid, r9, kw=None, r9kw=None):
    """RHEL 8 <rid> checks what RHEL 9 v3.0.0 <r9> checks (audit procedures compared): a private copy of that
    logic entry. r9kw must occur in the RHEL 9 keyword (default: the whole keyword); kw is the keyword checked
    against the RHEL 8 title (default: the RHEL 9 keyword)."""
    if r9 not in R.L or (r9kw or R.KW[r9]).lower() not in R.KW[r9].lower():
        raise SystemExit(f"gen_rhel_9.py: logic entry {r9} is no longer the {r9kw or R.KW[r9]!r} check")
    return put(rid, kw or R.KW[r9], copy.deepcopy(R.L[r9]))


def hollow_ok(spec):
    spec.hollow_ok = True
    return spec


# ── 1.1 filesystem: same audit procedures as RHEL 9 (module probes, /tmp and /dev/shm, separate partitions) ──
for _rid in ["1.1.1.%d" % i for i in range(1, 12)] + ["1.1.2.1.%d" % i for i in range(1, 5)] + \
        ["1.1.2.2.%d" % i for i in range(1, 5)] + ["1.1.2.3.%d" % i for i in range(1, 4)] + \
        ["1.1.2.4.%d" % i for i in range(1, 4)] + ["1.1.2.5.%d" % i for i in range(1, 5)] + \
        ["1.1.2.6.%d" % i for i in range(1, 5)] + ["1.1.2.7.%d" % i for i in range(1, 5)]:
    same(_rid, _rid)

# ── 1.2 package management ──
same("1.2.1.1", "1.2.1.1")                     # Manual: GPG keys
same("1.2.1.2", "1.2.1.2")                     # global gpgcheck on, no repository disabling it
put("1.2.1.3", "repo_gpgcheck", attest("repo_gpgcheck_reviewed"))   # Manual in RHEL 8 v4.0.0
same("1.2.1.4", "1.2.1.4")                     # Manual: repositories
same("1.2.1.5", "1.2.1.5")                     # install_weak_deps disabled in dnf.conf
same("1.2.2.1", "1.2.2.1")                     # Manual: updates

# ── 1.3 SELinux: same procedures ──
for _rid in ["1.3.1.%d" % i for i in range(1, 9)]:
    same(_rid, _rid)

# ── 1.4 bootloader, 1.5 process hardening (RHEL 8 renumbers 1.5) ──
same("1.4.1", "1.4.1")
same("1.4.2", "1.4.2")          # /boot/efi files 0700, others 0600, root:root (grub_file_ok)
for _rid, _r9 in [("1.5.1", "1.5.8"), ("1.5.2", "1.5.1"), ("1.5.3", "1.5.2"), ("1.5.4", "1.5.3"), ("1.5.5", "1.5.4"),
                  ("1.5.6", "1.5.5"), ("1.5.7", "1.5.7"), ("1.5.8", "1.5.6"), ("1.5.9", "1.5.9"), ("1.5.10", "1.5.10")]:
    same(_rid, _r9)

# ── 1.6 crypto policy. RHEL 8 differs from RHEL 9 in 1.6.2-1.6.4 (see the helpers in EXTRA["initial_setup"]) ──
IS = "input.initial_setup."
POL = R.POL   # crypto_policy.current_pol_raw: /etc/crypto-policies/state/CURRENT.pol
same("1.6.1", "1.6.1", kw="not set to legacy")   # the configured policy (/etc/crypto-policies/config) is not LEGACY
# 1.6.2: no unscoped hash/sign line enabling SHA1, AND sha1_in_certs present and 0 (the audit expects the line)
put("1.6.2", "sha1 hash and signature", custom(
    [f'text_collected({ref(POL)})'], [['not r8_sha1_enabled', 'r8_sha1_in_certs_zero']], dotted(POL),
    nest(POL, "hash = SHA2-256 SHA2-384\nsign = RSA-PSS-SHA2-256\nhash@RPM = SHA2-256 SHA1\nsha1_in_certs = 0"),
    nest(POL, "hash = SHA2-256 SHA1\nsign = RSA-PSS-SHA2-256\nsha1_in_certs = 0"), reads=[POL]))
# 1.6.3: the RHEL 8 audit flags 128-bit MACs on the unscoped mac line (RHEL 9: 64-bit)
put("1.6.3", "crypto policy macs", R.text_has(POL, "(?i)^mac\\s*=\\s*([^#]+)?-128\\b", False,
                                              "mac = HMAC-SHA2-256 HMAC-SHA2-512", "mac = HMAC-SHA2-256 UMAC-128"))
# 1.6.4: global CBC is acceptable when an ssh-scoped cipher line exists and has no CBC; no ssh-scoped line may
# carry CBC
put("1.6.4", "cbc for ssh", custom(
    [f'text_collected({ref(POL)})'],
    [['not r8_cbc_global', 'not r8_ssh_cbc_scoped'], ['r8_cbc_global', 'r8_ssh_cipher_scoped', 'not r8_ssh_cbc_scoped']],
    dotted(POL), nest(POL, "cipher = AES-256-GCM AES-128-GCM AES-256-CBC\ncipher@openssh-server = AES-256-GCM AES-128-GCM"),
    nest(POL, "cipher = AES-256-GCM AES-256-CBC"), reads=[POL]))
same("1.6.5", "1.6.5")   # Manual
same("1.6.6", "1.6.6")   # Manual

# ── 1.7 banners, 1.8 GDM ──
for _rid in ["1.7.%d" % i for i in range(1, 7)] + ["1.8.%d" % i for i in range(1, 7)]:
    same(_rid, _rid)
# 1.8.7: RHEL 8 requires WaylandEnable=false in [daemon] of /etc/gdm/custom.conf (RHEL 9 1.8.7 is the reverse)
put("1.8.7", "Xwayland is configured", R.gdm(["gdm_wayland_disabled"], [IS + "gdm_wayland_disabled == true"],
                                             {"gdm_wayland_disabled": True}, {"gdm_wayland_disabled": False}))


# ── 2.1 server services: package not installed, or every unit the audit names neither enabled nor active ──
for _rid, _r9 in [("2.1.1", "2.1.1"), ("2.1.2", "2.1.2"), ("2.1.3", "2.1.3"), ("2.1.4", "2.1.4"), ("2.1.5", "2.1.5"),
                  ("2.1.6", "2.1.6"), ("2.1.7", "2.1.8"), ("2.1.8", "2.1.9"), ("2.1.9", "2.1.10"), ("2.1.11", "2.1.11"),
                  ("2.1.12", "2.1.12"), ("2.1.13", "2.1.13"), ("2.1.14", "2.1.7"), ("2.1.15", "2.1.14"),
                  ("2.1.16", "2.1.15"), ("2.1.17", "2.1.16"), ("2.1.18", "2.1.17"), ("2.1.19", "2.1.18"),
                  ("2.1.22", "2.1.21"), ("2.1.23", "2.1.19"), ("2.1.24", "2.1.23")]:
    same(_rid, _r9)
put("2.1.10", "nis server", R.not_in_use({"ypserv": ["ypserv.service"]}))
put("2.1.20", "xinetd", R.not_in_use({"xinetd": ["xinetd.service"]}))
# 2.1.21: the RHEL 8 audit only checks that the "Server with GUI" environment group is not installed (no
# default-target alternative as in RHEL 9)
put("2.1.21", "GNOME Display Manager is removed", custom(
    ['is_boolean(input.gui.environment_installed)'], [['input.gui.environment_installed == false']],
    "gui.environment_installed", {"gui": {"environment_installed": False}}, {"gui": {"environment_installed": True}},
    reads=[["gui", "environment_installed"]]))

# ── 2.2 clients, 2.3 time synchronization ──
for _rid, _r9 in [("2.2.1", "2.2.1"), ("2.2.2", "2.2.2"), ("2.2.4", "2.2.3"), ("2.2.5", "2.2.4"),
                  ("2.3.1", "2.3.1"), ("2.3.2", "2.3.2"), ("2.3.3", "2.3.3")]:
    same(_rid, _r9)
_cp = '[c | some c in object.get(input, ["client_packages", "analysis"], []); c["package"] == "ypbind"]'
put("2.2.3", "nis client", R.alt(R.pkg_absent(["ypbind"]), [f'count({_cp}) > 0', f'every c in {_cp} {{ is_boolean(c.installed) }}'],
                                 [f'every c in {_cp} {{ c.installed == false }}'], [["client_packages", "analysis"]],
                                 "client_packages.analysis"))

# ── 2.4 job schedulers: same procedures ──
for _rid in ["2.4.1.%d" % i for i in range(1, 10)] + ["2.4.2.1"]:
    same(_rid, _rid)

# ── 3 network ──
for _rid, _r9 in [("3.1.1", "3.1.1"), ("3.1.2", "3.1.2"), ("3.1.3", "3.1.3"), ("3.2.1", "3.2.5"), ("3.2.2", "3.2.6"),
                  ("3.2.3", "3.2.1"), ("3.2.4", "3.2.3"), ("3.2.5", "3.2.4"), ("3.2.6", "3.2.2")]:
    same(_rid, _r9)
for _i in range(1, 19):   # running value and the value systemd-sysctl applies (same script in RHEL 8)
    same(f"3.3.1.{_i}", f"3.3.1.{_i}")
for _i in range(1, 9):    # IF IPv6 is enabled
    same(f"3.3.2.{_i}", f"3.3.2.{_i}")

# ── 4.1 firewalld ──
FW = "input.firewall."
same("4.1.1", "4.1.1")
# 4.1.2: the RHEL 8 audit requires FirewallBackend=nftables (RHEL 9: anything but iptables)
put("4.1.2", "backend", custom([f'text_collected({FW}backend)'], [[f'lower({FW}backend) == "nftables"']], "firewall.backend",
                               {"firewall": {"backend": "nftables"}}, {"firewall": {"backend": "iptables"}},
                               reads=[["firewall", "backend"]]))
for _rid in ["4.1.3", "4.1.4", "4.1.5", "4.1.6", "4.1.7"]:
    same(_rid, _rid)


# ── 5.1 SSH server. The effective configuration (ssh.sshd_config_raw) is `sshd -T $OPTIONS $CRYPTO_POLICY` with
#    /etc/crypto-policies/back-ends/opensshserver.config and /etc/sysconfig/sshd sourced, as the RHEL 8 audits run it ──
SS = "input.ssh."
SYSCONF = ["ssh", "sysconfig_sshd_raw"]          # new: text of /etc/sysconfig/sshd (comments included)
SYSPERM = ["ssh", "sysconfig_permissions"]       # new: /etc/sysconfig/sshd {mode, pw_name, gr_name}
# 5.1.1: no active CRYPTO_POLICY= line, and the commented "# CRYPTO_POLICY=" line is present
put("5.1.1", "crypto_policy is not set", custom(
    [f'text_collected({ref(SYSCONF)})'], [['not sshd_crypto_policy_active', 'sshd_crypto_policy_commented']],
    dotted(SYSCONF), nest(SYSCONF, "# CRYPTO_POLICY=\nOPTIONS=\"\""),
    nest(SYSCONF, "CRYPTO_POLICY='-oCiphers=aes256-ctr'\n# CRYPTO_POLICY="), reads=[SYSCONF]))
same("5.1.2", "5.1.1", kw="/etc/ssh/sshd_config is")     # sshd_config and sshd_config.d/*.conf 0600 root:root
_sp = {"mode": "0640", "pw_name": "root", "gr_name": "root"}
put("5.1.3", "/etc/sysconfig/sshd is", custom(
    [f'{ref(SYSPERM)}.mode != null', f'{ref(SYSPERM)}.pw_name != null', f'{ref(SYSPERM)}.gr_name != null'],
    [[f'perm_ok({ref(SYSPERM)}, "0640")']], dotted(SYSPERM),
    nest(SYSPERM, _sp), nest(SYSPERM, dict(_sp, mode="0644")), reads=[SYSPERM]))
same("5.1.4", "5.1.3")   # private host keys: root:root 0600 or root:ssh_keys 0640
# 5.1.5: RHEL 8 requires the public host keys group-owned by root (RHEL 9 also accepts ssh_keys)
_pub = {"path": "/etc/ssh/ssh_host_ed25519_key.pub", "mode": "0644", "pw_name": "root", "gr_name": "root"}
put("5.1.5", "public host key", custom(
    [f'is_array({SS}public_key_permissions)', f'count({SS}public_key_permissions) > 0'],
    [[f'every k in {SS}public_key_permissions {{ perm_ok(k, "0644") }}']], "ssh.public_key_permissions",
    {"ssh": {"public_key_permissions": [_pub]}}, {"ssh": {"public_key_permissions": [dict(_pub, gr_name="ssh_keys")]}},
    reads=[["ssh", "public_key_permissions"]]))
for _rid, _r9 in [("5.1.6", "5.1.8"), ("5.1.7", "5.1.9"), ("5.1.8", "5.1.5"), ("5.1.9", "5.1.10"), ("5.1.10", "5.1.11"),
                  ("5.1.11", "5.1.12"), ("5.1.12", "5.1.13"), ("5.1.13", "5.1.14"), ("5.1.14", "5.1.6"),
                  ("5.1.15", "5.1.15"), ("5.1.16", "5.1.16"), ("5.1.18", "5.1.17"), ("5.1.19", "5.1.19"),
                  ("5.1.20", "5.1.18"), ("5.1.21", "5.1.20"), ("5.1.22", "5.1.21"), ("5.1.23", "5.1.22"),
                  ("5.1.24", "5.1.23")]:
    same(_rid, _r9)
# 5.1.17: the RHEL 8 weak-MAC list (no hmac-sha1 / hmac-sha1-etm, adds umac-128-etm)
WEAK_MAC_8 = ["hmac-md5", "hmac-md5-96", "hmac-ripemd160", "hmac-sha1-96", "umac-64@openssh.com",
              "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-ripemd160-etm@openssh.com",
              "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com", "umac-128-etm@openssh.com"]
put("5.1.17", "sshd MACs", R.sshd_list_none("macs", WEAK_MAC_8, "hmac-sha2-512-etm@openssh.com,hmac-sha2-256",
                                           "hmac-sha2-256,umac-128-etm@openssh.com"))

# ── 5.2 privilege escalation ──
for _rid, _r9 in [("5.2.1", "5.2.1"), ("5.2.2", "5.2.4"), ("5.2.3", "5.2.5"), ("5.2.4", "5.2.6"), ("5.2.5", "5.2.7"),
                  ("5.2.6", "5.2.10"), ("5.2.7", "5.2.12")]:
    same(_rid, _r9)

# ── 5.3 PAM ──
PA = "input.pam."
PV = R.PV
for _rid, _kw, _pkg, _mn in [("5.3.1.1", "version of pam", "pam", "1.3.1-25"),
                             ("5.3.1.2", "version of authselect", "authselect", "1.2.6-1")]:
    _v = f'{ref(PV)}[{json.dumps(_pkg)}]'
    put(_rid, _kw, custom([f'text_collected({_v})'], [[f'rpm_version_ge({_v}, {json.dumps(_mn)})']],
                          f"pam.package_versions[{_pkg}]", {"pam": {"package_versions": {_pkg: _mn + ".el8"}}},
                          {"pam": {"package_versions": {_pkg: "1.0.0-1.el8"}}}, {"pam": {"package_versions": {}}},
                          reads=[PV]))
# 5.3.2.1: the active profile's system-auth and password-auth templates carry pwquality, pwhistory, faillock, unix
APF = ["pam", "authselect_profile_files"]   # new: {"system-auth": text, "password-auth": text} of the active profile
_mods = ["pam_pwquality", "pam_pwhistory", "pam_faillock", "pam_unix"]
_tmpl = R.PAMOK.replace("pam_faillock.so preauth silent", 'pam_faillock.so preauth silent {include if "with-faillock"}')
put("5.3.2.1", "active authselect profile includes pam modules", custom(
    [f'text_collected({ref(APF)}["system-auth"])', f'text_collected({ref(APF)}["password-auth"])'],
    [[f'every f in ["system-auth", "password-auth"] {{ every m in {json.dumps(_mods)} {{ '
      f'regex_in_text({ref(APF)}[f], concat("", [`\\b`, m, `\\.so\\b`])) }} }}']],
    dotted(APF), nest(APF, {"system-auth": _tmpl, "password-auth": _tmpl}),
    nest(APF, {"system-auth": _tmpl, "password-auth": R.drop(_tmpl, "pam_pwhistory")}),
    nest(APF, {"system-auth": _tmpl}), reads=[APF]))
for _rid in ["5.3.2.2", "5.3.2.3", "5.3.2.4", "5.3.2.5", "5.3.3.1.1", "5.3.3.1.2", "5.3.3.1.3"] + \
        ["5.3.3.2.%d" % i for i in range(1, 8)] + ["5.3.3.3.1", "5.3.3.3.2", "5.3.3.3.3"] + \
        ["5.3.3.4.%d" % i for i in range(1, 5)]:
    same(_rid, _rid)

# ── 5.4 user accounts and environment ──
for _rid in ["5.4.1.%d" % i for i in range(1, 7)] + ["5.4.2.%d" % i for i in range(1, 6)] + \
        ["5.4.2.7", "5.4.2.8", "5.4.3.1", "5.4.3.2"]:
    same(_rid, _rid)
# 5.4.2.6: umask lines of /root/.bash_profile and /root/.bashrc (the SUSE sibling's facts); none set passes
RSI = ["user_group", "root_shell_init_raw"]   # new for this contract: text of /root/.bash_profile + /root/.bashrc
put("5.4.2.6", "root user umask", custom(
    None, [[f'is_string({ref(RSI)})', f'every u in umask_values({ref(RSI)}) {{ umask_ok(u) }}'], ['input.user_group.root_shell_init_exists == false']],
    "user_group.root_shell_init_raw/root_shell_init_exists", nest(RSI, "umask 0027"), nest(RSI, "umask 0022"),
    reads=[RSI, ["user_group", "root_shell_init_exists"]],
    ev_alts=[[f'is_string({ref(RSI)})'], ['input.user_group.root_shell_init_exists == false']]))
# 5.4.3.3: a umask of 027 or stricter in /etc/profile.d/*.sh (at least one) AND UMASK in /etc/login.defs
PDR = ["pam", "profile_d_raw"]   # new for this contract (the Ubuntu sibling's): text of /etc/profile.d/*.sh
put("5.4.3.3", "default user umask", custom(
    [f'text_collected({ref(PDR)})', f'{PA}login_defs_umask != null'],
    [[f'count(umask_values({ref(PDR)})) > 0', f'every u in umask_values({ref(PDR)}) {{ umask_ok(u) }}',
      f'umask_ok(sprintf("%v", [{PA}login_defs_umask]))']],
    "pam.profile_d_raw/login_defs_umask", {"pam": {"profile_d_raw": "umask 027", "login_defs_umask": "027"}},
    {"pam": {"profile_d_raw": "umask 022", "login_defs_umask": "027"}}, {"pam": {"profile_d_raw": "umask 027"}},
    reads=[PDR, ["pam", "login_defs_umask"]]))


# ── 6.1 integrity checking (AIDE): same procedures as RHEL 9 6.3.1-6.3.3 ──
for _rid, _r9 in [("6.1.1", "6.3.1"), ("6.1.2", "6.3.2"), ("6.1.3", "6.3.3")]:
    same(_rid, _r9)


# ── 6.2 logging. The benchmark covers journald OR rsyslog: "only one is implemented". The method is decided from
#    collected facts: rsyslog when rsyslog.service_active is true, journald when rsyslog is collected inactive or
#    not installed (EXTRA["logging"]). A recommendation of the other method's subsection passes as not applicable;
#    with no rsyslog facts the method is undecided and the facts of the recommendation itself are required. ──
RSM = [["rsyslog", "service_active"], ["rsyslog", "installed"]]


def only_if(spec, method):
    """method: 'rsyslog' or 'journald'; the recommendation is not applicable under the other logging method"""
    other = {"rsyslog": "logging_journald", "journald": "logging_rsyslog"}[method]
    spec.ev_alts = spec.ev_alts + [[other]]
    spec.passes = spec.passes + [[other]]
    spec.reads = spec.reads + [p for p in RSM if p not in spec.reads]
    spec.field = f"{spec.field} (or the logging method)"
    return spec


JD = "input.journald."
same("6.2.1.1.1", "6.1.1.1")
put("6.2.1.1.2", "log file access", attest("journald_file_access_reviewed"))
put("6.2.1.1.3", "log file rotation", attest("journald_rotation_reviewed"))
put("6.2.1.1.4", "ForwardToSyslog is disabled", only_if(custom(
    [f'is_string({JD}forward_to_syslog)'], [[f'lower({JD}forward_to_syslog) != "yes"']], "journald.forward_to_syslog",
    {"journald": {"forward_to_syslog": "no"}}, {"journald": {"forward_to_syslog": "yes"}},
    reads=[["journald", "forward_to_syslog"]]), "journald"))
# journald.storage_mode / compress_enabled: effective values (the SUSE / Ubuntu siblings' fields)
put("6.2.1.1.5", "journald Storage", custom(
    [f'is_string({JD}storage_mode)'], [[f'lower({JD}storage_mode) == "persistent"']], "journald.storage_mode",
    {"journald": {"storage_mode": "persistent"}}, {"journald": {"storage_mode": "auto"}}, reads=[["journald", "storage_mode"]]))
put("6.2.1.1.6", "journald Compress", custom(
    [f'is_string({JD}compress_enabled)'], [[f'lower({JD}compress_enabled) == "yes"']], "journald.compress_enabled",
    {"journald": {"compress_enabled": "yes"}}, {"journald": {"compress_enabled": "no"}},
    reads=[["journald", "compress_enabled"]]))
put("6.2.1.2.1", "systemd-journal-remote is installed",
    only_if(R.pkg_present("systemd-journal-remote"), "journald"))
put("6.2.1.2.2", "systemd-journal-remote authentication", attest("journal_remote_authentication_configured"))
put("6.2.1.2.3", "systemd-journal-upload is enabled",
    only_if(R.unit_running("systemd-journal-upload.service"), "journald"))
same("6.2.1.2.4", "6.1.1.2", kw="systemd-journal-remote service is not in use")  # .socket and .service off
same("6.2.2.1", "6.1.2.1")
only_if(L["6.2.2.1"], "rsyslog")
L["6.2.2.1"].tf = {"rsyslog": {"installed": False, "service_active": True}}   # rsyslog is the method: must fail
same("6.2.2.2", "6.1.2.2")
only_if(L["6.2.2.2"], "rsyslog")
same("6.2.2.3", "6.1.1.3")
only_if(L["6.2.2.3"], "rsyslog")
same("6.2.2.4", "6.1.2.3", kw="log file creation mode")   # $FileCreateMode 0640 or stricter
only_if(L["6.2.2.4"], "rsyslog")
put("6.2.2.5", "rsyslog logging is configured", attest("rsyslog_logging_rules_reviewed"))
put("6.2.2.6", "remote log host", attest("rsyslog_remote_host_configured"))
# 6.2.2.7: the RHEL 8 audit looks for TCP reception only (imtcp, $InputTCPServerRun)
put("6.2.2.7", "not configured to receive logs", only_if(R.text_has(
    R.RC, "(?i)(^module\\(\\s*load\\s*=\\s*\"?imtcp\"?[\\s,)]|^input\\(\\s*type\\s*=\\s*\"?imtcp\"?|"
          "^\\$ModLoad\\s+imtcp\\b|^\\$InputTCPServerRun\\b)",
    False, "*.* /var/log/messages", 'module(load="imtcp")'), "rsyslog"))
put("6.2.2.8", "logrotate", attest("logrotate_reviewed"))
# 6.2.3.1: per-file classes of the RHEL 8 audit script (EXTRA["logging"]); owner_has_login_shell is new
LF = ["log_file_permissions", "analysis"]
put("6.2.3.1", "access to all logfiles", custom(
    [f'is_array({ref(LF)})', f'count({ref(LF)}) > 0'], [[f'every f in {ref(LF)} {{ log_file_ok(f) }}']], dotted(LF),
    nest(LF, [{"file": "/var/log/messages", "actual_mode": "0600", "actual_owner": "root", "actual_group": "root"},
              {"file": "/var/log/wtmp", "actual_mode": "0664", "actual_owner": "root", "actual_group": "utmp"},
              {"file": "/var/log/chrony/measurements.log", "actual_mode": "0640", "actual_owner": "chrony",
               "actual_group": "chrony", "owner_has_login_shell": False}]),
    nest(LF, [{"file": "/var/log/app.log", "actual_mode": "0640", "actual_owner": "alice", "actual_group": "alice",
               "owner_has_login_shell": True}]),
    reads=[LF]))


# ── 6.3 auditd ──
GRUB, KA = R.GRUB, R.KA
same("6.3.1.1", "6.2.1.1")
# 6.3.1.2 / 6.3.1.3: every boot entry (grubby --info=ALL; boot_security.kernel_args) AND GRUB_CMDLINE_LINUX
put("6.3.1.2", "prior to auditd", custom(
    [f'is_array({ref(KA)})', f'count({ref(KA)}) > 0', f'text_collected({ref(GRUB)})'],
    [['every a in input.boot_security.kernel_args { kernel_arg_has(a, `^audit=1$`) }', 'grub_cmdline_has(`^audit=1$`)']],
    "boot_security.kernel_args/bootloader.grub_config",
    merge(nest(KA, ["ro audit=1 audit_backlog_limit=8192"]), nest(GRUB, 'GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192"')),
    merge(nest(KA, ["ro audit=1 audit_backlog_limit=8192", "ro audit_backlog_limit=8192"]), nest(GRUB, 'GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192"')),
    nest(GRUB, 'GRUB_CMDLINE_LINUX="quiet audit=1"'), reads=[KA, GRUB]))
put("6.3.1.3", "audit_backlog_limit", custom(
    [f'is_array({ref(KA)})', f'count({ref(KA)}) > 0', f'text_collected({ref(GRUB)})'],
    [['every a in input.boot_security.kernel_args { backlog_ok(regex.split(`\\s+`, a)) }', 'backlog_ok(grub_cmdline_tokens)']],
    "boot_security.kernel_args/bootloader.grub_config",
    merge(nest(KA, ["ro audit=1 audit_backlog_limit=8192"]), nest(GRUB, 'GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192"')),
    merge(nest(KA, ["ro audit=1 audit_backlog_limit=8192"]), nest(GRUB, 'GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=64"')),
    nest(GRUB, 'GRUB_CMDLINE_LINUX="audit=1 audit_backlog_limit=8192"'), reads=[KA, GRUB]))
same("6.3.1.4", "6.2.1.4")
for _rid, _r9 in [("6.3.2.1", "6.2.2.1"), ("6.3.2.2", "6.2.2.2"), ("6.3.2.3", "6.2.2.3"), ("6.3.2.4", "6.2.2.4")]:
    same(_rid, _r9)

# 6.3.3 audit rules. Each RHEL 8 audit checks the on-disk rules (/etc/audit/rules.d, auditd.rules) AND the running
# rules (auditctl -l, auditd.active_rules); every matched rule must carry a key (-k / key=). Syscall rules the audit
# lists for arch=b64 and arch=b32 are required for both; auid>=1000 is the RHEL 8 UID_MIN default.
AR, ARD = R.AR, R.ARD
SRC = '["rules", "active_rules"]'
WATCH = "-w {p} -p {perm} -k k"
SYS = "-a always,exit -F arch={a} -S {s} {extra}-k k"
EXEC = "-a always,exit -F path={p} -F perm=x -F auid>=1000 -F auid!=unset -k k"
EXTRA_F = {"auid": "-F auid>=1000 -F auid!=unset ", "euid": "-C euid!=uid -F auid!=unset ",
           "eacces": "-F exit=-EACCES -F auid>=1000 -F auid!=unset ", "eperm": "-F exit=-EPERM -F auid>=1000 -F auid!=unset ",
           "unset": "-F auid!=unset "}
# collected = both are lists; an empty list is collected and the required rule is then absent (a failure)
AUDIT_EV = R.AUDIT_EV


def audit8(watches=(), syscalls=(), execs=(), extra_ev=(), extra_pass=(), extra_tp=None, reads=()):
    """watches: [(path, perm)]; syscalls: [(names, [field kinds], arches)]; execs: [path]. Good rules are listed
    watches, executables, then syscall rules (b64 before b32), so the failing case (last rule dropped) is a missing
    b32 rule wherever the audit names both architectures."""
    conds, good = [], []
    for p, perm in watches:
        conds.append(f'every src in {SRC} {{ audit8_watch(src, {json.dumps(p)}, {json.dumps(perm)}) }}')
        good.append(WATCH.format(p=p, perm=perm))
    for p in execs:
        conds.append(f'every src in {SRC} {{ audit8_exec(src, {json.dumps(p)}) }}')
        good.append(EXEC.format(p=p))
    for names, fields, arches in syscalls:
        conds.append(f'every src in {SRC} {{ every s in {json.dumps(names)} {{ every a in {json.dumps(list(arches))} '
                     f'{{ audit8_syscall(src, s, {json.dumps(fields)}, a) }} }} }}')
        extra = "".join(EXTRA_F[f] for f in fields)
        good += [SYS.format(a=a, s=",".join(names), extra=extra) for a in sorted(arches, reverse=True)]
    tp = {"auditd": {"rules": good, "active_rules": good}}
    bad = good[:-1] or [f"-w {p} -p x -k k" for p in execs]   # exec-only: a watch without the auid filters
    tf = {"auditd": {"rules": bad, "active_rules": bad}}
    if extra_tp:
        tp, tf = merge(tp, extra_tp), merge(tf, extra_tp)
    return custom(AUDIT_EV + list(extra_ev), [conds + list(extra_pass)], "auditd.rules/active_rules", tp, tf,
                  {"auditd": {"active_rules": good}}, reads=[ARD, AR] + list(reads))


B = ("b32", "b64")
put("6.3.3.1", "sudoers", audit8([("/etc/sudoers", "wa"), ("/etc/sudoers.d", "wa")]))
put("6.3.3.2", "actions as another user", audit8(syscalls=[(["execve"], ["euid"], B)]))
SU_ = R.SU_
_s = put("6.3.3.3", "modify the sudo log file", audit8(
    extra_ev=[f'text_collected({ref(SU_)})'],
    extra_pass=['count(sudo_logfiles) > 0', f'every f in sudo_logfiles {{ every src in {SRC} {{ audit8_watch(src, f, "wa") }} }}'],
    extra_tp={"sudo": {"sudoers_content": 'Defaults logfile="/var/log/sudo.log"'}}, reads=[SU_]))
_s.tp = merge(_s.tp, {"auditd": {"rules": [WATCH.format(p="/var/log/sudo.log", perm="wa")],
                                 "active_rules": [WATCH.format(p="/var/log/sudo.log", perm="wa")]}})
_s.tf = {"auditd": {"rules": [WATCH.format(p="/var/log/other.log", perm="wa")],
                    "active_rules": [WATCH.format(p="/var/log/other.log", perm="wa")]},
         "sudo": {"sudoers_content": 'Defaults logfile="/var/log/sudo.log"'}}
_s.tm = {"auditd": {"rules": _s.tf["auditd"]["rules"]}, "sudo": _s.tf["sudo"]}
put("6.3.3.4", "date and time", audit8([("/etc/localtime", "wa")], [(["adjtimex", "settimeofday", "clock_settime"], [], B)]))
put("6.3.3.5", "network environment", audit8(
    [(p, "wa") for p in ["/etc/issue", "/etc/issue.net", "/etc/hosts", "/etc/hostname", "/etc/sysconfig/network",
                         "/etc/sysconfig/network-scripts", "/etc/NetworkManager"]],
    [(["sethostname", "setdomainname"], [], B)]))
# 6.3.3.6: every setuid/setgid binary on a local filesystem (auditd.privileged_commands) is audited for execution
PC = R.PC
_s = put("6.3.3.6", "privileged commands", audit8(
    extra_ev=[f'is_array({ref(PC)})', f'count({ref(PC)}) > 0'],
    extra_pass=[f'every c in {ref(PC)} {{ every src in {SRC} {{ audit8_watch(src, c, "x") }} }}'], reads=[PC]))
_good = [EXEC.format(p="/usr/bin/su")]
_s.tp = {"auditd": {"rules": _good, "active_rules": _good, "privileged_commands": ["/usr/bin/su"]}}
_s.tf = {"auditd": {"rules": _good, "active_rules": _good, "privileged_commands": ["/usr/bin/su", "/usr/bin/passwd"]}}
_s.tm = {"auditd": {"rules": _good, "active_rules": _good}}
_ACC = ["creat", "open", "openat", "truncate", "ftruncate"]
put("6.3.3.7", "unsuccessful file access", audit8(syscalls=[(_ACC, ["eacces"], B), (_ACC, ["eperm"], B)]))
put("6.3.3.8", "user/group information", audit8(
    [(p, "wa") for p in ["/etc/group", "/etc/passwd", "/etc/gshadow", "/etc/shadow", "/etc/security/opasswd",
                         "/etc/nsswitch.conf", "/etc/pam.conf", "/etc/pam.d"]]))
put("6.3.3.9", "discretionary access control", audit8(syscalls=[
    (["chmod", "fchmod", "fchmodat"], ["auid"], B), (["chown", "fchown", "lchown", "fchownat"], ["auid"], B),
    (["setxattr", "lsetxattr", "fsetxattr", "removexattr", "lremovexattr", "fremovexattr"], ["auid"], B)]))
put("6.3.3.10", "file system mounts", audit8(syscalls=[(["mount"], ["auid"], B)]))
put("6.3.3.11", "session initiation", audit8([("/var/run/utmp", "wa"), ("/var/log/wtmp", "wa"), ("/var/log/btmp", "wa")]))
put("6.3.3.12", "login and logout", audit8([("/var/log/lastlog", "wa"), ("/var/run/faillock", "wa")]))
put("6.3.3.13", "file deletion", audit8(syscalls=[(["unlink", "unlinkat", "rename", "renameat"], ["auid"], B)]))
put("6.3.3.14", "Mandatory Access Controls", audit8([("/etc/selinux", "wa"), ("/usr/share/selinux", "wa")]))
for _rid, _kw, _p in [("6.3.3.15", "chcon", "/usr/bin/chcon"), ("6.3.3.16", "setfacl", "/usr/bin/setfacl"),
                      ("6.3.3.17", "chacl", "/usr/bin/chacl"), ("6.3.3.18", "usermod", "/usr/sbin/usermod")]:
    put(_rid, _kw, audit8(execs=[_p]))
# 6.3.3.19: the audit lists the module syscalls for arch=b64 only (auid!=unset) and the kmod executable rule.
# create_module and query_module, also in the example, are not required: the kernel no longer provides them.
put("6.3.3.19", "kernel module loading", audit8(execs=["/usr/bin/kmod"],
                                                syscalls=[(["init_module", "finit_module", "delete_module"], ["unset"], ("b64",))]))
same("6.3.3.20", "6.2.3.34")   # -c in the on-disk rules
same("6.3.3.21", "6.2.3.35")   # last -e of the on-disk rules is 2
put("6.3.3.22", "running and on disk", attest("audit_rules_running_match_disk"))   # Manual in RHEL 8 v4.0.0
for _rid, _r9 in [("6.3.4.1", "6.2.4.1"), ("6.3.4.2", "6.2.4.2"), ("6.3.4.3", "6.2.4.3"), ("6.3.4.5", "6.2.4.5"),
                  ("6.3.4.6", "6.2.4.6"), ("6.3.4.7", "6.2.4.7"), ("6.3.4.8", "6.2.4.8"), ("6.3.4.9", "6.2.4.9"),
                  ("6.3.4.10", "6.2.4.10")]:
    same(_rid, _r9)
# 6.3.4.4: log files group root or adm AND log_group in auditd.conf set to root or adm (an unset log_group fails)
LP = "input.auditd.log_permissions."
put("6.3.4.4", "log files group owner", custom(
    [f'{LP}gr_name != null', f'text_collected({ref(R.AC)})'],
    [[f'{LP}gr_name in {{"root", "adm"}}', 'lower(conf_last(input.auditd.config, "log_group")) in {"root", "adm"}']],
    "auditd.log_permissions.gr_name/auditd.config",
    {"auditd": {"log_permissions": {"gr_name": "adm"}, "config": "log_group = adm"}},
    {"auditd": {"log_permissions": {"gr_name": "root"}, "config": "log_file = /var/log/audit/audit.log"}},
    {"auditd": {"log_permissions": {"gr_name": "root"}}}, reads=[["auditd", "log_permissions", "gr_name"], R.AC]))

# ── 7.1 system file permissions, 7.2 local users and groups: same procedures ──
for _rid in ["7.1.%d" % i for i in range(1, 14)] + ["7.2.%d" % i for i in range(1, 10)]:
    same(_rid, _rid)

# Offender lists: a collected empty list is a genuine pass (carried over from the RHEL 9 entries they copy; the
# same() copies keep the flag).

# ── helpers used by one module only: the RHEL 9 blocks for the logic reused from them, plus this benchmark's ──
_SSH = R.EXTRA["ssh"]
_PV_OLD, _PV_NEW = "regex.match(`^5\\.1\\.[1-4]: `, v)", "regex.match(`^5\\.1\\.[2-5]: `, v)"
if _PV_OLD not in _SSH:
    raise SystemExit("gen_rhel_9.py: the ssh permission_violations rule changed; review the 5.1.2-5.1.5 mapping")
EXTRA = {
    "initial_setup": r'''
# 1.6.2: an unscoped hash/sign line of CURRENT.pol whose value enables SHA1 (a value starting with "-" removes it)
r8_sha1_enabled if {
	some l in active_lines(input.crypto_policy.current_pol_raw)
	some m in regex.find_all_string_submatch_n(`^(hash|sign)\s*=\s*(.*)$`, l, 1)
	contains(m[2], "SHA1")
	not startswith(trim_space(m[2]), "-")
}

# the audit expects the sha1_in_certs line itself, set to 0
r8_sha1_in_certs_zero if num(conf_last(input.crypto_policy.current_pol_raw, "sha1_in_certs")) == 0

# 1.6.4: CBC in the global cipher line, and the ssh-scoped cipher lines
r8_cbc_global if regex_in_text(input.crypto_policy.current_pol_raw, `(?i)^cipher\s*=\s*([^#]+)?-CBC\b`)

r8_ssh_cipher_scoped if regex_in_text(input.crypto_policy.current_pol_raw, `(?i)^cipher@(lib|open)ssh(-server|-client)?\s*=`)

r8_ssh_cbc_scoped if {
	regex_in_text(input.crypto_policy.current_pol_raw, `(?i)^cipher@(lib|open)ssh(-server|-client)?\s*=\s*([^#]+)?-CBC\b`)
}
''',
    "boot_security": R.EXTRA["boot_security"],
    "selinux": R.EXTRA["selinux"],
    "services": R.EXTRA["services"],
    "network": R.EXTRA["network"],
    "ssh": _SSH.replace(_PV_OLD, _PV_NEW).replace("the 5.1.1 / 5.1.3 / 5.1.4 (file access)", "the 5.1.2-5.1.5 (file access)")
    + r'''
# /etc/sysconfig/sshd lines, comments included (5.1.1 needs the commented CRYPTO_POLICY= line)
sshd_sysconfig_lines := [trim_space(l) | some l in split(input.ssh.sysconfig_sshd_raw, "\n")]

sshd_crypto_policy_active if {
	some l in sshd_sysconfig_lines
	regex.match(`(?i)^CRYPTO_POLICY\s*=`, l)
}

sshd_crypto_policy_commented if {
	some l in sshd_sysconfig_lines
	regex.match(`(?i)^#\s*CRYPTO_POLICY\s*=`, l)
}
''',
    "sudo": R.EXTRA["sudo"],
    "pam": R.EXTRA["pam"],
    "logging": r'''
# Logging method (6.2 covers journald OR rsyslog; only one is implemented): rsyslog when its service is active,
# journald when rsyslog is collected inactive or not installed. Undecided when the rsyslog facts are missing.
logging_rsyslog if input.rsyslog.service_active == true

logging_journald if {
	not logging_rsyslog
	input.rsyslog.service_active == false
}

logging_journald if {
	not logging_rsyslog
	input.rsyslog.installed == false
}

# 6.2.3.1: file classes of the benchmark's audit script, by file name
log_base(p) := regex.replace(p, `^.*/`, "")

log_class(b) := "login" if {
	regex.match(`^(lastlog(\..*)?|(wtmp|btmp)([.-].*)?|README)$`, b)
} else := "cloud" if {
	regex.match(`^(cloud-init\.log|localmessages|waagent\.log)`, b)
} else := "auth" if {
	regex.match(`^(secure([.-].*)?|secure.*\..*|auth\.log|syslog|messages)$`, b)
} else := "sssd" if {
	b in {"SSSD", "sssd"}
} else := "gdm" if {
	b in {"gdm", "gdm3"}
} else := "journal" if {
	regex.match(`\.journal~?$`, b)
} else := "other"

# class -> [max mode, owners, groups]
log_spec := {
	"login": ["0664", {"root"}, {"root", "utmp"}],
	"cloud": ["0644", {"root", "syslog"}, {"root", "adm"}],
	"auth": ["0640", {"root", "syslog"}, {"root", "adm"}],
	"sssd": ["0660", {"root", "SSSD"}, {"root", "SSSD"}],
	"gdm": ["0660", {"root"}, {"root", "gdm", "gdm3"}],
	"journal": ["0640", {"root"}, {"root", "systemd-journal"}],
}

log_file_ok(f) if {
	c := log_class(log_base(f.file))
	c != "other"
	s := log_spec[c]
	mode_within(f.actual_mode, s[0])
	f.actual_owner in s[1]
	f.actual_group in s[2]
}

# any other log: 0640 or stricter; owned by root or by a service account (no login shell), whose own group is
# then accepted, or by syslog with group root or adm
log_file_ok(f) if {
	log_class(log_base(f.file)) == "other"
	mode_within(f.actual_mode, "0640")
	f.actual_owner == "root"
}

log_file_ok(f) if {
	log_class(log_base(f.file)) == "other"
	mode_within(f.actual_mode, "0640")
	f.owner_has_login_shell == false
}

log_file_ok(f) if {
	log_class(log_base(f.file)) == "other"
	mode_within(f.actual_mode, "0640")
	f.actual_owner == "syslog"
	f.actual_group in {"root", "adm"}
}
''',
    "auditd": R.EXTRA["auditd"] + r'''
# 6.3.3: rules of one source, "rules" (on disk) or "active_rules" (auditctl -l); each matched rule needs a key
audit8_lines(src) := [l |
	some r in input.auditd[src]
	l := trim_space(r)
	l != ""
	not startswith(l, "#")
]

audit8_keyed(l) if regex.match(`(\s-k\s*\S+|\skey=\S+)\s*$`, l)

audit8_watch(src, p, perm) if {
	some l in audit8_lines(src)
	audit_path_tok(l, p)
	pv := audit_perm(l)
	every i in numbers.range(0, count(perm) - 1) { contains(pv, substring(perm, i, 1)) }
	audit8_keyed(l)
}

audit8_exec(src, p) if {
	some l in audit8_lines(src)
	regex.match(`^-a\s+(always,exit|exit,always)(\s|$)`, l)
	concat("", ["path=", p]) in audit_toks(l)
	contains(audit_perm(l), "x")
	audit_field(l, "auid")
	audit8_keyed(l)
}

audit8_syscall(src, s, fields, arch) if {
	some l in audit8_lines(src)
	regex.match(`^-a\s+(always,exit|exit,always)(\s|$)`, l)
	concat("", ["arch=", arch]) in audit_toks(l)
	s in line_syscalls(l)
	every f in fields { audit_field(l, f) }
	audit8_keyed(l)
}

audit_field(l, "unset") if regex.match(audit_unset, l)

# 6.3.1.2 / 6.3.1.3: kernel arguments of one boot entry
kernel_arg_has(a, re) if {
	some t in regex.split(`\s+`, a)
	regex.match(re, t)
}

backlog_ok(toks) if {
	some t in toks
	startswith(t, "audit_backlog_limit=")
	num(substring(t, 20, -1)) >= 8192
}
''',
}

# Regression tests appended to the generated test file of the module they are keyed by ("data.cis_rhel8." is
# rewritten to the configured package). They pin the decisions above that differ from RHEL 9.
REGRESSION_TESTS = {
    "services": r'''
# 0.0.0.0 is the wildcard address, not loopback (the benchmark's own script accepts it; this module does not)
test_mta_inet_interfaces_wildcard_address_flagged if {
	vs := data.cis_rhel8.services.violations with input as {"mta": {"has_mta": true, "non_loopback_listeners": [], "inet_interfaces": "0.0.0.0"}}
	count([v | some v in vs; startswith(v, "2.1.23: not met")]) > 0
}

test_mta_inet_interfaces_127_0_0_1_accepted if {
	vs := data.cis_rhel8.services.violations with input as {"mta": {"has_mta": true, "non_loopback_listeners": [], "inet_interfaces": "127.0.0.1"}}
	count([v | some v in vs; startswith(v, "2.1.23: ")]) == 0
}
''',
    "logging": r'''
# the logging method: rsyslog active makes the journald-only recommendations not applicable, and the reverse
test_rsyslog_method_journal_upload_not_applicable if {
	vs := data.cis_rhel8.logging.violations with input as {"rsyslog": {"installed": true, "service_active": true}}
	count([v | some v in vs; startswith(v, "6.2.1.2.1: ")]) == 0
	count([v | some v in vs; startswith(v, "6.2.1.2.3: ")]) == 0
	count([v | some v in vs; startswith(v, "6.2.1.1.4: ")]) == 0
}

test_journald_method_rsyslog_not_applicable if {
	vs := data.cis_rhel8.logging.violations with input as {"rsyslog": {"installed": false}}
	count([v | some v in vs; startswith(v, "6.2.2.1: ")]) == 0
	count([v | some v in vs; startswith(v, "6.2.2.3: ")]) == 0
	count([v | some v in vs; startswith(v, "6.2.1.2.1: ")]) > 0
}

test_rsyslog_method_forward_to_syslog_required if {
	vs := data.cis_rhel8.logging.violations with input as {"rsyslog": {"service_active": true}, "journald": {"forward_to_syslog": "no"}}
	count([v | some v in vs; startswith(v, "6.2.2.3: not met")]) > 0
}

test_remote_receive_module_with_params_flagged if {
	vs := data.cis_rhel8.logging.violations with input as {"rsyslog": {"installed": true, "service_active": true, "config_raw": "module(load=\"imtcp\" MaxSessions=\"500\")\n"}}
	count([v | some v in vs; startswith(v, "6.2.2.7: not met")]) > 0
}

test_remote_receive_commented_not_flagged if {
	vs := data.cis_rhel8.logging.violations with input as {"rsyslog": {"installed": true, "service_active": true, "config_raw": "#module(load=\"imtcp\")\n*.* /var/log/messages\n"}}
	count([v | some v in vs; startswith(v, "6.2.2.7: ")]) == 0
}

test_log_file_owned_by_login_user_fails if {
	vs := data.cis_rhel8.logging.violations with input as {"log_file_permissions": {"analysis": [{"file": "/var/log/messages", "actual_mode": "0640", "actual_owner": "alice", "actual_group": "root"}]}}
	count([v | some v in vs; startswith(v, "6.2.3.1: not met")]) > 0
}
''',
    "auditd": r'''
# on-disk and running rules are both required, keys are required, b32 and b64 are both required
test_audit_rule_only_running_is_evidence_missing if {
	vs := data.cis_rhel8.auditd.violations with input as {"auditd": {"active_rules": ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"]}}
	count([v | some v in vs; startswith(v, "6.3.3.10: evidence missing")]) > 0
}

test_audit_rule_without_key_fails if {
	r := ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset"]
	vs := data.cis_rhel8.auditd.violations with input as {"auditd": {"rules": r, "active_rules": r}}
	count([v | some v in vs; startswith(v, "6.3.3.10: not met")]) > 0
}

test_audit_rule_b64_only_fails if {
	r := ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts"]
	vs := data.cis_rhel8.auditd.violations with input as {"auditd": {"rules": r, "active_rules": r}}
	count([v | some v in vs; startswith(v, "6.3.3.10: not met")]) > 0
}

test_audit_running_differs_from_disk_fails if {
	ok := ["-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts", "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"]
	vs := data.cis_rhel8.auditd.violations with input as {"auditd": {"rules": ok, "active_rules": ["-e 2"]}}
	count([v | some v in vs; startswith(v, "6.3.3.10: not met")]) > 0
}
# a collected, empty rule list (auditctl -l printing "No rules", an empty rules.d) is a failure, not missing evidence
test_6_3_3_1_collected_empty_rules_fail if {
	vs := data.cis_rhel8.auditd.violations with input as {"auditd": {"rules": [], "active_rules": []}}
	count([v | some v in vs; startswith(v, "6.3.3.1: not met")]) > 0
	count([v | some v in vs; startswith(v, "6.3.3.1: evidence missing")]) == 0
}

test_6_3_3_20_collected_empty_on_disk_rules_fail if {
	vs := data.cis_rhel8.auditd.violations with input as {"auditd": {"rules": []}}
	count([v | some v in vs; startswith(v, "6.3.3.20: not met")]) > 0
	count([v | some v in vs; startswith(v, "6.3.3.20: evidence missing")]) == 0
}

test_6_3_3_21_collected_empty_on_disk_rules_fail if {
	vs := data.cis_rhel8.auditd.violations with input as {"auditd": {"rules": []}}
	count([v | some v in vs; startswith(v, "6.3.3.21: not met")]) > 0
	count([v | some v in vs; startswith(v, "6.3.3.21: evidence missing")]) == 0
}
''',
    "file_permissions": r'''
# 7.1.11 / 7.1.12: files found fail whether or not the sweep finished; only nothing found and an unfinished sweep is
# missing evidence
test_7_1_11_more_than_100_files_not_truncated_fails if {
	vs := data.cis_rhel8.file_permissions.violations with input as {"world_writable": {"files": ["/srv/ww/0", "/srv/ww/1", "/srv/ww/2", "/srv/ww/3", "/srv/ww/4", "/srv/ww/5", "/srv/ww/6", "/srv/ww/7", "/srv/ww/8", "/srv/ww/9", "/srv/ww/10", "/srv/ww/11", "/srv/ww/12", "/srv/ww/13", "/srv/ww/14", "/srv/ww/15", "/srv/ww/16", "/srv/ww/17", "/srv/ww/18", "/srv/ww/19", "/srv/ww/20", "/srv/ww/21", "/srv/ww/22", "/srv/ww/23", "/srv/ww/24", "/srv/ww/25", "/srv/ww/26", "/srv/ww/27", "/srv/ww/28", "/srv/ww/29", "/srv/ww/30", "/srv/ww/31", "/srv/ww/32", "/srv/ww/33", "/srv/ww/34", "/srv/ww/35", "/srv/ww/36", "/srv/ww/37", "/srv/ww/38", "/srv/ww/39", "/srv/ww/40", "/srv/ww/41", "/srv/ww/42", "/srv/ww/43", "/srv/ww/44", "/srv/ww/45", "/srv/ww/46", "/srv/ww/47", "/srv/ww/48", "/srv/ww/49", "/srv/ww/50", "/srv/ww/51", "/srv/ww/52", "/srv/ww/53", "/srv/ww/54", "/srv/ww/55", "/srv/ww/56", "/srv/ww/57", "/srv/ww/58", "/srv/ww/59", "/srv/ww/60", "/srv/ww/61", "/srv/ww/62", "/srv/ww/63", "/srv/ww/64", "/srv/ww/65", "/srv/ww/66", "/srv/ww/67", "/srv/ww/68", "/srv/ww/69", "/srv/ww/70", "/srv/ww/71", "/srv/ww/72", "/srv/ww/73", "/srv/ww/74", "/srv/ww/75", "/srv/ww/76", "/srv/ww/77", "/srv/ww/78", "/srv/ww/79", "/srv/ww/80", "/srv/ww/81", "/srv/ww/82", "/srv/ww/83", "/srv/ww/84", "/srv/ww/85", "/srv/ww/86", "/srv/ww/87", "/srv/ww/88", "/srv/ww/89", "/srv/ww/90", "/srv/ww/91", "/srv/ww/92", "/srv/ww/93", "/srv/ww/94", "/srv/ww/95", "/srv/ww/96", "/srv/ww/97", "/srv/ww/98", "/srv/ww/99"], "count": 250, "truncated": false}, "sticky_bit": {"world_writable_without_sticky": []}}
	count([v | some v in vs; startswith(v, "7.1.11: not met")]) > 0
	count([v | some v in vs; startswith(v, "7.1.11: evidence missing")]) == 0
}

test_7_1_11_nothing_found_in_an_unfinished_sweep_is_evidence_missing if {
	vs := data.cis_rhel8.file_permissions.violations with input as {"world_writable": {"files": [], "count": 0, "truncated": true}, "sticky_bit": {"world_writable_without_sticky": []}}
	count([v | some v in vs; startswith(v, "7.1.11: evidence missing")]) > 0
	count([v | some v in vs; startswith(v, "7.1.11: not met")]) == 0
}

test_7_1_12_found_in_an_unfinished_sweep_fails if {
	vs := data.cis_rhel8.file_permissions.violations with input as {"unowned_files": {"files": ["/srv/orphan"], "count": 1, "truncated": true}, "ungrouped_files": {"files": [], "count": 0}}
	count([v | some v in vs; startswith(v, "7.1.12: not met")]) > 0
	count([v | some v in vs; startswith(v, "7.1.12: evidence missing")]) == 0
}
''',
}

# ── workbook ──
AUDIT_DIGEST = "ac23b93fb10653574530ac1189b6f19ec59e609acac0b7c00080003d47927ed2"


def audit_digest(path):
    """SHA-256 over (id, status, profiles, audit procedure with whitespace collapsed) of every recommendation."""
    wb = openpyxl.load_workbook(path, read_only=True)
    recs = {}
    for ws in wb.worksheets:
        if ws.title in R.SKIP_SHEETS:
            continue
        rows = ws.iter_rows(values_only=True)
        head = next(rows)
        for r in rows:
            d = dict(zip(head, r))
            if not d.get("Recommendation #"):
                continue
            rid = str(d["Recommendation #"]).strip()
            rec = recs.setdefault(rid, {"status": str(d["Assessment Status"]).strip(), "profiles": [],
                                        "audit": " ".join(str(d["Audit Procedure"]).split())})
            rec["profiles"].append(ws.title)
    h = hashlib.sha256()
    for rid in sorted(recs, key=R.sort_key):
        rec = recs[rid]
        h.update("\x1f".join([rid, rec["status"], ",".join(rec["profiles"]), rec["audit"]]).encode() + b"\x1e")
    return h.hexdigest()


# Wording of the shared RHEL 9 emitter that describes rhel_9 history, restated for this module. Every pair must
# match at least once across the emitted files.
def reword():
    return [
        ("(e.g. 1.1.1.9 is Level 1", "(e.g. 1.1.1.10 is Level 1"),
        ('("level1" / "level2", the v2.0.0 values, mean', '("level1" / "level2", the earlier values, mean'),
        ("The section keys are the v2.0.0 ones; each now holds the v3.0.0", f"The section keys are the earlier module's; each holds the {VERSION}"),
        ("(v2.0.0 shapes)", "(the earlier module's shapes)"),
        ("of the v2.0.0 package;", "of the earlier hand-written package;"),
        ("# v2.0.0 compatibility", "# compatibility with the earlier module"),
        ("# v2.0.0 report shape", "# report shape of the earlier module"),
        ('"6.2.1.1: "', f'"{L2_SAMPLE}: "'),
        ("test_v3_", "test_"),
    ]


RESIDUE = ["v2.0.0", "rhel9", "RHEL 9", "1.1.1.9 is Level", "6.2.1.1: ", "test_v3_"]


def main(argv=None):
    argv = sys.argv if argv is None else argv
    if len(argv) < 2:
        raise SystemExit(__doc__)
    digest = audit_digest(argv[1])
    if digest != AUDIT_DIGEST:
        raise SystemExit(f"audit procedures, statuses or profiles differ from the ones the logic table was written "
                         f"from (digest {digest}): review the changed recommendations before regenerating")
    R.configure(OUT=OUT, PKG=PKG, GEN=GEN, BENCH=BENCH, VERSION=VERSION, EXPECTED_TOTAL=EXPECTED_TOTAL,
                EXPECTED_AUTOMATED=EXPECTED_AUTOMATED, EXPECTED_MANUAL=EXPECTED_MANUAL, FRAMEWORK=FRAMEWORK,
                DOMAINS=DOMAINS, EXTENDED=False, REPORT_EXTRA=[("violation_count", "count(_violations)")],
                SECTIONS=SECTIONS, SEC=SEC, SECTION_INPUTS=SECTION_INPUTS, RECOMMEND=RECOMMEND, L=L, KW=KW,
                EXTRA=EXTRA, REGRESSION_TESTS=REGRESSION_TESTS,
                GOOD_OVERRIDE={("journald", "forward_to_syslog"): "yes"})
    R.section_of = section_of
    recs = R.read_workbook(argv[1])
    a = sum(1 for r in recs.values() if r["assessment"] == "Automated")
    m = sum(1 for r in recs.values() if r["assessment"] == "Manual")
    if (len(recs), a, m) != (EXPECTED_TOTAL, EXPECTED_AUTOMATED, EXPECTED_MANUAL):
        raise SystemExit(f"workbook has {len(recs)} recommendations ({a} Automated, {m} Manual)")
    if set(L) != set(recs):
        raise SystemExit(f"logic/workbook mismatch: no logic {sorted(set(recs) - set(L), key=R.sort_key)}; "
                         f"no recommendation {sorted(set(L) - set(recs), key=R.sort_key)}")
    for rid, r in recs.items():
        if (r["assessment"] == "Manual") != L[rid].manual:
            raise SystemExit(f"{rid}: workbook says {r['assessment']}, logic table disagrees")
        kw = re.sub(r"\s+", " ", KW[rid]).lower().lstrip()
        if kw not in " ".join(r["title"].split()).lower() + " ":
            raise SystemExit(f"{rid}: logic keyword {KW[rid]!r} not in workbook title {r['title']!r}")
    recs = publish_titles(recs)
    by_mod = {n: [] for n, *_ in SECTIONS}
    for rid in sorted(recs, key=R.sort_key):
        by_mod[section_of(rid)].append(rid)
    for name, keys in SECTION_INPUTS.items():
        read = {p[0] for rid in by_mod[name] for p in L[rid].reads}
        if set(keys) - read:
            raise SystemExit(f"section_inputs[{name}]: {sorted(set(keys) - read)} read by no control of the section")
    files = {}
    for name, fname, *_ in SECTIONS:
        files[fname] = R.emit_module(name, by_mod[name], recs)
        files[f"tests/test_{name}_controls.rego"] = R.emit_tests(name, by_mod[name])
    files[f"{PKG}_complete.rego"] = R.emit_rollup(recs, by_mod)
    files[f"{PKG}_main.rego"] = R.emit_main(recs)
    files["l2_validation.rego"] = R.emit_l2(recs)
    files[f"tests/test_{PKG}_rollup.rego"] = R.emit_rollup_tests(recs)
    files[f"tests/test_{PKG}_control_results.rego"] = R.emit_control_results_tests(recs, by_mod)
    files = {k: v.replace("data.cis_rhel8.", f"data.{PKG}.") for k, v in files.items()}
    for old, new in reword():
        if not any(old in t for t in files.values()):
            raise SystemExit(f"emitter wording changed: {old!r} no longer found")
        files = {k: v.replace(old, new) for k, v in files.items()}
    for k, t in files.items():
        for bad in RESIDUE:
            if bad in t:
                raise SystemExit(f"{k}: RHEL 9 wording {bad!r} left in the emitted text")
    (OUT / "tests").mkdir(parents=True, exist_ok=True)
    for k, t in files.items():
        (OUT / k).write_text(t)
    if len(argv) > 2:  # input paths each control reads + merged passing inputs (gap analysis, collector work)
        pathlib.Path(argv[2]).write_text(json.dumps(
            {"reads": {rid: [".".join(p) for p in L[rid].reads] for rid in sorted(recs, key=R.sort_key)},
             "good": {n: R.good_input(by_mod[n]) for n, *_ in SECTIONS}}, indent=1))
    print(f"{len(recs)} recommendations ({a} Automated, {m} Manual) -> {OUT}")


if __name__ == "__main__":
    main()
