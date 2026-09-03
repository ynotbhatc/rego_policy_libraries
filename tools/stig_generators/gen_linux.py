#!/usr/bin/env python3
"""Generate Linux-family STIG modules (Ubuntu 22.04, Amazon Linux 2023, SLES 15).

Unlike the Windows registry family, Linux check-content is prose-heavy, so
rule logic is hand-authored here as compact Rego expressions per stig_id;
the generator stamps verified vuln_id/severity/title from the July 2026
XCCDF catalogs and emits modules, orchestrator, and green-fixture tests.
A rule listed here but missing from the catalog aborts generation — IDs
can never drift silently.

Shared input contract (documented in each module header):
  input.packages                  : list of installed package names
  input.sshd_config.<Directive>   : effective sshd value (string/number)
  input.ssh_client_config.Ciphers / .MACs
  input.sysctl["key"]             : number
  input.services[name].active|enabled|masked : bool
  input.fips.enabled              : bool
  input.crypto_policy.policy      : e.g. "FIPS"
  input.crypto_policy.overridden  : bool
  input.grub.password_required    : bool
  input.pam.nullok_present        : bool   (any nullok in pam auth stack)
  input.passwd.blank_password_accounts : list
  input.gdm.automatic_login_enabled    : bool
  input.systemd.ctrl_alt_del_masked    : bool
  input.systemd.ctrl_alt_del_burst_disabled : bool
  input.forbidden_files.shosts_present / .shosts_equiv_present : bool
  input.os.vendor_supported       : bool
  input.storage.persistent_partitions_encrypted : bool
  input.repos.gpgcheck / .localpkg_gpgcheck / .all_repos_gpgcheck : bool
  input.sudo.only_required_members : bool (attestation)
  input.sssd.pki_mapping_configured : bool
  input.x11.forwarding_disabled — via sshd_config X11Forwarding
"""
import json, os, re

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "benchmarks", "stig")
CATS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalogs")

FIPS_SSH_CIPHERS = "aes256-ctr,aes192-ctr,aes128-ctr"
FIPS_SSH_MACS = "hmac-sha2-512,hmac-sha2-256"

# semantic logic → (rego body lines builder, fixture contribution)
def pkg_absent(p):
    return ([f'not "{p}" in input.packages'], {})
def pkg_present(p):
    return ([f'"{p}" in input.packages'], ("packages", p))
def sshd(k, v):
    vv = f'"{v}"' if isinstance(v, str) else v
    return ([f'input.sshd_config.{k} == {vv}'], ("sshd_config", k, v))
def sshd_contains_only_fips(k, fixval):
    return ([f'input.sshd_config.{k} == "{fixval}"'], ("sshd_config", k, fixval))
def boolfact(path, val=True):
    parts = path.split(".")
    expr = "input." + ".".join(parts)
    return ([f"{expr} == {str(val).lower()}"], ("BOOL", path, val))
def svc_active(name):
    return ([f'input.services["{name}"].active == true'], ("services", name, {"active": True}))
def svc_masked(name):
    return ([f'input.services["{name}"].masked == true'], ("services", name, {"masked": True}))
def sysctl(k, n):
    return ([f'input.sysctl["{k}"] == {n}'], ("sysctl", k, n))
def empty_list(path):
    return ([f"count(input.{path}) == 0"], ("EMPTYLIST", path))
def crypto_policy_fips():
    return (['input.crypto_policy.policy == "FIPS"'], ("BOOL2", "crypto_policy.policy", "FIPS"))
def sshd_max(k, n):
    return ([f'input.sshd_config.{k} <= {n}', f'input.sshd_config.{k} > 0'], ("sshd_config", k, n))
def cp_ossh(field, val):
    return ([f'input.crypto_policy.{field} == "{val}"'], ("BOOL2", f"crypto_policy.{field}", val))
def crypto_not_overridden():
    return (["input.crypto_policy.overridden == false"], ("BOOL", "crypto_policy.overridden", False))

PLATFORMS = {
  "ubuntu_22_04": {
    "pkg": "ubuntu_22_04", "platform": "Canonical Ubuntu 22.04 LTS",
    "rules": {
      "UBTU-22-211000": boolfact("os.vendor_supported"),
      "UBTU-22-211015": boolfact("systemd.ctrl_alt_del_masked"),
      "UBTU-22-212010": boolfact("grub.password_required"),
      "UBTU-22-215030": pkg_absent("rsh-server"),
      "UBTU-22-215035": pkg_absent("telnet"),
      "UBTU-22-255010": pkg_present("openssh-server"),
      "UBTU-22-255015": svc_active("ssh"),
      "UBTU-22-255025": (['input.sshd_config.PermitEmptyPasswords == "no"',
                          'input.sshd_config.PermitUserEnvironment == "no"'],
                         ("sshd_config2", {"PermitEmptyPasswords": "no", "PermitUserEnvironment": "no"})),
      "UBTU-22-255040": sshd("X11Forwarding", "no"),
      "UBTU-22-271030": boolfact("gdm.ctrl_alt_del_disabled"),
      "UBTU-22-432015": boolfact("sudo.only_required_members"),
      "UBTU-22-611060": boolfact("pam.nullok_present", False),
      "UBTU-22-611065": empty_list("passwd.blank_password_accounts"),
      "UBTU-22-612040": boolfact("sssd.pki_mapping_configured"),
      "UBTU-22-671010": boolfact("fips.enabled"),
      # High-value CAT II config checks (values verified against check text)
      "UBTU-22-213010": sysctl("kernel.dmesg_restrict", 1),
      "UBTU-22-213015": svc_masked("kdump-tools"),
      "UBTU-22-255030": sshd("ClientAliveCountMax", 1),
      "UBTU-22-255035": sshd_max("ClientAliveInterval", 600),
      "UBTU-22-255045": sshd("X11UseLocalhost", "yes"),
      "UBTU-22-255050": sshd("Ciphers", "aes256-ctr,aes256-gcm@openssh.com,aes128-ctr,aes128-gcm@openssh.com"),
      "UBTU-22-255055": sshd("MACs", "hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com"),
    },
  },
  "amazon_linux_2023": {
    "pkg": "amazon_linux_2023", "platform": "Amazon Linux 2023",
    "rules": {
      "AZLX-23-000050": boolfact("fips.enabled"),
      "AZLX-23-000100": boolfact("storage.persistent_partitions_encrypted"),
      "AZLX-23-000115": boolfact("repos.localpkg_gpgcheck"),
      "AZLX-23-000120": boolfact("repos.gpgcheck"),
      "AZLX-23-000125": boolfact("repos.all_repos_gpgcheck"),
      "AZLX-23-000130": boolfact("os.vendor_supported"),
      "AZLX-23-000300": pkg_absent("vsftpd"),
      "AZLX-23-001180": pkg_present("openssh-server"),
      "AZLX-23-001185": svc_active("sshd"),
      "AZLX-23-001195": pkg_present("crypto-policies"),
      "AZLX-23-001205": cp_ossh("opensshserver_ciphers", "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"),
      "AZLX-23-001210": cp_ossh("opensshserver_macs", "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"),
      "AZLX-23-001225": sshd("RekeyLimit", "1G 1h"),
      "AZLX-23-001255": sshd("UsePAM", "yes"),
      "AZLX-23-001270": crypto_policy_fips(),
      "AZLX-23-001285": crypto_not_overridden(),
      "AZLX-23-002450": boolfact("selinux.enforcing"),
      "AZLX-23-001206": cp_ossh("openssh_client_ciphers", "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"),
      "AZLX-23-001211": cp_ossh("openssh_client_macs", "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"),
      # CAT II derivable set (IDs from catalog lookup)
      "AZLX-23-001240": sshd("PermitRootLogin", "no"),
      "AZLX-23-001235": sshd("PermitEmptyPasswords", "no"),
      "AZLX-23-000225": sysctl("kernel.randomize_va_space", 2),
      "AZLX-23-000200": sysctl("kernel.dmesg_restrict", 1),
    },
  },
  "sles_15": {
    "pkg": "sles_15", "platform": "SUSE Linux Enterprise Server 15",
    "rules": {
      "SLES-15-010000": boolfact("os.vendor_supported"),
      "SLES-15-010030": pkg_absent("vsftpd"),
      "SLES-15-010035": pkg_present("crypto-policies"),
      "SLES-15-010045": crypto_policy_fips(),
      "SLES-15-010046": crypto_not_overridden(),
      "SLES-15-010160": cp_ossh("opensshserver_ciphers", "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr"),
      "SLES-15-010180": pkg_absent("telnet-server"),
      "SLES-15-010190": boolfact("grub.password_required"),
      "SLES-15-010200": boolfact("grub.uefi_password_required"),
      "SLES-15-010270": cp_ossh("opensshserver_macs", "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512"),
      "SLES-15-010330": boolfact("storage.persistent_partitions_encrypted"),
      "SLES-15-010430": boolfact("repos.gpgcheck"),
      "SLES-15-010450": boolfact("sudo.nopasswd_or_noauthenticate_present", False),
      "SLES-15-010510": boolfact("fips.enabled"),
      "SLES-15-010530": svc_active("sshd"),
      "SLES-15-020100": boolfact("accounts.root_only_uid0"),
      "SLES-15-020181": empty_list("passwd.blank_password_accounts"),
      "SLES-15-020300": boolfact("pam.nullok_present", False),
      "SLES-15-040020": boolfact("forbidden_files.shosts_present", False),
      "SLES-15-040030": boolfact("forbidden_files.shosts_equiv_present", False),
      "SLES-15-040060": boolfact("systemd.ctrl_alt_del_masked"),
      "SLES-15-040061": boolfact("gdm.ctrl_alt_del_disabled"),
      "SLES-15-040062": boolfact("systemd.ctrl_alt_del_burst_disabled"),
      "SLES-15-040430": boolfact("gdm.automatic_login_enabled", False),
      "SLES-15-040440": sshd("PermitEmptyPasswords", "no"),
      # CAT II derivable set
      "SLES-15-010220": sshd("PermitRootLogin", "no"),
      "SLES-15-010280": sshd("X11Forwarding", "no"),
    },
  },
}

def rego_ident(stig_id):
    return "r_" + re.sub(r"[^a-z0-9]+", "_", stig_id.lower()).strip("_")

def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')

def set_deep(fx, dotted, val):
    parts = dotted.split(".")
    d = fx
    for p in parts[:-1]:
        d = d.setdefault(p, {})
    d[parts[-1]] = val

def build_fixture(entries):
    fx = {}
    for e in entries:
        if not e: continue
        kind = e[0]
        if kind == "packages":
            fx.setdefault("packages", [])
            if e[1] not in fx["packages"]: fx["packages"].append(e[1])
        elif kind == "sshd_config":
            fx.setdefault("sshd_config", {})[e[1]] = e[2]
        elif kind == "sshd_config2":
            fx.setdefault("sshd_config", {}).update(e[1])
        elif kind == "services":
            fx.setdefault("services", {}).setdefault(e[1], {}).update(e[2])
        elif kind == "sysctl":
            fx.setdefault("sysctl", {})[e[1]] = e[2]
        elif kind == "BOOL":
            set_deep(fx, e[1], e[2])
        elif kind == "BOOL2":
            set_deep(fx, e[1], e[2])
        elif kind == "EMPTYLIST":
            set_deep(fx, e[1], [])
    return fx



ALIAS_TMPL = """# Framework-key entrypoint alias with the fail-closed gate (pattern from
# stig_kubernetes_main.rego / rego PR #52 lineage): an empty input must
# report fully non-compliant with an explicit finding, never a pass.

package stig.{pkg}.main

import data.stig.{pkg}
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_finding := {{
\t"rule_title": "FAIL-CLOSED: no facts supplied for stig.{pkg} — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
\t"severity": "CAT I",
\t"status": "Open",
}}

_upstream := {pkg}.compliance_report

_total_controls := _upstream.total_controls

_upstream_open := [f | some f in _upstream.open_findings]

_open_findings := array.concat(_upstream_open, [_no_facts_finding]) if not _facts_supplied

_open_findings := _upstream_open if _facts_supplied

_failed := _total_controls if not _facts_supplied

_failed := count(_upstream_open) if _facts_supplied

_passed := 0 if not _facts_supplied

_passed := max([0, _total_controls - _failed]) if _facts_supplied

default _percentage := 0

_percentage := round((_passed * 100) / _total_controls) if _total_controls > 0

default _compliant := false

_compliant if {{
\t_facts_supplied
\tcount(_open_findings) == 0
}}

compliance_report := object.union(_upstream, {{
\t"compliant": _compliant,
\t"passed_controls": _passed,
\t"failed_controls": _failed,
\t"compliance_percentage": _percentage,
\t"open_findings": _open_findings,
\t"violations": _open_findings,
\t"violation_count": count(_open_findings),
\t"facts_supplied": _facts_supplied,
}})

compliant := _compliant

violations := _open_findings
"""

def write_alias(outdir, key, pkg):
    open(os.path.join(outdir, f"stig_{key}_main.rego"), "w").write(ALIAS_TMPL.format(pkg=pkg))

def main():
    for key, cfg in PLATFORMS.items():
        cat = json.load(open(f"{CATS}/{key}.json"))
        bykey = {r["stig_id"]: r for r in cat["rules"]}
        missing = [sid for sid in cfg["rules"] if sid not in bykey]
        if missing:
            raise SystemExit(f"{key}: rule IDs not in current XCCDF catalog: {missing}")
        bench, release = cat["benchmark"], cat["release"]
        ver = f"V{cat['version']}R{release.split('Release:')[1].split()[0]}" if "Release:" in release else f"V{cat['version']}"
        outdir = os.path.join(REPO, key)
        os.makedirs(os.path.join(outdir, "tests"), exist_ok=True)
        lines = [f"package stig.{cfg['pkg']}.core", "",
                 f"# DISA STIG — {bench}",
                 f"# {ver} | {release}",
                 f"# {len(cfg['rules'])} rules (all CAT I + selected CAT II). Rule IDs, severities and",
                 "# titles verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.",
                 "# Input contract: see gen_linux.py header / tests fixture.",
                 "", "import rego.v1", ""]
        finds, fixture_entries = [], []
        cat1 = 0
        for sid in sorted(cfg["rules"]):
            body, fx = cfg["rules"][sid]
            r = bykey[sid]
            if r["severity"] == "CAT I": cat1 += 1
            ident = rego_ident(sid)
            lines.append(f"# {sid} | {r['vuln_id']} | {r['severity']}")
            lines.append(f"default {ident} := false")
            lines.append(ident + " if {")
            for b in body:
                lines.append("\t" + b)
            lines.append("}")
            lines.append("")
            title = esc(" ".join(r["title"].split())[:220])
            lines += [f"finding_{ident} := {{",
                      f'\t"vuln_id": "{r["vuln_id"]}",',
                      f'\t"stig_id": "{sid}",',
                      f'\t"severity": "{r["severity"]}",',
                      f'\t"rule_title": "{title}",',
                      f'\t"status": status_{ident},',
                      "}",
                      f'status_{ident} := "Not_a_Finding" if {ident}',
                      f'status_{ident} := "Open" if not {ident}', ""]
            finds.append(f"finding_{ident}")
            fixture_entries.append(fx)
        lines.append("findings := [")
        lines += [f"\t{f}," for f in finds]
        lines += ["]", "", "default compliant := false", "",
                  'compliant if count([f | some f in findings; f.status == "Open"]) == 0']
        open(os.path.join(outdir, "core.rego"), "w").write("\n".join(lines) + "\n")

        # orchestrator
        total = len(cat["rules"])
        o = [f"package stig.{cfg['pkg']}", "",
             f"# DISA STIG — {bench} — Master Aggregator",
             f"# {ver} | {release}",
             f"# Coverage: {len(cfg['rules'])} of {total} rules ({cat1} CAT I of "
             f"{sum(1 for r in cat['rules'] if r['severity']=='CAT I')}); remainder is follow-up work.",
             "# Rule IDs verified against the July 2026 SRG-STIG library on 2026-09-03.",
             "", "import rego.v1", "",
             f"import data.stig.{cfg['pkg']}.core", "",
             "all_findings := core.findings", "",
             'open_findings := [f | some f in all_findings; f.status == "Open"]',
             'cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]', "",
             "default overall_compliant := false",
             "overall_compliant if count(cat_i_open) == 0",
             "default fully_compliant := false",
             "fully_compliant if count(open_findings) == 0", "",
             "stig_assessment := {",
             '\t"metadata": {',
             f'\t\t"stig_title": "{esc(bench)}",',
             f'\t\t"version": "{ver}",',
             f'\t\t"release": "{esc(release)}",',
             f'\t\t"platform": "{esc(cfg["platform"])}",',
             '\t\t"assessed_host": object.get(input, ["system_info", "hostname"], "unknown"),',
             "\t},",
             '\t"summary": {',
             '\t\t"total_findings": count(all_findings),',
             '\t\t"open": count(open_findings),',
             '\t\t"not_a_finding": count(all_findings) - count(open_findings),',
             '\t\t"cat_i_open": count(cat_i_open),',
             '\t\t"overall_compliant": overall_compliant,',
             '\t\t"fully_compliant": fully_compliant,',
             "\t},",
             '\t"findings": all_findings,',
             "}", "",
             "# Uniform library entrypoint contract (consumed by the .main alias's",
             "# fail-closed gate): total_controls + open_findings are required.",
             "compliance_report := {",
             '\t"total_controls": count(all_findings),',
             '\t"open_findings": open_findings,',
             '\t"passed_controls": count(all_findings) - count(open_findings),',
             '\t"failed_controls": count(open_findings),',
             '\t"compliant": fully_compliant,',
             "}"]
        open(os.path.join(outdir, f"stig_{key}_complete.rego"), "w").write("\n".join(o) + "\n")

        fixture = build_fixture(fixture_entries)
        fxs = json.dumps(fixture, indent=1).replace("\n", "\n\t")
        t = [f"package stig.{cfg['pkg']}_test", "", "import rego.v1",
             f"import data.stig.{cfg['pkg']}", "",
             "test_report_wellformed_on_empty_input if {",
             f"\treport := {cfg['pkg']}.stig_assessment with input as {{}}",
             "\tis_object(report)",
             "\treport.summary.total_findings > 0",
             "\treport.summary.open == report.summary.total_findings",
             "}", "",
             f"green_fixture := {fxs}", "",
             "test_fully_compliant_on_green_fixture if {",
             f"\treport := {cfg['pkg']}.stig_assessment with input as green_fixture",
             "\treport.summary.fully_compliant == true",
             "\treport.summary.cat_i_open == 0",
             "}"]
        open(os.path.join(outdir, "tests", f"test_stig_{key}.rego"), "w").write("\n".join(t) + "\n")
        write_alias(outdir, key, cfg["pkg"])
        print(f"{key}: {len(cfg['rules'])} rules ({cat1} CAT I) of {total} total")

if __name__ == "__main__":
    main()
