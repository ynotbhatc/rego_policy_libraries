#!/usr/bin/env python3
"""Final STIG platform batch: Crunchy Postgres 16, MS SQL 2016 Instance,
Apache 2.4 (Unix, Server), Cisco IOS-XE Router (NDM), vSphere 8 ESXi.

Hand-authored logic, catalog-gated IDs, same emission shape as gen_k8s.
Input contracts documented per module header; DBMS/network rules that are
inherently organizational are modeled as explicit attestation booleans —
named for what a human verified, never silently passed.
"""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_k8s import ALIAS_TMPL

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "benchmarks", "stig")
CATS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalogs")

def boolfact(path, val=True):
    return ([f'input.{path} == {str(val).lower()}'], ("BOOL", path, val))
def strfact(path, val):
    return ([f'input.{path} == "{val}"'], ("BOOL", path, val))
def pg(setting, val):
    vv = f'"{val}"' if isinstance(val, str) else val
    return ([f'input.pg_settings["{setting}"] == {vv}'], ("MAP", "pg_settings", setting, val))
def esxi(setting, val):
    vv = f'"{val}"' if isinstance(val, str) else val
    return ([f'input.esxi.advanced_settings["{setting}"] == {vv}'], ("MAP2", "esxi.advanced_settings", setting, val))

PLATFORMS = {
  "postgresql_16": {
    "pkg": "postgresql_16", "platform": "Crunchy Data Postgres 16",
    "contract": [
      "input.pg_settings[<name>]          : SHOW <name> value",
      "input.pg.*                         : attestation booleans (documented reviews)",
    ],
    "rules": {
      "CD16-00-000200": boolfact("pg.org_level_auth_integrated"),
      "CD16-00-000300": boolfact("pg.authorizations_enforced"),
      "CD16-00-002700": boolfact("pg.install_account_restricted"),
      "CD16-00-003800": pg("password_encryption", "scram-sha-256"),
      "CD16-00-003900": pg("ssl", "on"),
      "CD16-00-004100": boolfact("pg.pki_keys_access_enforced"),
      "CD16-00-004400": boolfact("pg.fips_modules_in_use"),
      "CD16-00-005200": boolfact("pg.data_at_rest_protected"),
      "CD16-00-008300": boolfact("pg.nsa_crypto_for_classified"),
      "CD16-00-008500": boolfact("pg.crypto_integrity_mechanisms"),
      "CD16-00-009300": boolfact("pg.vendor_supported_version"),
      # CAT II audit rules (pgaudit-driven; attestation over audit config review)
      "CD16-00-011800": boolfact("pg.audit_successful_object_access"),
      "CD16-00-011900": boolfact("pg.audit_unsuccessful_object_access"),
    },
  },
  "ms_sql_2016": {
    "pkg": "ms_sql_2016", "platform": "MS SQL Server 2016 Instance",
    "contract": [
      "input.sql.*                        : instance facts + attestation booleans",
    ],
    "rules": {
      "SQL6-D0-003700": boolfact("sql.org_level_auth_integrated"),
      "SQL6-D0-003900": boolfact("sql.authorizations_enforced"),
      "SQL6-D0-006700": boolfact("sql.install_account_restricted"),
      "SQL6-D0-007900": boolfact("sql.password_standards_enforced"),
      "SQL6-D0-008200": boolfact("sql.encrypted_password_transmission"),
      "SQL6-D0-008300": boolfact("sql.tls_for_transmission"),
      "SQL6-D0-008400": boolfact("sql.pki_keys_access_enforced"),
      "SQL6-D0-008700": boolfact("sql.fips_modules_in_use"),
      "SQL6-D0-009500": boolfact("sql.data_at_rest_protected"),
      "SQL6-D0-016200": boolfact("sql.sa_account_disabled"),
      "SQL6-D0-018100": boolfact("sql.sqlcmd_no_cleartext_credentials"),
      "SQL6-D0-018200": boolfact("sql.auth_feedback_obscured"),
      "SQL6-D0-018300": boolfact("sql.vendor_supported_version"),
    },
  },
  "apache_2_4_unix": {
    "pkg": "apache_2_4_unix", "platform": "Apache Server 2.4 (Unix)",
    "contract": [
      "input.apache.*                     : parsed httpd facts + attestations",
    ],
    "rules": {
      "AS24-U1-000270": boolfact("apache.documentation_excluded"),
      "AS24-U1-000440": boolfact("apache.app_dirs_admin_only"),
      "AS24-U1-000520": boolfact("apache.session_id_full_charset"),
      "AS24-U1-000940": boolfact("apache.service_account_no_login_shell"),
      "AS24-U1-000960": boolfact("apache.vendor_supported_version"),
      # CAT II (semantics matched to verified rule titles)
      "AS24-U1-000030": boolfact("apache.remote_session_crypto_enabled"),
      "AS24-U1-000180": boolfact("apache.log_files_privileged_only"),
      "AS24-U1-000230": boolfact("apache.modules_reviewed_and_signed"),
      "AS24-U1-000310": boolfact("apache.unused_script_mappings_removed"),
      "AS24-U1-000650": boolfact("apache.session_inactive_timeout_set"),
    },
  },
  "cisco_ios_xe_router": {
    "pkg": "cisco_ios_xe_router", "platform": "Cisco IOS-XE Router (NDM)",
    "contract": [
      "input.cisco.*                      : config-derived facts + attestations",
    ],
    "rules": {
      "CISC-ND-000470": boolfact("cisco.nonsecure_services_disabled"),
      "CISC-ND-000620": boolfact("cisco.passwords_stored_hashed"),
      "CISC-ND-000720": boolfact("cisco.session_timeout_configured"),
      "CISC-ND-001200": boolfact("cisco.ssh_fips_hmac_configured"),
      "CISC-ND-001210": boolfact("cisco.ssh_fips_ciphers_configured"),
      "CISC-ND-001370": boolfact("cisco.two_authentication_servers"),
      "CISC-ND-001450": boolfact("cisco.two_syslog_servers"),
      "CISC-ND-001470": boolfact("cisco.supported_ios_release"),
      # CAT II (semantics matched to verified rule titles)
      "CISC-ND-000550": boolfact("cisco.min_15_char_password_enforced"),
      "CISC-ND-001410": boolfact("cisco.config_backup_on_change"),
    },
  },
  "vmware_vsphere_8": {
    "pkg": "vmware_vsphere_8", "platform": "VMware vSphere 8.0 ESXi",
    "contract": [
      "input.esxi.advanced_settings[<key>] : Get-AdvancedSetting values",
      "input.esxi.*                        : host facts + attestations",
    ],
    "rules": {
      "ESXI-80-000014": boolfact("esxi.ssh_fips_140_2_enabled"),
      "ESXI-80-000133": boolfact("esxi.vib_acceptance_partner_or_stricter"),
      "ESXI-80-000217": boolfact("esxi.vswitch_mac_changes_rejected"),
      "ESXI-80-000221": boolfact("esxi.patches_current"),
      # CAT II (semantics matched to verified rule titles)
      "ESXI-80-000008": boolfact("esxi.lockdown_mode_enabled"),
      "ESXI-80-000035": boolfact("esxi.password_quality_policy_configured"),
      "ESXI-80-000068": boolfact("esxi.shell_idle_timeout_15min"),
      "ESXI-80-000113": boolfact("esxi.audit_storage_one_week_allocated"),
      "ESXI-80-000124": boolfact("esxi.ntp_authoritative_source_configured"),
      "ESXI-80-000160": boolfact("esxi.mgmt_traffic_isolated_or_encrypted"),
    },
  },
}

def rego_ident(sid): return "r_" + re.sub(r"[^a-z0-9]+", "_", sid.lower()).strip("_")
def esc(s): return s.replace("\\", "\\\\").replace('"', '\\"')
def set_deep(fx, dotted, val):
    d = fx; parts = dotted.split(".")
    for p in parts[:-1]: d = d.setdefault(p, {})
    d[parts[-1]] = val

def build_fixture(entries):
    fx = {}
    for e in entries:
        if not e: continue
        if e[0] == "BOOL":
            set_deep(fx, e[1], e[2])
        elif e[0] == "MAP":
            fx.setdefault(e[1], {})[e[2]] = e[3]
        elif e[0] == "MAP2":
            base, sub = e[1].split(".")
            fx.setdefault(base, {}).setdefault(sub, {})[e[2]] = e[3]
    return fx

def main():
    for key, cfg in PLATFORMS.items():
        cat = json.load(open(f"{CATS}/{key}.json"))
        by = {r["stig_id"]: r for r in cat["rules"]}
        missing = [sid for sid in cfg["rules"] if sid not in by]
        if missing:
            raise SystemExit(f"{key}: rule IDs not in current XCCDF: {missing}")
        bench, release = cat["benchmark"], cat["release"]
        ver = f"V{cat['version']}R{release.split('Release:')[1].split()[0]}" if "Release:" in release else f"V{cat['version']}"
        outdir = os.path.join(REPO, key)
        os.makedirs(os.path.join(outdir, "tests"), exist_ok=True)
        cat1 = sum(1 for sid in cfg["rules"] if by[sid]["severity"] == "CAT I")
        total_cat1 = sum(1 for r in cat["rules"] if r["severity"] == "CAT I")
        hdr_contract = "".join(f"#   {c}\n" for c in cfg["contract"])
        lines = [f"package stig.{cfg['pkg']}.core", "",
                 f"# DISA STIG — {bench}",
                 f"# {ver} | {release}",
                 f"# {len(cfg['rules'])} rules (all CAT I + selected CAT II); IDs/severities/titles",
                 "# verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.",
                 "# Organizational rules are explicit attestation booleans — named for what",
                 "# a human verified, never silently passed. Input contract:",
                 hdr_contract.rstrip(),
                 "", "import rego.v1", ""]
        finds, fixture_entries = [], []
        for sid in sorted(cfg["rules"]):
            body, fx = cfg["rules"][sid]
            r = by[sid]
            ident = rego_ident(sid)
            lines.append(f"# {sid} | {r['vuln_id']} | {r['severity']}")
            lines.append(f"default {ident} := false")
            lines.append(ident + " if {")
            for b in body: lines.append("\t" + b)
            lines.append("}")
            lines.append("")
            title = esc(" ".join(r["title"].split())[:220])
            lines += [f"finding_{ident} := {{",
                      f'\t"vuln_id": "{r["vuln_id"]}",',
                      f'\t"stig_id": "{sid}",',
                      f'\t"severity": "{r["severity"]}",',
                      f'\t"rule_title": "{title}",',
                      f'\t"status": status_{ident},', "}",
                      f'status_{ident} := "Not_a_Finding" if {ident}',
                      f'status_{ident} := "Open" if not {ident}', ""]
            finds.append(f"finding_{ident}")
            fixture_entries.append(fx)
        lines.append("findings := [")
        lines += [f"\t{f}," for f in finds]
        lines += ["]", "", "default compliant := false", "",
                  'compliant if count([f | some f in findings; f.status == "Open"]) == 0']
        open(os.path.join(outdir, "core.rego"), "w").write("\n".join(lines) + "\n")

        total = len(cat["rules"])
        o = [f"package stig.{cfg['pkg']}", "",
             f"# DISA STIG — {bench} — Master Aggregator",
             f"# {ver} | {release}",
             f"# Coverage: {len(cfg['rules'])} of {total} rules ({cat1} of {total_cat1} CAT I).",
             "# Rule IDs verified against the July 2026 SRG-STIG library on 2026-09-03.",
             "", "import rego.v1", "", f"import data.stig.{cfg['pkg']}.core", "",
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
             "# Uniform library entrypoint contract.",
             "compliance_report := {",
             '\t"total_controls": count(all_findings),',
             '\t"open_findings": open_findings,',
             '\t"passed_controls": count(all_findings) - count(open_findings),',
             '\t"failed_controls": count(open_findings),',
             '\t"compliant": fully_compliant,',
             "}"]
        open(os.path.join(outdir, f"stig_{key}_complete.rego"), "w").write("\n".join(o) + "\n")

        fx = build_fixture(fixture_entries)
        fxs = json.dumps(fx, indent=1).replace("\n", "\n\t")
        t = [f"package stig.{cfg['pkg']}_test", "", "import rego.v1",
             f"import data.stig.{cfg['pkg']}", "",
             "test_report_wellformed_on_empty_input if {",
             f"\treport := {cfg['pkg']}.stig_assessment with input as {{}}",
             "\tis_object(report)", "\treport.summary.total_findings > 0",
             "}", "",
             f"green_fixture := {fxs}", "",
             "test_fully_compliant_on_green_fixture if {",
             f"\treport := {cfg['pkg']}.stig_assessment with input as green_fixture",
             "\treport.summary.fully_compliant == true",
             "}", "",
             "test_main_alias_fail_closed_on_empty if {",
             f"\trep := data.stig.{cfg['pkg']}.main.compliance_report with input as {{}}",
             "\trep.compliant == false",
             "\trep.facts_supplied == false",
             "}"]
        open(os.path.join(outdir, "tests", f"test_stig_{key}.rego"), "w").write("\n".join(t) + "\n")
        open(os.path.join(outdir, f"stig_{key}_main.rego"), "w").write(ALIAS_TMPL.format(pkg=cfg["pkg"]))
        print(f"{key}: {len(cfg['rules'])} rules ({cat1}/{total_cat1} CAT I) of {total}")

if __name__ == "__main__":
    main()
