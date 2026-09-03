#!/usr/bin/env python3
"""Kubernetes + OpenShift STIG modules — hand-authored logic, catalog-verified IDs.

Input contract:
  input.api_server.flags[<flag>]          : string value of --<flag>
  input.api_server.admission_plugins      : list (enable-admission-plugins)
  input.kubelet.config.<key>              : kubelet config file values
  input.controller_manager.flags[<flag>]
  input.etcd.flags[<flag>]
  input.scheduler.flags[<flag>]
  input.etcd.encryption_provider_configured : bool
  input.secrets.env_var_usage_count       : number (0 = none)
  input.namespaces.user_resources_in_dedicated : bool (attestation)
  input.pod_security.admission_config_file_set : bool
  OpenShift adds: input.openshift.* / input.rhcos.*
"""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "benchmarks", "stig")
CATS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalogs")

def flag(comp, name, val):
    return ([f'input.{comp}.flags["{name}"] == "{val}"'], ("flags", comp, name, val))
def flag_absent(comp, name):
    return ([f'not input.{comp}.flags["{name}"]'], None)
def kubelet(key, val):
    vv = f'"{val}"' if isinstance(val, str) else str(val).lower() if isinstance(val, bool) else val
    return ([f'input.kubelet.config.{key} == {vv}'], ("kubelet", key, val))
def kubelet_absent(key):
    return ([f'not input.kubelet.config.{key}'], None)
def admission(plugin):
    return ([f'"{plugin}" in input.api_server.admission_plugins'], ("admission", plugin))
def boolfact(path, val=True):
    return ([f'input.{path} == {str(val).lower()}'], ("BOOL", path, val))
def numfact(path, val):
    return ([f'input.{path} == {val}'], ("BOOL", path, val))

PLATFORMS = {
  "kubernetes": {
    "pkg": "kubernetes", "platform": "Kubernetes",
    "rules": {
      # CAT I
      "CNTR-K8-000220": flag("controller_manager", "use-service-account-credentials", "true"),
      "CNTR-K8-000290": boolfact("namespaces.user_resources_in_dedicated"),
      "CNTR-K8-000330": kubelet("readOnlyPort", 0),
      "CNTR-K8-000360": flag("api_server", "anonymous-auth", "false"),
      "CNTR-K8-000370": kubelet("authentication_anonymous_enabled", False),
      "CNTR-K8-000380": kubelet("authorization_mode", "Webhook"),
      "CNTR-K8-000440": kubelet_absent("staticPodPath"),
      "CNTR-K8-001160": numfact("secrets.env_var_usage_count", 0),
      "CNTR-K8-001161": boolfact("secrets.sensitive_data_in_secrets_only"),
      "CNTR-K8-001162": boolfact("etcd.encryption_provider_configured"),
      "CNTR-K8-001620": kubelet("protectKernelDefaults", True),
      "CNTR-K8-002000": admission("ValidatingAdmissionWebhook"),
      "CNTR-K8-002001": admission("PodSecurity"),
      "CNTR-K8-002010": boolfact("pod_security.policy_enforced"),
      "CNTR-K8-002011": boolfact("pod_security.admission_config_file_set"),
      "CNTR-K8-002620": flag_absent("api_server", "basic-auth-file"),
      "CNTR-K8-002630": flag_absent("api_server", "token-auth-file"),
      "CNTR-K8-002640": (['input.api_server.flags["tls-cert-file"] != ""',
                          'input.api_server.flags["tls-private-key-file"] != ""'],
                         ("flags2", {"api_server": {"tls-cert-file": "/etc/kubernetes/pki/apiserver.crt",
                                                    "tls-private-key-file": "/etc/kubernetes/pki/apiserver.key"}})),
      # High-value CAT II (semantics verified against check text)
      "CNTR-K8-000160": (['input.scheduler.flags["tls-min-version"] in {"VersionTLS12", "VersionTLS13"}'],
                         ("flags", "scheduler", "tls-min-version", "VersionTLS12")),
      "CNTR-K8-000170": (['input.api_server.flags["tls-min-version"] in {"VersionTLS12", "VersionTLS13"}'],
                         ("flags", "api_server", "tls-min-version", "VersionTLS12")),
      "CNTR-K8-000850": (['not input.kubelet.flags["hostname-override"]'], None),
      "CNTR-K8-001480": flag("etcd", "peer-client-cert-auth", "true"),
      "CNTR-K8-003110": boolfact("manifests.owned_by_root"),
    },
  },
  "openshift_4": {
    "pkg": "openshift_4", "platform": "Red Hat OpenShift Container Platform 4.x",
    "rules": {
      # CAT I
      "CNTR-OS-000090": boolfact("openshift.rbac_enforced"),
      "CNTR-OS-000170": boolfact("rhcos.audit_at_startup"),
      "CNTR-OS-000400": boolfact("openshift.root_sessions_disabled"),
      "CNTR-OS-000460": boolfact("openshift.identity_provider_fips_validated"),
      "CNTR-OS-000510": boolfact("openshift.fips_mode_enabled"),
      "CNTR-OS-000660": boolfact("openshift.default_scc_least_privilege"),
      "CNTR-OS-001010": boolfact("rhcos.sshd_disabled"),
      # High-value CAT II
      "CNTR-OS-000010": boolfact("openshift.oauth_idle_timeout_configured"),
      "CNTR-OS-000030": boolfact("openshift.cluster_logging_forwarding_configured"),
      "CNTR-OS-000320": boolfact("openshift.api_server_audit_profile_set"),
      "CNTR-OS-000560": boolfact("openshift.etcd_encryption_enabled"),
      "CNTR-OS-000720": boolfact("rhcos.chrony_configured"),
      "CNTR-OS-000860": boolfact("openshift.image_source_policy_configured"),
      "CNTR-OS-000930": boolfact("openshift.network_policy_default_deny"),
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
        k = e[0]
        if k == "flags":
            fx.setdefault(e[1], {}).setdefault("flags", {})[e[2]] = e[3]
        elif k == "flags2":
            for comp, flags in e[1].items():
                fx.setdefault(comp, {}).setdefault("flags", {}).update(flags)
        elif k == "kubelet":
            fx.setdefault("kubelet", {}).setdefault("config", {})[e[1]] = e[2]
        elif k == "admission":
            fx.setdefault("api_server", {}).setdefault("admission_plugins", [])
            if e[1] not in fx["api_server"]["admission_plugins"]:
                fx["api_server"]["admission_plugins"].append(e[1])
        elif k == "BOOL":
            set_deep(fx, e[1], e[2])
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
        by = {r["stig_id"]: r for r in cat["rules"]}
        missing = [sid for sid in cfg["rules"] if sid not in by]
        if missing:
            raise SystemExit(f"{key}: rule IDs not in current XCCDF: {missing}")
        bench, release = cat["benchmark"], cat["release"]
        ver = f"V{cat['version']}R{release.split('Release:')[1].split()[0]}" if "Release:" in release else f"V{cat['version']}"
        outdir = os.path.join(REPO, key)
        os.makedirs(os.path.join(outdir, "tests"), exist_ok=True)
        cat1 = sum(1 for sid in cfg["rules"] if by[sid]["severity"] == "CAT I")
        lines = [f"package stig.{cfg['pkg']}.core", "",
                 f"# DISA STIG — {bench}",
                 f"# {ver} | {release}",
                 f"# {len(cfg['rules'])} rules (all CAT I + selected CAT II); IDs/severities/titles",
                 "# verified against the July 2026 SRG-STIG library XCCDF on 2026-09-03.",
                 "# Input contract: see gen_k8s.py header / tests fixture.",
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
        total_cat1 = sum(1 for r in cat["rules"] if r["severity"] == "CAT I")
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
             "}"]
        open(os.path.join(outdir, "tests", f"test_stig_{key}.rego"), "w").write("\n".join(t) + "\n")
        print(f"{key}: {len(cfg['rules'])} rules ({cat1}/{total_cat1} CAT I) of {total}")

if __name__ == "__main__":
    main()
