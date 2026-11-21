#!/usr/bin/env python3
"""DISA STIG for Red Hat OpenShift Container Platform 4.x: benchmarks/stig/openshift_4/core.rego and its per-rule tests.

    python3 tools/stig_generators/gen_openshift_stig.py      # needs catalogs/openshift_4.json (parse_xccdf.py) and opa

The module's 14 rules, each written 2026-11-18 against its V2R7 check text with the gen_rhel9.py machinery (fail-closed
evidence, generated pass / fail / evidence-missing tests). Facts follow the CIS OpenShift contract where the check reads
the same thing (`openshift.image_config`, `scc.items[]`, `oauth.identity_providers`); node facts are per node under
`rhcos.nodes[]` (every node must pass; an empty list is not collected):
  rhcos.nodes[] {name, audit_rules[] (uncommented /etc/audit/audit.rules lines), boot_entries_options[] (the options
  lines of /boot/loader/entries/*.conf), dmesg_nx (dmesg | grep Execute), cpu_flags[], fips_enabled (sysctl
  crypto.fips_enabled), sshd_config {PermitRootLogin, ClientAliveCountMax, ClientAliveInterval}, sshd_enabled,
  sshd_active (systemctl is-enabled / is-active sshd.service)}
A check that is an organizational review the facts cannot decide is an attestation (input.attest.<key>) whose absence
is Not_Reviewed, never a permanent Open.
"""
import json, os, re, subprocess, shutil, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_rhel9 as G  # noqa: E402
from linux_stig_table import Table  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "benchmarks", "stig", "openshift_4")
cat = json.load(open(os.path.join(HERE, "catalogs", "openshift_4.json")))
BY = {r["stig_id"]: r for r in cat["rules"]}
T = Table(sources=())


def norm_rule(l):
    l = re.sub(r"\s+", " ", l.strip()).replace(" -F key=", " -k ")
    return l.replace("auid!=-1", "auid!=unset").replace("auid!=4294967295", "auid!=unset")


EXECPRIV = [l.strip() for l in BY["CNTR-OS-000720"]["check"].splitlines() if l.strip().startswith("-a always")]
AUDIT930 = [l.strip() for l in BY["CNTR-OS-000930"]["check"].splitlines() if l.strip().startswith("-a always")]
assert len(EXECPRIV) == 4 and len(AUDIT930) == 70, (len(EXECPRIV), len(AUDIT930))
SCC_ALLOWED = ["system:cluster-admins", "system:nodes", "system:masters", "system:admin",
               "system:serviceaccount:openshift-infra:build-controller",
               "system:serviceaccount:openshift-infra:pv-recycler-controller",
               "system:serviceaccount:openshift-machine-api:machine-api-termination-handler"]

HELPERS = r'''
# rhcos.nodes[]: per-node facts; every node must pass, an empty list is not collected
_nodes := ns if {
	ns := input.rhcos.nodes
	is_array(ns)
	count(ns) > 0
}

# kernel arguments of a node: the tokens of its /boot/loader/entries/*.conf options lines
_kargs(n) := {t | some l in n.boot_entries_options; is_string(l); s := trim_space(l); parts := split(s, " "); some t in parts; t != ""}

# an audit rule line compared token for token (`-F key=x` is `-k x`; auid!=-1 / 4294967295 are auid!=unset)
_rule_norm(l) := concat(" ", [t | some t in parts; t != ""]) if {
	is_string(l)
	a := replace(trim_space(l), " -F key=", " -k ")
	b := replace(a, "auid!=-1", "auid!=unset")
	x := replace(b, "auid!=4294967295", "auid!=unset")
	parts := split(x, " ")
}

_node_rules(n) := {r | some l in n.audit_rules; r := _rule_norm(l)}

# the expected audit rules of CNTR-OS-000720 / CNTR-OS-000930, normalised as above (from the check text)
execpriv_rules := ''' + json.dumps(sorted({norm_rule(l) for l in EXECPRIV})).replace('", "', '",\n\t"').replace("[", "{\n\t", 1)[:-1] + "\n}" + r'''

unsuccessful_access_rules := ''' + json.dumps(sorted({norm_rule(l) for l in AUDIT930})).replace('", "', '",\n\t"').replace("[", "{\n\t", 1)[:-1] + "\n}" + r'''

# SCC subjects the CNTR-OS-000660 check permits on a host-access / privileged / non-MustRunAsRange SCC
scc_permitted_subjects := ''' + "{" + ", ".join(json.dumps(x) for x in SCC_ALLOWED) + "}" + r'''

_scc_privileged(s) if s.allowHostIPC == true

_scc_privileged(s) if s.allowHostPID == true

_scc_privileged(s) if s.allowHostPorts == true

_scc_privileged(s) if s.allowHostNetwork == true

_scc_privileged(s) if s.allowHostDirVolumePlugin == true

_scc_privileged(s) if s.allowPrivilegedContainer == true

_scc_privileged(s) if object.get(s, ["runAsUser", "type"], "") != "MustRunAsRange"

_scc_subjects(s) := {x | some k in ["users", "groups"]; xs := object.get(s, k, []); some x in xs}

_scc_offender(s) if {
	_scc_privileged(s)
	some x in _scc_subjects(s)
	not x in scc_permitted_subjects
}

# system:authenticated belongs only on the restricted profile
_scc_offender(s) if {
	not s.metadata.name in {"restricted", "restricted-v2"}
	groups := object.get(s, "groups", [])
	"system:authenticated" in groups
}

# OpenShift Virtualization on a cluster older than 4.18 (input.openshift.cluster_version "4.17.3")
_pre_418 if {
	v := _str(["openshift", "cluster_version"])
	m := regex.find_all_string_submatch_n(`^4\.([0-9]+)(\.|$)`, v, 1)
	minor := to_number(m[0][1])
	minor < 18
}'''


def node(**kv):
    n = {"name": "worker-0", "audit_rules": EXECPRIV + AUDIT930 + ["--loginuid-immutable"],
         "boot_entries_options": ["options root=UUID=1 rw audit=1 audit_backlog_limit=8192 page_poison=1 fips=1"],
         "dmesg_nx": "[    0.000000] NX (Execute Disable) protection: active", "cpu_flags": ["fpu", "nx", "lm"],
         "fips_enabled": "1", "sshd_config": {"PermitRootLogin": "no", "ClientAliveCountMax": "0", "ClientAliveInterval": "600"},
         "sshd_enabled": "disabled", "sshd_active": "inactive"}
    n.update(kv)
    return {"rhcos": {"nodes": [n, dict(n, name="master-0")]}}


def nodes_rule(sid, name, conds, bad_nodes, expect, fix, comment, extra_ev=(), extra_alt=(), green_extra=None, **kw):
    alt = ["ns := _nodes", "every n in ns {\n" + "\n".join("\t" + c for c in conds) + "\n}"] + list(extra_alt)
    green = node()
    if green_extra:
        green.update(green_extra)
    T.R("core", sid, name, [("rhcos", "nodes")] + list(extra_ev), [alt], green,
        [{"rhcos": {"nodes": [node()["rhcos"]["nodes"][0], dict(node()["rhcos"]["nodes"][1], **b)]}} for b in bad_nodes]
        + [{"rhcos": {"nodes": []}}] + list(kw.pop("bad_extra", [])),
        expect, fix, comment=comment, **kw)


# ── cluster configuration ─────────────────────────────────────────────────────────────────────────────────────
T.R("core", "CNTR-OS-000010", "registries_secure", [("openshift", "image_config")],
    [["ic := input.openshift.image_config", 'allowed := object.get(ic, ["spec", "allowedRegistriesForImport"], [])', "is_array(allowed)",
      "count([r | some r in allowed; r.insecure == true]) == 0",
      'insecure := object.get(ic, ["spec", "registrySources", "insecureRegistries"], [])', "is_array(insecure)", "count(insecure) == 0"]],
    {"openshift": {"image_config": {"spec": {"allowedRegistriesForImport": [{"domainName": "registry.redhat.io", "insecure": False}]}}}},
    [{"openshift": {"image_config": {"spec": {"allowedRegistriesForImport": [{"domainName": "r.example", "insecure": True}]}}}},
     {"openshift": {"image_config": {"spec": {"registrySources": {"insecureRegistries": ["r.example:5000"]}}}}}],
    "image.config.openshift.io/cluster must list no allowedRegistriesForImport entry with insecure: true and no registrySources.insecureRegistries",
    "Remove insecure registries from image.config.openshift.io/cluster",
    comment="input.openshift.image_config: image.config.openshift.io/cluster (the CIS OpenShift fact)")

for sid, name in [("CNTR-OS-000030", "central_user_management"), ("CNTR-OS-000460", "idp_ldap_or_oidc")]:
    T.R("core", sid, name, [("oauth", "identity_providers")],
        [["ps := input.oauth.identity_providers", "is_array(ps)", "count(ps) > 0", 'every p in ps {\n\tp.type in {"LDAP", "OpenID"}\n}']],
        {"oauth": {"identity_providers": [{"name": "corp-ldap", "type": "LDAP"}, {"name": "sso", "type": "OpenID"}]}},
        [{"oauth": {"identity_providers": [{"name": "corp-ldap", "type": "LDAP"}, {"name": "local", "type": "HTPasswd"}]}},
         {"oauth": {"identity_providers": []}}],
        "oauth cluster identityProviders must be of type LDAP or OpenID only (at least one configured)",
        "Configure an LDAP or OpenID identity provider and remove other provider types from oauth/cluster",
        comment="input.oauth.identity_providers [{name, type}] from oauth cluster .spec.identityProviders "
                "(an empty list fails: no centralized provider is configured)")

T.R("core", "CNTR-OS-000660", "scc_least_privilege", [("scc", "items")],
    [["items := input.scc.items", "is_array(items)", "count(items) > 0", "count([s | some s in items; _scc_offender(s)]) == 0",
      '_attested("cntr_os_000660_role_review")']],
    {"scc": {"items": [{"metadata": {"name": "restricted-v2"}, "allowPrivilegedContainer": False, "runAsUser": {"type": "MustRunAsRange"},
                        "groups": ["system:authenticated"], "users": []},
                       {"metadata": {"name": "privileged"}, "allowPrivilegedContainer": True, "runAsUser": {"type": "RunAsAny"},
                        "groups": ["system:cluster-admins", "system:nodes", "system:masters"], "users": ["system:admin"]}]},
     "attest": {"cntr_os_000660_role_review": True}},
    [{"scc": {"items": [{"metadata": {"name": "privileged"}, "allowPrivilegedContainer": True, "groups": ["devs"], "users": []}]}},
     {"scc": {"items": [{"metadata": {"name": "anyuid"}, "runAsUser": {"type": "MustRunAsRange"}, "groups": ["system:authenticated"]}]}},
     {"attest": {"cntr_os_000660_role_review": False}}],
    "every SCC that allows host access, privileged containers or a runAsUser other than MustRunAsRange may name only the "
    "check's permitted users and groups, system:authenticated only on restricted; and the review of roles granting "
    "'use' of nonpermitted SCCs (check step 2) must be attested (input.attest.cntr_os_000660_role_review)",
    "Remove non-permitted users and groups from privileged SCCs and roles granting their use",
    comment="input.scc.items (oc get scc -ojson, the CIS OpenShift fact); step 2 (roles that allow 'use' of SCCs) is an attested review")

T.R("core", "CNTR-OS-000090", "rbac_reviewed", [], [],
    {}, [], "the review of cluster roles, role bindings and the OpenShift Virtualization permissions the check lists must "
    "be attested (input.attest.cntr_os_000090_rbac_review): whether a user needs privileged access is an organizational judgement",
    "Review cluster roles and bindings and remove privileged access that is not required",
    comment="manual review: 'users with privileged access that do not require that access' cannot be decided from facts",
    attest_alts=[['_attested("cntr_os_000090_rbac_review")']])
T.RULES["CNTR-OS-000090"]["manual"] = True
T.RULES["CNTR-OS-000090"]["green"] = {"attest": {"cntr_os_000090_rbac_review": True}}

# ── per node ──────────────────────────────────────────────────────────────────────────────────────────────────
nodes_rule("CNTR-OS-000170", "audit_at_startup", ['"audit=1" in _kargs(n)', '"audit_backlog_limit=8192" in _kargs(n)'],
           [{"boot_entries_options": ["options rw audit=1"]}, {"boot_entries_options": ["options rw audit=0 audit_backlog_limit=8192"]}],
           "every node's boot loader entries must carry audit=1 and audit_backlog_limit=8192",
           "Add the kernel arguments with a MachineConfig (kernelArguments: audit=1, audit_backlog_limit=8192)",
           "kernel arguments from /boot/loader/entries/*.conf on every node (the check's 'audit_backlog' is the audit_backlog_limit argument)")
nodes_rule("CNTR-OS-000320", "loginuid_immutable", ['some l in n.audit_rules\n\ttrim_space(l) == "--loginuid-immutable"'],
           [{"audit_rules": EXECPRIV}, {"audit_rules": ["# --loginuid-immutable"]}],
           "every node's /etc/audit/audit.rules must carry --loginuid-immutable",
           "Add --loginuid-immutable to the audit rules with a MachineConfig", "uncommented /etc/audit/audit.rules lines per node")
nodes_rule("CNTR-OS-000400", "root_ssh_disabled_and_timeouts",
           ['_lower_eq(n.sshd_config.PermitRootLogin, "no")', '_lower_eq(n.sshd_config.ClientAliveCountMax, "0")',
            "is_string(n.sshd_config.ClientAliveInterval)", "regex.match(`^[0-9]+$`, trim_space(n.sshd_config.ClientAliveInterval))",
            "to_number(trim_space(n.sshd_config.ClientAliveInterval)) <= 600"],
           [{"sshd_config": {"PermitRootLogin": "yes", "ClientAliveCountMax": "0", "ClientAliveInterval": "600"}},
            {"sshd_config": {"PermitRootLogin": "no", "ClientAliveCountMax": "1", "ClientAliveInterval": "600"}},
            {"sshd_config": {"PermitRootLogin": "no", "ClientAliveCountMax": "0", "ClientAliveInterval": "900"}}],
           "on every node /etc/ssh/sshd_config must set PermitRootLogin no, ClientAliveCountMax 0 and ClientAliveInterval 600 or less; "
           "with OpenShift Virtualization before 4.18 the hyperconverged featureGates.nonRoot must be true",
           "Set the sshd options with a MachineConfig; enable the nonRoot feature gate",
           "per-node sshd_config values; input.openshift.virtualization_enabled, cluster_version, hyperconverged",
           extra_ev=[("openshift", "virtualization_enabled")],
           extra_alt=["_virt_nonroot_ok"], green_extra={"openshift": {"virtualization_enabled": False}},
           bad_extra=[{"openshift": {"virtualization_enabled": True, "cluster_version": "4.17.2",
                                     "hyperconverged": {"spec": {"featureGates": {"nonRoot": False}}}}}],
           pass_cases=[{"openshift": {"virtualization_enabled": True, "cluster_version": "4.18.1"}}])
nodes_rule("CNTR-OS-000510", "fips_enabled_nodes", ['_s(n.fips_enabled) == "1"'], [{"fips_enabled": "0"}],
           "sysctl crypto.fips_enabled must be 1 on every node", "Install the cluster with fips: true",
           "sysctl crypto.fips_enabled per node")
nodes_rule("CNTR-OS-000560", "shared_resources_protected", ['"page_poison=1" in _kargs(n)'],
           [{"boot_entries_options": ["options rw audit=1"]}],
           "every node's boot entries must carry page_poison=1; with OpenShift Virtualization the hyperconverged ksmConfiguration "
           "must not be set to anything but false, no VM disk may be shareable, and persistentReservation must be false unless "
           "Windows SCF is in use (input.attest.cntr_os_000560_windows_scf)",
           "Add page_poison=1 with a MachineConfig; disable KSM, shareable disks and persistentReservation",
           "kernel arguments per node; input.openshift.virtualization_enabled, hyperconverged, cnv_shareable_disk_vms",
           extra_ev=[("openshift", "virtualization_enabled")], extra_alt=["_virt_sharing_ok"],
           green_extra={"openshift": {"virtualization_enabled": False}},
           bad_extra=[{"openshift": {"virtualization_enabled": True, "hyperconverged": {"spec": {"ksmConfiguration": {"nodeLabelSelector": {}}}},
                                     "cnv_shareable_disk_vms": []}},
                      {"openshift": {"virtualization_enabled": True, "hyperconverged": {"spec": {}}, "cnv_shareable_disk_vms": ["ns/vm1"]}}],
           pass_cases=[{"openshift": {"virtualization_enabled": True, "hyperconverged": {"spec": {"featureGates": {"persistentReservation": False}}},
                                      "cnv_shareable_disk_vms": []}}])
nodes_rule("CNTR-OS-000720", "execpriv_audited", ["every r in execpriv_rules {\n\t\tr in _node_rules(n)\n\t}"],
           [{"audit_rules": EXECPRIV[:3]}], "every node must carry the four execve execpriv audit rules the check lists",
           "Add the execpriv rules to /etc/audit/rules.d with a MachineConfig", "uncommented /etc/audit/audit.rules lines per node")
nodes_rule("CNTR-OS-000860", "nx_protection", ['_nx(n)'], [{"dmesg_nx": "", "cpu_flags": ["fpu", "lm"]}],
           "every node's dmesg must show 'NX (Execute Disable) protection: active', or its /proc/cpuinfo flags must contain nx",
           "Enable NX in the firmware", "dmesg | grep Execute and /proc/cpuinfo flags per node",
           pass_cases=[{"rhcos": {"nodes": [dict(node()["rhcos"]["nodes"][0], dmesg_nx="")]}}])
nodes_rule("CNTR-OS-000930", "access_attempts_audited", ["every r in unsuccessful_access_rules {\n\t\tr in _node_rules(n)\n\t}"],
           [{"audit_rules": EXECPRIV + AUDIT930[:-1]}], "every node must carry all 70 audit rules the check lists",
           "Add the rules to /etc/audit/rules.d with a MachineConfig", "uncommented /etc/audit/audit.rules lines per node")
nodes_rule("CNTR-OS-001010", "sshd_disabled", ['_s(n.sshd_enabled) != "enabled"', '_s(n.sshd_active) != "active"', "is_string(n.sshd_enabled)",
                                                "is_string(n.sshd_active)"],
           [{"sshd_enabled": "enabled"}, {"sshd_active": "active"}],
           "sshd.service must be neither enabled nor active on any node", "systemctl disable --now sshd.service with a MachineConfig",
           "systemctl is-enabled / is-active sshd.service per node")

HELPERS += r'''

_s(v) := lower(trim_space(v)) if is_string(v)

_lower_eq(v, want) if _s(v) == want

_nx(n) if contains(n.dmesg_nx, "NX (Execute Disable) protection: active")

_nx(n) if "nx" in n.cpu_flags

default _virt_nonroot_ok := false

_virt_nonroot_ok if input.openshift.virtualization_enabled == false

_virt_nonroot_ok if {
	input.openshift.virtualization_enabled == true
	not _pre_418
	_collected(["openshift", "cluster_version"])
}

_virt_nonroot_ok if {
	input.openshift.virtualization_enabled == true
	_pre_418
	input.openshift.hyperconverged.spec.featureGates.nonRoot == true
}

default _virt_sharing_ok := false

_virt_sharing_ok if input.openshift.virtualization_enabled == false

_virt_sharing_ok if {
	input.openshift.virtualization_enabled == true
	hc := input.openshift.hyperconverged
	object.get(hc, ["spec", "ksmConfiguration"], false) == false
	vms := input.openshift.cnv_shareable_disk_vms
	is_array(vms)
	count(vms) == 0
	_persistent_reservation_ok(hc)
}

_persistent_reservation_ok(hc) if object.get(hc, ["spec", "featureGates", "persistentReservation"], false) == false

_persistent_reservation_ok(_) if _attested("cntr_os_000560_windows_scf")'''


def main():
    RULES, _ = T.finish()
    path = os.path.join(OUT, "core.rego")
    text = open(path).read()
    k = "package stig.openshift_4.core\n"
    header = text[:text.index(k) + len(k)]   # METADATA (incl. the make coverage block) and the package line
    sev = {}
    blocks = []
    for sid, spec in RULES.items():
        s, fname, b = G.block(sid, BY[sid], spec)
        sev.setdefault(s, []).append(fname)
        blocks.append(b)
    out = [header.rstrip("\n"), "",
           f"# {cat['benchmark']} {cat['version']} ({cat['release_date']})",
           f"# Generated by tools/stig_generators/gen_openshift_stig.py ({G.VERIFIED}): {len(RULES)} of {len(cat['rules'])} rules, each",
           "# written against its check text; ids, severities and titles from the catalog (regenerate, don't hand-edit).", "",
           "import rego.v1", "", G.HELPERS, HELPERS, ""] + blocks
    out += ["findings := [\n" + "".join(f"\t{n},\n" for k in ("CAT I", "CAT II", "CAT III") for n in sev.get(k, [])) + "]", "",
            "default compliant := false", "",
            'compliant if count([f | some f in findings; f.status in {"Open", "Not_Reviewed"}]) == 0', ""]
    open(path, "w").write("\n".join(out))
    green = {}
    tests = []
    for sid, spec in RULES.items():
        G.deep_merge(green, spec["green"], sid)
    for sid, spec in RULES.items():
        tests += G.tests_for("openshift_4", "core", sid, spec, "green_fixture")
    tpath = os.path.join(OUT, "tests", "test_core_rules.rego")
    t = ["package stig.openshift_4.core_rules_test", "", "import rego.v1", "",
         "# Generated by tools/stig_generators/gen_openshift_stig.py: per rule a pass, a fail per mutation and an evidence-missing test.", "",
         f"green_fixture := {json.dumps(green, indent=chr(9), sort_keys=True)}", "",
         "test_every_finding_unresolved_on_empty_input if {",
         "\tfs := data.stig.openshift_4.core.findings with input as {}",
         '\tcount([f | some f in fs; not f.status in {"Open", "Not_Reviewed"}]) == 0', "}", "",
         "test_compliant_on_green_fixture if {", "\tdata.stig.openshift_4.core.compliant with input as green_fixture", "}", "",
         "test_rbac_review_not_reviewed_without_attestation if {",
         '\tdata.stig.openshift_4.core.status_cntr_os_000090 == "Not_Reviewed" with input as json.remove(green_fixture, ["attest/cntr_os_000090_rbac_review"])', "}", ""]
    open(tpath, "w").write("\n".join(t + tests).rstrip() + "\n")
    subprocess.run([shutil.which("opa"), "fmt", "-w", path, tpath], check=True)
    print(f"openshift_4: {len(RULES)} of {len(cat['rules'])} {cat['version']} rules")


if __name__ == "__main__":
    main()
