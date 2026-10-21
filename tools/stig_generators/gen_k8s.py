#!/usr/bin/env python3
"""Kubernetes, RKE2 and OpenShift STIG modules — hand-authored logic, catalog-verified IDs.

    python3 tools/stig_generators/gen_k8s.py kubernetes rke2     # the platforms to regenerate
                                                                  # (default: kubernetes rke2)

`kubernetes` (Kubernetes STIG V2R6) and `rke2` (RGS RKE2 STIG V2R7) cover EVERY rule in their catalog and
carry a TWO-WAY gate like gen_oracle_db.py: generation aborts if a catalog rule has no logic entry or a logic
entry has no catalog rule. The `openshift_4` module (CAT I + selected CAT II) was produced by an earlier
version of this script and is now hand-maintained; its logic table is in git history (before 2026-10-21).

FAIL-CLOSED everywhere: every rule lists the evidence it needs; if any is absent the finding is Open with
detail "<STIG-ID>: evidence missing — <field> not collected". Absence checks ("flag X must not be set")
require the collection itself to exist (is_object(...)) — never `not input.x.flags["y"]` on its own.
Rules whose DISA check is a documentation review or human judgment read `input.attest.<key> == true`
(Open "not attested" otherwise). Every finding carries `check_type` (machine / attestation /
machine+attestation) and `detail`.

Kubernetes input contract (one evaluation per control-plane node; kubelet facts are that node's):
  input.api_server.flags[<flag>]           : string value of --<flag> from the kube-apiserver manifest
  input.api_server.admission_plugins       : list (--enable-admission-plugins, split)
  input.api_server.audit_policy            : parsed --audit-policy-file {apiVersion, kind, rules[{level, ...}]}
  input.api_server.encryption_config       : parsed --encryption-provider-config
                                             {resources: [{resources: ["secrets"], providers: ["aescbc", "identity"]}]}
                                             (providers = provider names in file order)
  input.controller_manager.flags / input.scheduler.flags / input.etcd.flags : manifest flags
  input.kubelet.flags[<flag>]              : kubelet command-line args (ps -ef / systemd ExecStart), {} if none
  input.kubelet.config                     : the KubeletConfiguration file (--config) as parsed YAML
                                             (authentication.anonymous.enabled, authorization.mode,
                                             authentication.x509.clientCAFile, readOnlyPort, staticPodPath,
                                             featureGates, streamingConnectionIdleTimeout, tlsCertFile,
                                             tlsPrivateKeyFile, protectKernelDefaults). Legacy flattened keys
                                             authentication_anonymous_enabled / authorization_mode still accepted.
  input.cluster.version                    : server version ("v1.30.2")
  input.cluster.namespace_resources[<ns>]  : `kubectl get all` names for default / kube-public / kube-node-lease
  input.cluster.dashboard_pods             : pods matching k8s-app=kubernetes-dashboard (list)
  input.cluster.images                     : every container image ref running in the cluster (list)
  input.kubectl.client_versions            : kubectl client version on the control plane and each node (list)
  input.worker_nodes                       : [{name, sshd_active, sshd_enabled}]
  input.workloads.user_pod_host_ports      : host ports used by pods in user namespaces (list of numbers)
  input.secrets.env_var_usage_count        : number of secretKeyRef env vars in workloads (0 = none)
  input.pod_security.policies              : PodSecurityPolicies (only read for clusters older than 1.25)
  input.kube_proxy.running                 : bool
  input.files.<group>                      : [{path, mode ("0644"), owner, group}] for groups manifests,
                                             kubelet_config_file, kubelet_client_ca, kube_proxy_kubeconfig,
                                             etcd_data, control_plane_confs, pki, kubelet_kubeconfig,
                                             kubeadm_conf, kubelet_config_yaml
  input.attest.<key>                       : organizational attestations (see each rule)

RKE2 input contract (one evaluation per RKE2 server node):
  input.rke2.config                        : /etc/rancher/rke2/config.yaml as parsed YAML
  input.rke2.args.kube_apiserver / kube_controller_manager / kube_scheduler / kubelet
                                           : the component args RKE2 renders (ps -ef), flag -> value
  input.rke2.audit_policy                  : parsed audit policy file {rules[{level, resources[{group, resources}]}]}
  input.rke2.pss_defaults                  : `defaults` of the pod-security-admission-config-file
  input.rke2.files.<group>                 : [{name, mode, owner, group}] for groups etc (/etc/rancher/rke2),
                                             root (/var/lib/rancher/rke2), agent, bin, data, server
  input.cluster.namespace_resources / input.cluster.images : as for Kubernetes
  input.attest.<key>                       : organizational attestations
"""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(HERE, "..", "..", "benchmarks", "stig")
CATS = os.path.join(HERE, "catalogs")
SEV = {"high": "CAT I", "medium": "CAT II", "low": "CAT III",
       "CAT I": "CAT I", "CAT II": "CAT II", "CAT III": "CAT III"}

# ALIAS_TMPL is imported by gen_apps.py, gen_linux.py and gen_oracle_db.py — keep it.

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


# ── rule specs ─────────────────────────────────────────────────────────────────────────────────
# A spec is a dict:
#   alts   : list of alternative bodies (OR); each a list of Rego lines (AND)
#   ev     : evidence paths (tuples) that must be present, else "evidence missing"
#   green  : fixture patch that makes the rule pass (deep-merged into the shared green fixture)
#   bad    : patch that, object.union-ed onto the green fixture, makes the rule fail (evidence still present)
#   expect : what the check requires (goes into the Open finding's detail)
#   kind   : machine | attestation | machine+attestation
def R(alts, ev, green, bad, expect, kind="machine"):
    return {"alts": alts, "ev": [tuple(e) for e in ev], "green": green, "bad": bad, "expect": expect, "kind": kind}


def nest(dotted, val):
    d = val
    for p in reversed(dotted.split(".")):
        d = {p: d}
    return d


def ref(obj, key):                      # input.<obj>["key"]
    return f'input.{obj}["{key}"]'


def flag_eq(obj, name, val, bad=None):
    if bad is None:
        bad = {"true": "false", "false": "true"}.get(val, "__wrong__")
    return R([[f'{ref(obj, name)} == "{val}"']], [obj.split(".")], nest(obj, {name: val}),
             nest(obj, {name: bad}), f'{obj} --{name} must be "{val}"')


def flag_in(obj, name, vals, green, bad):
    s = ", ".join(f'"{v}"' for v in vals)
    return R([[f"{ref(obj, name)} in {{{s}}}"]], [obj.split(".")], nest(obj, {name: green}),
             nest(obj, {name: bad}), f"{obj} --{name} must be one of {', '.join(vals)}")


def flag_set(obj, name, green):
    return R([[f"_nonempty({ref(obj, name)})"]], [obj.split(".")], nest(obj, {name: green}),
             nest(obj, {name: ""}), f"{obj} --{name} must be set to a non-empty value")


def flag_path(obj, name, green):       # set to an absolute path
    return R([[f"_nonempty({ref(obj, name)})", f'startswith({ref(obj, name)}, "/")']], [obj.split(".")],
             nest(obj, {name: green}), nest(obj, {name: "-"}), f"{obj} --{name} must be set to a valid path")


def flag_set_not(obj, name, forbidden, green):
    return R([[f"_nonempty({ref(obj, name)})", f'{ref(obj, name)} != "{forbidden}"']], [obj.split(".")],
             nest(obj, {name: green}), nest(obj, {name: forbidden}),
             f'{obj} --{name} must be set and not "{forbidden}"')


def flag_absent(obj, name):
    return R([[f"is_object(input.{obj})", f'object.get(input.{obj}, "{name}", null) == null']],
             [obj.split(".")], nest(obj, {}), nest(obj, {name: "/set/by/test"}),
             f"{obj} --{name} must not be set")


def flag_num_ge(obj, name, n, green):
    return R([[f"_nonempty({ref(obj, name)})", f"to_number({ref(obj, name)}) >= {n}"]], [obj.split(".")],
             nest(obj, {name: str(green)}), nest(obj, {name: str(n - 1)}),
             f"{obj} --{name} must be set to at least {n}")


def flag_duration_ge(obj, name, dur, green, bad):
    return R([[f"_nonempty({ref(obj, name)})", f'_duration_ge({ref(obj, name)}, "{dur}")']], [obj.split(".")],
             nest(obj, {name: green}), nest(obj, {name: bad}), f"{obj} --{name} must be set to at least {dur}")


def flag_has_all(obj, name, items, bad):
    s = ", ".join(f'"{v}"' for v in items)
    return R([[f"_nonempty({ref(obj, name)})", f"_list_has_all({ref(obj, name)}, [{s}])"]], [obj.split(".")],
             nest(obj, {name: ",".join(items)}), nest(obj, {name: bad}),
             f"{obj} --{name} must include {', '.join(items)}")


def gate_not(obj, gate, val):          # feature gate <gate> must not be set to <val> in --feature-gates
    return R([[f"is_object(input.{obj})", f'_gate_count(input.{obj}, "{gate}", "{val}") == 0']], [obj.split(".")],
             nest(obj, {}), nest(obj, {"feature-gates": f"{gate}={val}"}),
             f"{obj} --feature-gates must not set {gate}={val}")


def kcfg(path, val, default=None, bad=None):
    p = json.dumps(path.split("."))
    v = json.dumps(val)
    d = "null" if default is None else json.dumps(default)
    if bad is None:
        bad = (not val) if isinstance(val, bool) else "__wrong__"
    return R([["is_object(input.kubelet.config)", f"object.get(input.kubelet.config, {p}, {d}) == {v}"]],
             [("kubelet", "config")], nest("kubelet.config." + path, val), nest("kubelet.config." + path, bad),
             f"kubelet config {path} must be {v}" + ("" if default is None else " (or unset)"))


def kcfg_set(path, green):
    p = json.dumps(path.split("."))
    return R([[f'_nonempty(object.get(input.kubelet.config, {p}, ""))']], [("kubelet", "config")],
             nest("kubelet.config." + path, green), nest("kubelet.config." + path, ""),
             f"kubelet config {path} must be set to a non-empty value")


def kcfg_absent(path):
    p = json.dumps(path.split("."))
    return R([["is_object(input.kubelet.config)", f"object.get(input.kubelet.config, {p}, null) == null"]],
             [("kubelet", "config")], {"kubelet": {"config": {}}}, nest("kubelet.config." + path, "/etc/kubernetes/manifests"),
             f"kubelet config {path} must not be set")


def kcfg_duration_ge(path, dur, green, bad):
    p = json.dumps(path.split("."))
    return R([[f'_nonempty(object.get(input.kubelet.config, {p}, ""))',
               f'_duration_ge(object.get(input.kubelet.config, {p}, ""), "{dur}")']], [("kubelet", "config")],
             nest("kubelet.config." + path, green), nest("kubelet.config." + path, bad),
             f"kubelet config {path} must be at least {dur}")


def kgate_not(gate, val):              # kubelet config featureGates.<gate> must not be <val>
    return R([["is_object(input.kubelet.config)",
               f'object.get(input.kubelet.config, ["featureGates", "{gate}"], null) != {json.dumps(val)}']],
             [("kubelet", "config")], {"kubelet": {"config": {}}}, {"kubelet": {"config": {"featureGates": {gate: val}}}},
             f"kubelet config featureGates.{gate} must not be {json.dumps(val)}")


FILE_ROOT = {"path": "/etc/kubernetes/x", "mode": "0600", "owner": "root", "group": "root"}


def files_owned(key, owner, group, sample, base="files", name_key="path"):
    ent = [{name_key: sample, "mode": "0600", "owner": owner, "group": group}]
    return R([[f'_files_owned(input.{base}["{key}"], "{owner}", "{group}")']], [(*base.split("."), key)],
             nest(base, {key: ent}), nest(base, {key: [{name_key: sample, "mode": "0600", "owner": "nobody", "group": group}]}),
             f"every {key} file must be owned by {owner}:{group}")


def files_mode(key, mx, sample, owner="root", group="root", base="files", name_key="path"):
    ent = [{name_key: sample, "mode": "0600", "owner": owner, "group": group}]
    return R([[f'_files_mode_le(input.{base}["{key}"], "{mx}")']], [(*base.split("."), key)],
             nest(base, {key: ent}), nest(base, {key: [{name_key: sample, "mode": "0666", "owner": owner, "group": group}]}),
             f"every {key} file must have mode {mx} or more restrictive")


def files_suffix_mode(key, suffix, mx, sample):
    ent = [{"path": sample, "mode": "0600", "owner": "root", "group": "root"}]
    return R([[f'_files_suffix_mode_le(input.files["{key}"], "{suffix}", "{mx}")']], [("files", key)],
             {"files": {key: ent}}, {"files": {key: [{"path": sample, "mode": "0666", "owner": "root", "group": "root"}]}},
             f"every {suffix} file under {key} must have mode {mx} or more restrictive")


def attest(key, what):
    return R([[f"input.attest.{key} == true"]], [], {"attest": {key: True}}, {"attest": {key: False}},
             f"input.attest.{key} must be true ({what})", "attestation")


def fact(lines, ev, green, bad, expect):
    return R([lines], ev, green, bad, expect)


def deep_merge(a, b, where=""):
    """Merge b into a; raise if two rules write different leaf values to the same key."""
    for k, v in b.items():
        if k in a and isinstance(a[k], dict) and isinstance(v, dict):
            deep_merge(a[k], v, f"{where}.{k}")
        elif k in a and isinstance(a[k], list) and isinstance(v, list) and all(isinstance(x, dict) for x in a[k] + v):
            a[k] += [json.loads(json.dumps(x)) for x in v if x not in a[k]]   # file / node entry lists accumulate
        elif k in a and a[k] != v:
            raise SystemExit(f"green fixture conflict at {where}.{k}: {a[k]!r} vs {v!r}")
        else:
            a[k] = json.loads(json.dumps(v))
    return a


def allof(*specs, expect=None):
    alts = [[]]
    for s in specs:
        alts = [a + b for a in alts for b in s["alts"]]
    ev = []
    for s in specs:
        ev += [e for e in s["ev"] if e not in ev]
    green = {}
    for s in specs:
        deep_merge(green, s["green"])
    kinds = {s["kind"] for s in specs}
    kind = "machine+attestation" if len(kinds) > 1 or "machine+attestation" in kinds else kinds.pop()
    return {"alts": alts, "ev": ev, "green": green, "bad": specs[0]["bad"],
            "expect": expect or "; ".join(s["expect"] for s in specs), "kind": kind}


def anyof(*specs, bad, expect):
    """OR of specs; `bad` must defeat every alternative."""
    ev = []
    for e in specs[0]["ev"]:
        ev.append(e)
    green = json.loads(json.dumps(specs[0]["green"]))
    return {"alts": [a for s in specs for a in s["alts"]], "ev": ev, "green": green, "bad": bad,
            "expect": expect, "kind": specs[0]["kind"]}


# Rego helpers emitted once per module (no `with`, no `some k, v in` inside comprehensions).
HELPERS = r'''
# ── shared helpers ─────────────────────────────────────────────────────────────────────────────
# evidence present: the value exists at the path (an explicit null counts as not collected)
_collected(path) if object.get(input, path, null) != null

_nonempty(s) if {
	is_string(s)
	trim_space(s) != ""
}

# --feature-gates "A=true,B=false": how many entries set <name> to <val> (0 when the flag is unset)
_gate_count(flags, name, val) := count([1 |
	some kv in split(object.get(flags, "feature-gates", ""), ",")
	p := split(trim_space(kv), "=")
	count(p) == 2
	trim_space(p[0]) == name
	lower(trim_space(p[1])) == val
])

_list_has_all(csv, items) if {
	have := {trim_space(x) | some x in split(csv, ",")}
	every i in items {
		i in have
	}
}

_duration_ge(v, minimum) if time.parse_duration_ns(v) >= time.parse_duration_ns(minimum)

# Octal mode "0644"/"644" is at most <mx> (3 digits) when every permission bit it sets is allowed by mx,
# digit by digit (a numeric comparison is wrong: 0460 < 0644 but grants group write), and any
# special-bit digit (setuid/setgid/sticky) is 0.
_allowed_bits := {
	"0": {"0"},
	"4": {"0", "4"},
	"5": {"0", "1", "4", "5"},
	"6": {"0", "2", "4", "6"},
	"7": {"0", "1", "2", "3", "4", "5", "6", "7"},
}

_mode_le(mode, mx) if {
	m := sprintf("%v", [mode])
	n := count(m)
	n >= 3
	# per-character split (split(m, "") does not terminate on OPA 1.10)
	d := [substring(m, i, 1) | some i in numbers.range(0, n - 1)]
	every i, c in d {
		_digit_ok(i, n, c, mx)
	}
}

_digit_ok(i, n, c, _) if {
	i < n - 3
	c == "0"
}

_digit_ok(i, n, c, mx) if {
	i >= n - 3
	c in _allowed_bits[substring(mx, i - (n - 3), 1)]
}

# file lists: present, non-empty (an empty list proves nothing), every entry satisfies the test
_files_owned(fs, owner, group) if {
	is_array(fs)
	count(fs) > 0
	every f in fs {
		f.owner == owner
		f.group == group
	}
}

_files_mode_le(fs, mx) if {
	is_array(fs)
	count(fs) > 0
	every f in fs {
		_mode_le(f.mode, mx)
	}
}

_files_suffix_mode_le(fs, suffix, mx) if {
	is_array(fs)
	sel := [f | some f in fs; endswith(f.path, suffix)]
	count(sel) > 0
	every f in sel {
		_mode_le(f.mode, mx)
	}
}

# entries named in <names> (when present) must be at most <mx>
_named_mode_le(fs, names, mx) if {
	is_array(fs)
	count(fs) > 0
	every f in fs {
		_named_ok(f, names, mx)
	}
}

_named_ok(f, names, _) if not f.name in names

_named_ok(f, names, mx) if {
	f.name in names
	_mode_le(f.mode, mx)
}

# version "v1.30.2" -> numbers
_ver_part(v, i) := to_number(regex.find_n(`^[0-9]+`, split(trim_prefix(v, "v"), ".")[i], 1)[0])

_k8s_minor := _ver_part(input.cluster.version, 1) if _ver_part(input.cluster.version, 0) == 1

_ver_at_least(v, a, _, _) if _ver_part(v, 0) > a

_ver_at_least(v, a, b, _) if {
	_ver_part(v, 0) == a
	_ver_part(v, 1) > b
}

_ver_at_least(v, a, b, c) if {
	_ver_part(v, 0) == a
	_ver_part(v, 1) == b
	_ver_part(v, 2) >= c
}

# kubernetes namespaces that may hold only the kubernetes service
_only_kubernetes_service(nsr) if {
	is_array(nsr["default"])
	is_array(nsr["kube-public"])
	every ns in ["default", "kube-public", "kube-node-lease"] {
		every r in object.get(nsr, ns, []) {
			r == "service/kubernetes"
		}
	}
}

# image repository without tag/digest ("reg:5000/a/b:1.2@sha256:..." -> "reg:5000/a/b")
_image_repo(img) := r if {
	parts := split(split(img, "@")[0], "/")
	last := parts[count(parts) - 1]
	r := concat("/", array.concat(array.slice(parts, 0, count(parts) - 1), [split(last, ":")[0]]))
}

_single_version_per_image(imgs) if {
	is_array(imgs)
	count(imgs) > 0
	refs := {split(i, "@")[0] | some i in imgs}
	every repo in {_image_repo(i) | some i in refs} {
		count({i | some i in refs; _image_repo(i) == repo}) == 1
	}
}
'''


# ── Kubernetes STIG V2R6 — all 92 rules ─────────────────────────────────────────────────────────
AS, CM, SC, ET, KL = "api_server.flags", "controller_manager.flags", "scheduler.flags", "etcd.flags", "kubelet.flags"
TLS = ["VersionTLS12", "VersionTLS13"]
K8_CIPHERS = ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
              "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]
GREEN_VERSION = {"cluster": {"version": "v1.30.2"}}


def k8_ppsm(component):
    return attest(f"{component}_pps_ppsm_cal_compliant",
                  f"{component} ports, protocols and services reviewed against the PPSM CAL and system documentation")


def files_pair(key, sample, mode="644"):
    return files_owned(key, "root", "root", sample), files_mode(key, mode, sample)


MANIFESTS_OWN, MANIFESTS_MODE = files_pair("manifests", "/etc/kubernetes/manifests/kube-apiserver.yaml")
KCF_OWN, KCF_MODE = files_pair("kubelet_config_file", "/var/lib/kubelet/config.yaml")
CONFS_OWN, CONFS_MODE = files_pair("control_plane_confs", "/etc/kubernetes/admin.conf")
KKC_OWN, KKC_MODE = files_pair("kubelet_kubeconfig", "/etc/kubernetes/kubelet.conf")
KADM_OWN, KADM_MODE = files_pair("kubeadm_conf", "/etc/systemd/system/kubelet.service.d/10-kubeadm.conf")
KCY_OWN, KCY_MODE = files_pair("kubelet_config_yaml", "/var/lib/kubelet/config.yaml")
KCA_OWN, KCA_MODE = files_pair("kubelet_client_ca", "/etc/kubernetes/pki/ca.crt")


def kube_proxy(spec):
    """Applies only if kube-proxy runs: explicit running == false passes; otherwise the file test."""
    off = R([["input.kube_proxy.running == false"]], [], {}, {}, "")
    on = allof(R([["input.kube_proxy.running == true"]], [], {"kube_proxy": {"running": True}}, {}, ""), spec)
    s = anyof(on, off, bad=spec["bad"], expect="if kube-proxy runs: " + spec["expect"])
    s["ev"] = [("kube_proxy", "running")]
    return s


KP_OWN, KP_MODE = files_pair("kube_proxy_kubeconfig", "/var/lib/kube-proxy/kubeconfig.conf")

AUDIT_POLICY_RR = {"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "rules": [{"level": "RequestResponse"}]}

K8_RULES = {
    "CNTR-K8-000150": flag_in(CM, "tls-min-version", TLS, "VersionTLS12", "VersionTLS11"),
    "CNTR-K8-000160": flag_in(SC, "tls-min-version", TLS, "VersionTLS12", "VersionTLS11"),
    "CNTR-K8-000170": flag_in(AS, "tls-min-version", TLS, "VersionTLS12", "VersionTLS11"),
    "CNTR-K8-000180": flag_eq(ET, "auto-tls", "false"),
    "CNTR-K8-000190": flag_eq(ET, "peer-auto-tls", "false"),
    "CNTR-K8-000220": flag_eq(CM, "use-service-account-credentials", "true"),
    "CNTR-K8-000270": fact([f'_nonempty({ref(AS, "authorization-mode")})',
                            f'_list_has_all({ref(AS, "authorization-mode")}, ["Node", "RBAC"])',
                            f'not "AlwaysAllow" in split({ref(AS, "authorization-mode")}, ",")'],
                           [("api_server", "flags")], {"api_server": {"flags": {"authorization-mode": "Node,RBAC"}}},
                           {"api_server": {"flags": {"authorization-mode": "AlwaysAllow"}}},
                           "api_server --authorization-mode must include Node and RBAC and not AlwaysAllow"),
    "CNTR-K8-000290": fact(["_only_kubernetes_service(input.cluster.namespace_resources)"],
                           [("cluster", "namespace_resources")],
                           {"cluster": {"namespace_resources": {"default": ["service/kubernetes"], "kube-public": [], "kube-node-lease": []}}},
                           {"cluster": {"namespace_resources": {"default": ["service/kubernetes", "deployment.apps/web"]}}},
                           "default, kube-public and kube-node-lease must hold nothing but service/kubernetes"),
    "CNTR-K8-000300": flag_eq(SC, "bind-address", "127.0.0.1", "0.0.0.0"),
    "CNTR-K8-000310": flag_eq(CM, "bind-address", "127.0.0.1", "0.0.0.0"),
    "CNTR-K8-000330": allof(flag_absent(KL, "read-only-port"), kcfg("readOnlyPort", 0, default=0, bad=10255)),
    "CNTR-K8-000350": flag_set_not(AS, "secure-port", "0", "6443"),
    "CNTR-K8-000360": flag_eq(AS, "anonymous-auth", "false"),
    "CNTR-K8-000370": allof(flag_absent(KL, "anonymous-auth"),
                            anyof(kcfg("authentication.anonymous.enabled", False),
                                  kcfg("authentication_anonymous_enabled", False),
                                  bad={"kubelet": {"config": {"authentication": {"anonymous": {"enabled": True}}}}},
                                  expect="kubelet config authentication.anonymous.enabled must be false")),
    "CNTR-K8-000380": anyof(allof(flag_absent(KL, "authorization-mode"), kcfg("authorization.mode", "Webhook")),
                            flag_eq(KL, "authorization-mode", "Webhook"),
                            allof(flag_absent(KL, "authorization-mode"), kcfg("authorization_mode", "Webhook")),
                            bad={"kubelet": {"config": {"authorization": {"mode": "AlwaysAllow"}}}},
                            expect="kubelet authorization mode must be Webhook"),
    "CNTR-K8-000400": fact(["is_array(input.worker_nodes)", "count(input.worker_nodes) > 0",
                            "every n in input.worker_nodes {\n\t\tn.sshd_active == false\n\t}"],
                           [("worker_nodes",)], {"worker_nodes": [{"name": "worker-1", "sshd_active": False, "sshd_enabled": False}]},
                           {"worker_nodes": [{"name": "worker-1", "sshd_active": True, "sshd_enabled": False}]},
                           "sshd must not be running on any worker node"),
    "CNTR-K8-000410": fact(["is_array(input.worker_nodes)", "count(input.worker_nodes) > 0",
                            "every n in input.worker_nodes {\n\t\tn.sshd_enabled == false\n\t}"],
                           [("worker_nodes",)], {"worker_nodes": [{"name": "worker-1", "sshd_active": False, "sshd_enabled": False}]},
                           {"worker_nodes": [{"name": "worker-1", "sshd_active": False, "sshd_enabled": True}]},
                           "sshd must not be enabled on any worker node"),
    "CNTR-K8-000420": fact(["is_array(input.cluster.dashboard_pods)", "count(input.cluster.dashboard_pods) == 0"],
                           [("cluster", "dashboard_pods")], {"cluster": {"dashboard_pods": []}},
                           {"cluster": {"dashboard_pods": ["kubernetes-dashboard/kubernetes-dashboard-7b5d"]}},
                           "no pods labelled k8s-app=kubernetes-dashboard may run"),
    "CNTR-K8-000430": fact(["is_array(input.kubectl.client_versions)", "count(input.kubectl.client_versions) > 0",
                            "every v in input.kubectl.client_versions {\n\t\t_ver_at_least(v, 1, 12, 9)\n\t}"],
                           [("kubectl", "client_versions")], {"kubectl": {"client_versions": ["v1.30.2"]}},
                           {"kubectl": {"client_versions": ["v1.30.2", "v1.12.8"]}},
                           "kubectl must be 1.12.9 or newer on the control plane and every node"),
    "CNTR-K8-000440": allof(kcfg_absent("staticPodPath"), flag_absent(KL, "pod-manifest-path")),
    "CNTR-K8-000450": allof(gate_not(AS, "DynamicAuditing", "true"), flag_absent(KL, "feature-gates"),
                            kgate_not("DynamicAuditing", True)),
    # applicable only to Kubernetes 1.25 and older: newer clusters pass on the version fact alone
    "CNTR-K8-000460": anyof(R([["_k8s_minor > 25"]], [("cluster", "version")], GREEN_VERSION, {}, ""),
                            R([["_k8s_minor <= 25",
                                "every c in [input.api_server.flags, input.controller_manager.flags, input.scheduler.flags] {\n\t\t_gate_count(c, \"DynamicKubeletConfig\", \"false\") > 0\n\t}",
                                'object.get(input.kubelet.config, ["featureGates", "DynamicKubeletConfig"], null) == false',
                                'object.get(input.kubelet.flags, "feature-gates", null) == null']], [], {}, {}, ""),
                            bad={"cluster": {"version": "v1.25.4"}},
                            expect="Kubernetes 1.25 and older: DynamicKubeletConfig=false in every manifest and the kubelet config"),
    "CNTR-K8-000470": gate_not(AS, "AllAlpha", "true"),
    "CNTR-K8-000610": flag_set(AS, "audit-log-path", "/var/log/kubernetes/audit/audit.log"),
    "CNTR-K8-000700": allof(flag_set(AS, "audit-policy-file", "/etc/kubernetes/audit-policy.yaml"),
                            fact(['startswith(input.api_server.audit_policy.apiVersion, "audit.k8s.io/")',
                                  'input.api_server.audit_policy.kind == "Policy"',
                                  "count(input.api_server.audit_policy.rules) > 0",
                                  'every r in input.api_server.audit_policy.rules {\n\t\tr.level == "RequestResponse"\n\t}'],
                                 [("api_server", "audit_policy")], {"api_server": {"audit_policy": AUDIT_POLICY_RR}},
                                 {"api_server": {"audit_policy": {"rules": [{"level": "Metadata"}]}}},
                                 "audit policy must log all requests at RequestResponse"),
                            expect="--audit-policy-file set; policy logs all requests at RequestResponse"),
    "CNTR-K8-000850": flag_absent(KL, "hostname-override"),
    "CNTR-K8-000860": MANIFESTS_OWN,
    "CNTR-K8-000880": KCF_OWN,
    "CNTR-K8-000890": KCF_MODE,
    "CNTR-K8-000900": MANIFESTS_MODE,
    "CNTR-K8-000910": flag_eq(CM, "profiling", "false"),
    "CNTR-K8-000920": k8_ppsm("api_server"),
    "CNTR-K8-000930": k8_ppsm("scheduler"),
    "CNTR-K8-000940": k8_ppsm("controller_manager"),
    "CNTR-K8-000950": k8_ppsm("etcd"),
    "CNTR-K8-000960": fact(["is_array(input.workloads.user_pod_host_ports)",
                            "every p in input.workloads.user_pod_host_ports {\n\t\tto_number(p) >= 1024\n\t}"],
                           [("workloads", "user_pod_host_ports")], {"workloads": {"user_pod_host_ports": [30080]}},
                           {"workloads": {"user_pod_host_ports": [30080, 443]}},
                           "pods in user namespaces must not use privileged (<1024) host ports"),
    "CNTR-K8-001160": fact(["input.secrets.env_var_usage_count == 0"], [("secrets", "env_var_usage_count")],
                           {"secrets": {"env_var_usage_count": 0}}, {"secrets": {"env_var_usage_count": 2}},
                           "no workload may load a Secret into an environment variable"),
    "CNTR-K8-001161": attest("sensitive_data_only_in_secrets",
                             "manual review of all resources and ConfigMaps found no sensitive information outside Secrets or an external store"),
    "CNTR-K8-001162": allof(flag_set(AS, "encryption-provider-config", "/etc/kubernetes/enc/encryption-config.yaml"),
                            fact(["some r in input.api_server.encryption_config.resources",
                                  '"secrets" in r.resources', 'r.providers[0] != "identity"'],
                                 [("api_server", "encryption_config")],
                                 {"api_server": {"encryption_config": {"resources": [{"resources": ["secrets"], "providers": ["aescbc", "identity"]}]}}},
                                 {"api_server": {"encryption_config": {"resources": [{"resources": ["secrets"], "providers": ["identity", "aescbc"]}]}}},
                                 "the encryption config must cover secrets with a non-identity first provider"),
                            expect="--encryption-provider-config set; secrets covered; identity not the first provider"),
    "CNTR-K8-001163": attest("secret_access_need_to_know",
                             "read access to Secrets and Secrets attached to workloads are limited to documented requirements"),
    "CNTR-K8-001300": allof(flag_absent(KL, "streaming-connection-idle-timeout"),
                            kcfg_duration_ge("streamingConnectionIdleTimeout", "5m", "5m0s", "1m0s")),
    "CNTR-K8-001360": attest("no_user_pods_in_system_namespaces",
                             "review found no user pods in kube-system, kube-public or kube-node-lease"),
    "CNTR-K8-001400": flag_has_all(AS, "tls-cipher-suites", K8_CIPHERS, "TLS_RSA_WITH_AES_128_CBC_SHA"),
    "CNTR-K8-001410": flag_set(AS, "client-ca-file", "/etc/kubernetes/pki/ca.crt"),
    "CNTR-K8-001420": allof(flag_absent(KL, "client-ca-file"),
                            kcfg_set("authentication.x509.clientCAFile", "/etc/kubernetes/pki/ca.crt")),
    "CNTR-K8-001430": flag_set(CM, "root-ca-file", "/etc/kubernetes/pki/ca.crt"),
    "CNTR-K8-001440": allof(flag_set(AS, "tls-cert-file", "/etc/kubernetes/pki/apiserver.crt"),
                            flag_set(AS, "tls-private-key-file", "/etc/kubernetes/pki/apiserver.key")),
    "CNTR-K8-001450": flag_eq(ET, "client-cert-auth", "true"),
    "CNTR-K8-001460": allof(flag_absent(KL, "tls-private-key-file"), kcfg_set("tlsPrivateKeyFile", "/var/lib/kubelet/pki/kubelet.key")),
    "CNTR-K8-001470": allof(flag_absent(KL, "tls-cert-file"), kcfg_set("tlsCertFile", "/var/lib/kubelet/pki/kubelet.crt")),
    "CNTR-K8-001480": flag_eq(ET, "peer-client-cert-auth", "true"),
    "CNTR-K8-001490": flag_set(ET, "key-file", "/etc/kubernetes/pki/etcd/server.key"),
    "CNTR-K8-001500": flag_set(ET, "cert-file", "/etc/kubernetes/pki/etcd/server.crt"),
    "CNTR-K8-001510": flag_set(AS, "etcd-cafile", "/etc/kubernetes/pki/etcd/ca.crt"),
    "CNTR-K8-001520": flag_set(AS, "etcd-certfile", "/etc/kubernetes/pki/apiserver-etcd-client.crt"),
    "CNTR-K8-001530": flag_set(AS, "etcd-keyfile", "/etc/kubernetes/pki/apiserver-etcd-client.key"),
    "CNTR-K8-001540": flag_set(ET, "peer-cert-file", "/etc/kubernetes/pki/etcd/peer.crt"),
    "CNTR-K8-001550": flag_set(ET, "peer-key-file", "/etc/kubernetes/pki/etcd/peer.key"),
    "CNTR-K8-001620": allof(flag_absent(KL, "protect-kernel-defaults"), kcfg("protectKernelDefaults", True)),
    # The check text is a pre-1.25 check; the plugin is on by default since 1.21, so 1.25+ passes unless disabled.
    "CNTR-K8-002000": anyof(R([['"ValidatingAdmissionWebhook" in input.api_server.admission_plugins']], [("api_server", "flags")],
                              {"api_server": {"admission_plugins": ["NodeRestriction", "ValidatingAdmissionWebhook", "PodSecurity"]}}, {}, ""),
                            R([["_k8s_minor >= 25",
                                f'not "ValidatingAdmissionWebhook" in split(object.get(input.{AS}, "disable-admission-plugins", ""), ",")']],
                              [], {}, {}, ""),
                            bad={"api_server": {"admission_plugins": ["NodeRestriction"],
                                                "flags": {"disable-admission-plugins": "ValidatingAdmissionWebhook"}}},
                            expect="ValidatingAdmissionWebhook must be enabled (in --enable-admission-plugins, or 1.25+ and not disabled)"),
    # PodSecurity feature gate: GA in 1.25 and removed in 1.28, so an absent gate is not a finding; =false is.
    "CNTR-K8-002001": allof(gate_not(AS, "PodSecurity", "false"), gate_not(CM, "PodSecurity", "false"),
                            gate_not(SC, "PodSecurity", "false"), flag_absent(KL, "feature-gates"),
                            kgate_not("PodSecurity", False)),
    "CNTR-K8-002010": anyof(R([["_k8s_minor >= 25"]], [("cluster", "version")], GREEN_VERSION, {}, ""),
                            R([["_k8s_minor < 25", "count(input.pod_security.policies) > 0",
                                "every p in input.pod_security.policies {\n\t\tp.runAsUser.rule == \"MustRunAsNonRoot\"\n\t\tcount(p.supplementalGroups.ranges) > 0\n\t\tevery g in p.supplementalGroups.ranges {\n\t\t\tg.min > 0\n\t\t}\n\t\tcount(p.fsGroup.ranges) > 0\n\t\tevery g in p.fsGroup.ranges {\n\t\t\tg.min > 0\n\t\t}\n\t}"]],
                              [], {}, {}, ""),
                            bad={"cluster": {"version": "v1.24.9"}},
                            expect="Kubernetes before 1.25: a PodSecurityPolicy with MustRunAsNonRoot and non-zero group ranges"),
    "CNTR-K8-002011": allof(flag_set(AS, "admission-control-config-file", "/etc/kubernetes/psa/admission.yaml"),
                            attest("pod_security_admission_least_privilege",
                                   "the PodSecurity admission configuration represents least privilege")),
    "CNTR-K8-002600": flag_set_not(AS, "request-timeout", "0", "60s"),
    "CNTR-K8-002620": flag_absent(AS, "basic-auth-file"),
    "CNTR-K8-002630": flag_absent(AS, "token-auth-file"),
    "CNTR-K8-002640": allof(flag_set(AS, "kubelet-client-certificate", "/etc/kubernetes/pki/apiserver-kubelet-client.crt"),
                            flag_set(AS, "kubelet-client-key", "/etc/kubernetes/pki/apiserver-kubelet-client.key")),
    "CNTR-K8-002700": fact(["_single_version_per_image(input.cluster.images)"], [("cluster", "images")],
                           {"cluster": {"images": ["registry.k8s.io/kube-apiserver:v1.30.2", "registry.k8s.io/etcd:3.5.12-0"]}},
                           {"cluster": {"images": ["registry.k8s.io/kube-apiserver:v1.30.2", "registry.k8s.io/kube-apiserver:v1.29.6"]}},
                           "only one version of each image may run"),
    "CNTR-K8-002720": fact(["count(input.kubectl.client_versions) > 0",
                            "every v in input.kubectl.client_versions {\n\t\t_ver_part(v, 0) == 1\n\t\tabs(_ver_part(v, 1) - _k8s_minor) <= 1\n\t}"],
                           [("cluster", "version"), ("kubectl", "client_versions")],
                           {"cluster": {"version": "v1.30.2"}, "kubectl": {"client_versions": ["v1.30.2"]}},
                           {"kubectl": {"client_versions": ["v1.27.0"]}},
                           "kubectl must be within one minor version of the cluster (version skew policy)"),
    "CNTR-K8-003110": MANIFESTS_OWN,
    "CNTR-K8-003120": files_owned("etcd_data", "etcd", "etcd", "/var/lib/etcd/member"),
    "CNTR-K8-003130": CONFS_OWN,
    "CNTR-K8-003140": kube_proxy(KP_MODE),
    "CNTR-K8-003150": kube_proxy(KP_OWN),
    "CNTR-K8-003160": allof(flag_absent(KL, "client-ca-file"), KCA_MODE),
    "CNTR-K8-003170": allof(flag_absent(KL, "client-ca-file"), KCA_OWN),
    "CNTR-K8-003180": files_owned("pki", "root", "root", "/etc/kubernetes/pki/ca.crt"),
    "CNTR-K8-003190": KKC_MODE,
    "CNTR-K8-003200": KKC_OWN,
    "CNTR-K8-003210": KADM_OWN,
    "CNTR-K8-003220": KADM_MODE,
    "CNTR-K8-003230": KCY_MODE,
    "CNTR-K8-003240": KCY_OWN,
    "CNTR-K8-003260": files_mode("etcd_data", "644", "/var/lib/etcd/member", owner="etcd", group="etcd"),
    "CNTR-K8-003270": CONFS_MODE,
    "CNTR-K8-003280": allof(flag_set(AS, "audit-policy-file", "/etc/kubernetes/audit-policy.yaml"),
                            fact(['input.api_server.audit_policy.kind == "Policy"', "count(input.api_server.audit_policy.rules) > 0"],
                                 [("api_server", "audit_policy")], {"api_server": {"audit_policy": AUDIT_POLICY_RR}},
                                 {"api_server": {"audit_policy": {"kind": "Policy", "rules": []}}},
                                 "the audit policy file must have valid content (kind Policy, at least one rule)"),
                            expect="--audit-policy-file set with valid content"),
    "CNTR-K8-003290": flag_num_ge(AS, "audit-log-maxsize", 100, 100),
    "CNTR-K8-003300": flag_num_ge(AS, "audit-log-maxbackup", 10, 10),
    "CNTR-K8-003310": flag_num_ge(AS, "audit-log-maxage", 30, 30),
    "CNTR-K8-003320": flag_path(AS, "audit-log-path", "/var/log/kubernetes/audit/audit.log"),
    "CNTR-K8-003330": files_suffix_mode("pki", ".crt", "644", "/etc/kubernetes/pki/ca.crt"),
    "CNTR-K8-003340": files_suffix_mode("pki", ".key", "600", "/etc/kubernetes/pki/ca.key"),
}


# ── RGS RKE2 STIG V2R7 — all 21 rules ───────────────────────────────────────────────────────────
RA, RCM, RSC, RKL = "rke2.args.kube_apiserver", "rke2.args.kube_controller_manager", "rke2.args.kube_scheduler", "rke2.args.kubelet"
R2_CIPHERS = ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
              "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"]
RKE2_AUDIT_POLICY = {"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "metadata": {"name": "rke2-audit-policy"},
                     "rules": [{"level": "Metadata", "resources": [{"group": "", "resources": ["secrets"]}]},
                               {"level": "RequestResponse", "resources": [{"group": "", "resources": ["*"]}]}]}
PSS_DEFAULTS = {"audit": "restricted", "audit-version": "latest", "enforce": "restricted",
                "enforce-version": "latest", "warn": "restricted", "warn-version": "latest"}


def rf(name, mode="0600"):
    return {"name": name, "mode": mode, "owner": "root", "group": "root"}


RKE2_FILES = {
    "etc": [rf("config.yaml"), rf("rke2-pss.yaml")],
    "root": [rf("agent", "0700"), rf("bin", "0750"), rf("data", "0750"), rf("server", "0700")],
    "agent": [rf("kubelet.kubeconfig", "0640"), rf("client-ca.crt"), rf("client-kubelet.key"),
              rf("pod-manifests", "0700"), rf("etc", "0700")],
    "bin": [rf("kubectl", "0750"), rf("containerd", "0750")],
    "data": [rf("v1.30.2-rke2r1-a1b2c3", "0750")],
    "server": [rf("cred", "0700"), rf("db", "0700"), rf("tls", "0700"), rf("manifests", "0750"),
               rf("logs", "0750"), rf("token")],
}
F = "input.rke2.files"
R2_000520_LINES = [
    f'_files_owned({F}.etc, "root", "root")', f'_files_mode_le({F}.etc, "600")',
    f'_files_owned({F}.root, "root", "root")', f'_named_mode_le({F}.root, {{"data"}}, "750")',
    f'_files_owned({F}.agent, "root", "root")',
    f'_named_mode_le({F}.agent, {{"rke2controller.kubeconfig", "kubelet.kubeconfig", "kubeproxy.kubeconfig"}}, "640")',
    f'_named_mode_le({F}.agent, {{"client-ca.crt", "client-kubelet.crt", "client-kube-proxy.crt", "client-rke2-controller.crt", "server-ca.crt", "serving-kubelet.crt"}}, "600")',
    f'_named_mode_le({F}.agent, {{"client-kubelet.key", "serving-kubelet.key", "client-rke2-controller.key", "client-kube-proxy.key"}}, "600")',
    f'_named_mode_le({F}.agent, {{"pod-manifests", "etc"}}, "700")',
    f'_files_owned({F}.bin, "root", "root")', f'_files_mode_le({F}.bin, "750")',
    f'_files_owned({F}.data, "root", "root")', f'_files_mode_le({F}.data, "750")',
    f'_files_owned({F}.server, "root", "root")',
    f'_named_mode_le({F}.server, {{"cred", "db", "tls"}}, "700")',
    f'_named_mode_le({F}.server, {{"manifests", "logs"}}, "750")',
    f'_named_mode_le({F}.server, {{"token"}}, "600")',
    'input.rke2.config["write-kubeconfig-mode"] in {"0600", "600"}',
]

RKE2_RULES = {
    "CNTR-R2-000010": allof(*[flag_in(c, "tls-min-version", TLS, "VersionTLS12", "VersionTLS11") for c in (RA, RCM, RSC)],
                            *[flag_has_all(c, "tls-cipher-suites", R2_CIPHERS, "TLS_RSA_WITH_AES_128_GCM_SHA256") for c in (RA, RCM, RSC)],
                            expect="kube-apiserver, kube-controller-manager and kube-scheduler: --tls-min-version VersionTLS12+ and "
                                   "--tls-cipher-suites including " + ", ".join(R2_CIPHERS)),
    "CNTR-R2-000030": flag_eq(RCM, "use-service-account-credentials", "true"),
    "CNTR-R2-000060": allof(flag_set(RA, "audit-policy-file", "/etc/rancher/rke2/audit-policy.yaml"),
                            flag_eq(RA, "audit-log-mode", "blocking-strict", "batch"),
                            fact(['input.rke2.config.profile in {"cis", "cis-1.23", "cis-1.6"}'], [("rke2", "config")],
                                 {"rke2": {"config": {"profile": "cis"}}}, {"rke2": {"config": {"profile": ""}}},
                                 "config.yaml profile must be cis (or cis-1.23 / cis-1.6)"),
                            fact(["some r1 in input.rke2.audit_policy.rules", 'r1.level == "Metadata"',
                                  "some g1 in r1.resources", 'g1.group == ""', '"secrets" in g1.resources',
                                  "some r2 in input.rke2.audit_policy.rules", 'r2.level == "RequestResponse"',
                                  "some g2 in r2.resources", '"*" in g2.resources'],
                                 [("rke2", "audit_policy")], {"rke2": {"audit_policy": RKE2_AUDIT_POLICY}},
                                 {"rke2": {"audit_policy": {"rules": [{"level": "None"}]}}},
                                 "the audit policy must log secrets at Metadata and all resources at RequestResponse"),
                            expect="--audit-policy-file set, --audit-log-mode blocking-strict, profile cis, audit policy as DISA lists"),
    "CNTR-R2-000100": flag_eq(RCM, "bind-address", "127.0.0.1", "0.0.0.0"),
    "CNTR-R2-000110": flag_eq(RKL, "anonymous-auth", "false"),
    "CNTR-R2-000130": flag_eq(RKL, "read-only-port", "0", "10255"),
    "CNTR-R2-000150": flag_eq(RKL, "authorization-mode", "Webhook", "AlwaysAllow"),
    "CNTR-R2-000160": flag_eq(RA, "anonymous-auth", "false"),
    "CNTR-R2-000320": flag_num_ge(RA, "audit-log-maxage", 30, 30),
    "CNTR-R2-000460": attest("rke2_images_signature_verified",
                             "every RKE2 image was obtained with Hauler and its signature verified against the RGS (Carbide) key"),
    "CNTR-R2-000520": fact(R2_000520_LINES, [("rke2", "files"), ("rke2", "config")],
                           {"rke2": {"files": RKE2_FILES, "config": {"write-kubeconfig-mode": "0600"}}},
                           {"rke2": {"files": {"server": [rf("token", "0644")]}}},
                           "RKE2 file ownership root:root and the modes DISA lists for /etc/rancher/rke2 and /var/lib/rancher/rke2; "
                           "write-kubeconfig-mode 0600"),
    "CNTR-R2-000550": attest("rke2_only_essential_components_enabled",
                             "every default RKE2 component not required (canal, coredns, ingress-nginx, kube-proxy, metrics-server) is disabled"),
    "CNTR-R2-000580": attest("rke2_pps_ppsm_cal_compliant",
                             "RKE2 ports, protocols and services reviewed against the PPSM CAL or approved by the ISSO"),
    "CNTR-R2-000800": attest("no_sensitive_values_in_workload_env",
                             "review of pods, jobs and cronjobs found no sensitive values in environment variables"),
    "CNTR-R2-000890": flag_duration_ge(RKL, "streaming-connection-idle-timeout", "5m", "5m", "30s"),
    "CNTR-R2-000940": flag_eq(RKL, "protect-kernel-defaults", "true"),
    "CNTR-R2-000970": allof(fact(["_only_kubernetes_service(input.cluster.namespace_resources)"],
                                 [("cluster", "namespace_resources")],
                                 {"cluster": {"namespace_resources": {"default": ["service/kubernetes"], "kube-public": [], "kube-node-lease": []}}},
                                 {"cluster": {"namespace_resources": {"kube-public": ["pod/web-1"]}}},
                                 "default, kube-public and kube-node-lease hold nothing but service/kubernetes"),
                            attest("kube_system_resources_approved",
                                   "kube-system holds only the RKE2 system components DISA lists or ISSO-approved services")),
    "CNTR-R2-001130": fact(['_nonempty(input.rke2.config["pod-security-admission-config-file"])',
                            "is_object(input.rke2.pss_defaults)",
                            "every k, v in " + json.dumps(PSS_DEFAULTS) + " {\n\t\tinput.rke2.pss_defaults[k] == v\n\t}"],
                           [("rke2", "config"), ("rke2", "pss_defaults")],
                           {"rke2": {"config": {"pod-security-admission-config-file": "/etc/rancher/rke2/rke2-pss.yaml"},
                                     "pss_defaults": PSS_DEFAULTS}},
                           {"rke2": {"pss_defaults": {"enforce": "baseline"}}},
                           "pod-security-admission-config-file set; defaults audit/enforce/warn = restricted, versions = latest"),
    "CNTR-R2-001270": fact([f'_nonempty({ref(RA, "authorization-mode")})',
                            f'{{trim_space(m) | some m in split({ref(RA, "authorization-mode")}, ",")}} == {{"Node", "RBAC"}}'],
                           [RA.split(".")], nest(RA, {"authorization-mode": "Node,RBAC"}),
                           nest(RA, {"authorization-mode": "AlwaysAllow"}),
                           "kube-apiserver --authorization-mode must be RBAC,Node (either order)"),
    "CNTR-R2-001580": fact(["_single_version_per_image(input.cluster.images)"], [("cluster", "images")],
                           {"cluster": {"images": ["rancher/hardened-kubernetes:v1.30.2-rke2r1-build20240611", "rancher/hardened-etcd:v3.5.13-k3s1-build20240531"]}},
                           {"cluster": {"images": ["rancher/hardened-coredns:v1.11.1-build20240305", "rancher/hardened-coredns:v1.10.1-build20230607"]}},
                           "only one version of each image may run"),
    "CNTR-R2-001620": attest("rke2_supported_version_and_current_images",
                             "every node runs a supported RKE2 release and every running image is the latest patched version"),
}

PLATFORMS = {
    "kubernetes": {"pkg": "kubernetes", "platform": "Kubernetes", "domains": "[kubernetes, container]",
                   "full": True, "rules": K8_RULES, "main": "kubernetes"},
    "rke2": {"pkg": "rke2", "platform": "Rancher Government Solutions RKE2", "domains": "[kubernetes, container]",
             "full": True, "rules": RKE2_RULES},
}


# Framework-key bridge for platforms generated here (mirrors stig_kubernetes_main.rego, which is hand-maintained).
MAIN_TMPL = """# Wrapper exposing the {name} STIG compliance report at the package path
# of the conventional framework-key entrypoint:
#
#   /v1/data/stig_{pkg}/main/compliance_report
#
# All policy logic lives in stig_{pkg}_complete.rego under `package stig.{pkg}`.
# Generated by tools/stig_generators/gen_k8s.py; same contract and fail-closed
# gate as stig_kubernetes_main.rego.

{meta}
package stig.{pkg}.main

import data.stig.{pkg}
import rego.v1

# FAIL-CLOSED GATE: an empty input is reported fully non-compliant with an
# explicit finding, never a pass. A partial input is caught rule by rule: every
# rule whose evidence is absent is Open with "evidence missing" in its detail.

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

_no_facts_finding := {{
\t"rule_title": "FAIL-CLOSED: no facts supplied for stig.{pkg} — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
\t"severity": "CAT I",
\t"status": "Open",
}}

default _upstream := {{}}

_upstream := {pkg}.compliance_report

default _total_controls := 0

_total_controls := _upstream.total_controls

default _upstream_open := []

_upstream_open := [f | some f in _upstream.open_findings]

_open_findings := array.concat(_upstream_open, [_no_facts_finding]) if not _facts_supplied

_open_findings := _upstream_open if _facts_supplied

# No facts => every control is unverified, which counts as failed, not passed.
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


def rego_ident(sid):
    return "r_" + re.sub(r"[^a-z0-9]+", "_", sid.lower()).strip("_")


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def rego_lines(body):
    out = []
    for b in body:                      # continuation lines of a multi-line entry carry their own indent
        first, *rest = b.split("\n")
        out += ["\t" + first] + rest
    return out


def emit(key, cfg):
    cat = json.load(open(os.path.join(CATS, f"{key}.json")))
    by = {r["stig_id"]: r for r in cat["rules"]}
    missing = [sid for sid in cfg["rules"] if sid not in by]
    if missing:
        raise SystemExit(f"{key}: rule IDs not in current XCCDF: {missing}")
    uncovered = [sid for sid in by if sid not in cfg["rules"]]
    if cfg["full"] and uncovered:
        raise SystemExit(f"{key}: catalog rules without logic: {uncovered}")
    bench, ver = cat["benchmark"], cat["version"]
    release = f"Release: {cat['release']} Benchmark Date: {cat['release_date']}"
    pkg = cfg["pkg"]
    outdir = os.path.join(REPO, key)
    os.makedirs(os.path.join(outdir, "tests"), exist_ok=True)
    rules = cfg["rules"]
    n_att = sum(1 for s in rules.values() if s["kind"] == "attestation")
    n_mix = sum(1 for s in rules.values() if s["kind"] == "machine+attestation")
    n_mac = len(rules) - n_att - n_mix
    cat1 = sum(1 for sid in rules if SEV[by[sid]["severity"]] == "CAT I")
    meta = ["# METADATA", f'# title: "DISA STIG — {esc(bench)}"', "# custom:", "#   class: security",
            f"#   framework: stig_{key}", "#   source: disa", f"#   domains: {cfg['domains']}"]
    contract = [l for l in __doc__.split("\n")]
    lines = meta + [f"package stig.{pkg}.core", "",
                    f"# DISA STIG — {bench}", f"# {ver} | {release}",
                    f"# {len(rules)} rules — every rule in the catalog ({cat1} CAT I): {n_mac} machine-checked,",
                    f"# {n_mix} machine-checked plus an attestation, {n_att} attestation-only (DISA's check is a",
                    "# documentation review or human judgment). IDs/severities/titles verified against the",
                    "# DISA XCCDF on 2026-10-21 (tools/stig_generators/gen_k8s.py; regenerate, don't hand-edit).",
                    "# FAIL-CLOSED: a rule whose evidence is absent is Open with detail",
                    '# "<STIG-ID>: evidence missing — <field> not collected"; attestations are Open until',
                    "# input.attest.<key> is true. Input contract: gen_k8s.py docstring, summarised here:"]
    sect = "Kubernetes input contract" if key == "kubernetes" else "RKE2 input contract"
    take = False
    for l in contract:
        if l.startswith(sect):
            take = True
        elif take and (l.startswith("RKE2 input contract") or l.startswith("OpenShift")):
            break
        if take:
            lines.append("#   " + l.rstrip())
    lines += ["", "import rego.v1", HELPERS.rstrip(), ""]
    finds, green, tests = [], {}, []
    for sid in sorted(rules):
        spec, r = rules[sid], by[sid]
        ident, sev = rego_ident(sid), SEV[r["severity"]]
        deep_merge(green, spec["green"], sid)
        evs = ", ".join(json.dumps(list(e)) for e in spec["ev"])
        lines += [f"# {sid} | {r['vuln_id']} | {sev} | {spec['kind']}",
                  f"missing_{ident} := [concat(\".\", p) | some p in [{evs}]; not _collected(p)]", "",
                  f"default {ident} := false", ""]
        for alt in spec["alts"]:
            lines += [ident + " if {", f"\tcount(missing_{ident}) == 0"] + rego_lines(alt) + ["}", ""]
        fail_word = "not attested" if spec["kind"] == "attestation" else "check failed"
        title = esc(" ".join(r["title"].split())[:220])
        lines += [f'default detail_{ident} := ""', "",
                  f'detail_{ident} := sprintf("%s: evidence missing — %s not collected", ["{sid}", concat(", ", missing_{ident})]) if count(missing_{ident}) > 0',
                  "",
                  f"detail_{ident} := \"{sid}: {fail_word} — {esc(spec['expect'])}\" if {{",
                  f"\tcount(missing_{ident}) == 0", f"\tnot {ident}", "}", "",
                  f'detail_{ident} := "{sid}: Not_a_Finding" if {ident}', "",
                  f"finding_{ident} := {{",
                  f'\t"vuln_id": "{r["vuln_id"]}",', f'\t"stig_id": "{sid}",', f'\t"severity": "{sev}",',
                  f'\t"rule_title": "{title}",', f'\t"check_type": "{spec["kind"]}",',
                  f'\t"status": status_{ident},', f'\t"detail": detail_{ident},', "}", "",
                  f'status_{ident} := "Not_a_Finding" if {ident}', "",
                  f'status_{ident} := "Open" if not {ident}', ""]
        finds.append(f"finding_{ident}")
        # tests: pass on green, fail on the mutation, evidence missing when the first evidence path is removed
        tests += [f"test_{ident}_pass if {{", f"\tfs := {pkg}.core.findings with input as green_fixture",
                  f'\tsome f in fs', f'\tf.stig_id == "{sid}"', '\tf.status == "Not_a_Finding"', "}", "",
                  f"test_{ident}_fail if {{",
                  f"\tfs := {pkg}.core.findings with input as object.union(green_fixture, {json.dumps(spec['bad'])})",
                  f'\tsome f in fs', f'\tf.stig_id == "{sid}"', '\tf.status == "Open"',
                  f'\tcontains(f.detail, "{fail_word}")', "}", ""]
        if spec["ev"]:
            tests += [f"test_{ident}_evidence_missing if {{",
                      f"\tfs := {pkg}.core.findings with input as json.remove(green_fixture, [\"{'/'.join(spec['ev'][0])}\"])",
                      f'\tsome f in fs', f'\tf.stig_id == "{sid}"', '\tf.status == "Open"',
                      '\tcontains(f.detail, "evidence missing")', "}", ""]
    lines.append("findings := [")
    lines += [f"\t{f}," for f in finds]
    lines += ["]", "", "default compliant := false", "",
              'compliant if count([f | some f in findings; f.status == "Open"]) == 0']
    open(os.path.join(outdir, "core.rego"), "w").write("\n".join(lines) + "\n")

    o = meta[:1] + [f'# title: "DISA STIG — {esc(bench)} — Master Aggregator"'] + meta[2:] + [
        f"package stig.{pkg}", "",
        f"# DISA STIG — {bench} — Master Aggregator", f"# {ver} | {release}",
        f"# Coverage: {len(rules)} of {len(cat['rules'])} rules ({cat1} CAT I): {n_mac} machine-checked,",
        f"# {n_mix} machine-checked plus an attestation, {n_att} attestation-only.",
        "# Rule IDs verified against the DISA XCCDF on 2026-10-21.",
        "", "import rego.v1", "", f"import data.stig.{pkg}.core", "",
        "all_findings := core.findings", "",
        'open_findings := [f | some f in all_findings; f.status == "Open"]', "",
        'cat_i_open := [f | some f in open_findings; f.severity == "CAT I"]', "",
        "default overall_compliant := false", "", "overall_compliant if count(cat_i_open) == 0", "",
        "default fully_compliant := false", "", "fully_compliant if count(open_findings) == 0", "",
        "stig_assessment := {", '\t"metadata": {',
        f'\t\t"stig_title": "{esc(bench)}",', f'\t\t"version": "{ver}",', f'\t\t"release": "{esc(release)}",',
        f'\t\t"platform": "{esc(cfg["platform"])}",',
        '\t\t"assessed_host": object.get(input, ["system_info", "hostname"], "unknown"),', "\t},",
        '\t"summary": {', '\t\t"total_findings": count(all_findings),', '\t\t"open": count(open_findings),',
        '\t\t"not_a_finding": count(all_findings) - count(open_findings),', '\t\t"cat_i_open": count(cat_i_open),',
        '\t\t"overall_compliant": overall_compliant,', '\t\t"fully_compliant": fully_compliant,', "\t},",
        '\t"findings": all_findings,', "}", "",
        "# Uniform library entrypoint contract (consumed by the .main alias's",
        "# fail-closed gate): total_controls + open_findings are required.",
        "compliance_report := {",
        '\t"total_controls": count(all_findings),', '\t"open_findings": open_findings,',
        '\t"passed_controls": count(all_findings) - count(open_findings),', '\t"failed_controls": count(open_findings),',
        '\t"compliant": fully_compliant,', "}"]
    open(os.path.join(outdir, f"stig_{key}_complete.rego"), "w").write("\n".join(o) + "\n")

    gs = json.dumps(green, indent="\t").replace("\n", "\n\t")
    t = [f"package stig.{pkg}_test", "", "import rego.v1", "", f"import data.stig.{pkg}", "",
         "# Generated by tools/stig_generators/gen_k8s.py — one pass, one fail and (where the rule reads",
         "# collected evidence) one evidence-missing test per rule, plus empty-input fail-closed tests.", "",
         f"green_fixture := {gs}", "",
         "test_report_wellformed_on_empty_input if {", f"\treport := {pkg}.stig_assessment with input as {{}}",
         "\tis_object(report)", f"\treport.summary.total_findings == {len(rules)}", "}", "",
         "test_every_finding_open_on_empty_input if {", f"\tfs := {pkg}.core.findings with input as {{}}",
         f"\tcount(fs) == {len(rules)}", '\tcount([f | some f in fs; f.status != "Open"]) == 0', "}", "",
         "test_fully_compliant_on_green_fixture if {", f"\treport := {pkg}.stig_assessment with input as green_fixture",
         f"\treport.summary.total_findings == {len(rules)}", "\treport.summary.fully_compliant == true", "}", "",
         "test_main_fail_closed_on_empty_input if {", f"\trep := data.stig.{pkg}.main.compliance_report with input as {{}}",
         "\trep.compliant == false", "\trep.facts_supplied == false", f"\trep.failed_controls == {len(rules)}", "}", "",
         "test_main_compliant_on_green_fixture if {", f"\trep := data.stig.{pkg}.main.compliance_report with input as green_fixture",
         "\trep.compliant == true", "\trep.violation_count == 0", "}", "",
         "test_main_partial_input_is_not_compliant if {",
         f'\trep := data.stig.{pkg}.main.compliance_report with input as {{"cluster": {{"version": "v1.30.2"}}}}',
         "\trep.compliant == false", "\trep.facts_supplied == true", "}", ""] + tests
    open(os.path.join(outdir, "tests", f"test_stig_{key}.rego"), "w").write("\n".join(t).rstrip() + "\n")
    if "main" not in cfg:   # kubernetes keeps its hand-maintained bridge
        mmeta = "\n".join(meta[:1] + [f'# title: "Wrapper exposing the {cfg["platform"]} STIG compliance report at the package path"'] + meta[2:])
        open(os.path.join(outdir, f"stig_{key}_main.rego"), "w").write(
            MAIN_TMPL.format(name=cfg["platform"], pkg=pkg, meta=mmeta))
    print(f"{key}: {len(rules)} of {len(cat['rules'])} rules ({cat1} CAT I): {n_mac} machine, "
          f"{n_mix} machine+attestation, {n_att} attestation-only; {ver} {cat['release_date']}")


if __name__ == "__main__":
    for key in (sys.argv[1:] or ["kubernetes", "rke2"]):
        if key not in PLATFORMS:
            raise SystemExit(f"unknown platform {key}; known: {', '.join(PLATFORMS)}")
        emit(key, PLATFORMS[key])
