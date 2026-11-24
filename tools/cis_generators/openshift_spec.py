"""Logic table, Rego helpers, green fixture and extra tests for gen_openshift.py.

Hand-written from the audit procedures of CIS Red Hat OpenShift Container Platform Benchmark v2.0.0. Wording is ours;
no benchmark text is stored here. The file-mode helpers (octal, mode_within, _files, _named, _owned, _pki_*) and the
flag normalisation (_norm, _bool) are copied from the gen_kubernetes.py helper block, which cannot be imported
because that script reads its workbook at import time.
"""


def add(path, value):
    return [{"op": "add", "path": path, "value": value}]


def rm(path):
    return [{"op": "remove", "path": path}]


def fact(cid, kw, title, ev, label, oks, fail, miss, needs_attest=()):
    return {"id": cid, "kw": kw, "title": title, "kind": "fact", "ev": ev, "label": label, "ok": oks,
            "fail": fail, "miss": miss, "needs_attest": list(needs_attest)}


def att(cid, kw, title, key):
    return {"id": cid, "kw": kw, "title": title, "kind": "attest", "attest": key, "attest_root": "input"}


# ── file checks (files.<group>, every entry on every node / pod) ─────────────────────────────────────────
def fmode(cid, kw, title, group, stem, mx, idx):
    return fact(cid, kw, title, [f'_has_named("{group}", "{stem}")'], f"files.{group} entry for {stem}",
                [[f'every f in _named("{group}", "{stem}") {{ mode_within(f.mode, "{mx}") }}']],
                add(f"/files/{group}/{idx}/mode", "0644" if mx == "600" else "0777"), rm(f"/files/{group}"))


def fown(cid, kw, title, group, stem, idx):
    return fact(cid, kw, title, [f'_has_named("{group}", "{stem}")'], f"files.{group} entry for {stem}",
                [[f'every f in _named("{group}", "{stem}") {{ _owned(f, "root", "root") }}']],
                add(f"/files/{group}/{idx}/owner", "nobody"), rm(f"/files/{group}"))


def gmode(cid, kw, title, group, mx, sel="_files", label=None, idx=0):
    return fact(cid, kw, title, [f'count({sel}("{group}")) > 0'], label or f"files.{group}",
                [[f'every f in {sel}("{group}") {{ mode_within(f.mode, "{mx}") }}']],
                add(f"/files/{group}/{idx}/mode", "0666"), rm(f"/files/{group}"))


def gown(cid, kw, title, group, sel="_files", label=None):
    return fact(cid, kw, title, [f'count({sel}("{group}")) > 0'], label or f"files.{group}",
                [[f'every f in {sel}("{group}") {{ _owned(f, "root", "root") }}']],
                add(f"/files/{group}/0/group", "wheel"), rm(f"/files/{group}"))


# ── kube-apiserver config.yaml (openshift.kube_apiserver_config.apiServerArguments) ──────────────────────
KAS = "openshift.kube_apiserver_config"
KAS_EV = ['_collected("kube_apiserver_config")']
KAS_MISS = rm("/openshift/kube_apiserver_config")
ARGP = "/openshift/kube_apiserver_config/apiServerArguments"


def kas(cid, kw, title, oks, fail):
    return fact(cid, kw, title, KAS_EV, KAS, oks, fail, KAS_MISS)


def kas_set(name, value):
    return add(f"{ARGP}/{name}", value)


KCM = "openshift.kube_controller_manager_config"
KCM_EV = ['_collected("kube_controller_manager_config")']
KCM_MISS = rm("/openshift/kube_controller_manager_config")


def kcm(cid, kw, title, oks, fail):
    return fact(cid, kw, title, KCM_EV, KCM, oks, fail, KCM_MISS)


# ── etcd members and kubelet nodes ───────────────────────────────────────────────────────────────────────
ETCD_EV = ["_etcd_members_collected"]
ETCD_LABEL = "etcd.members[].flags"
ETCD_MISS = rm("/etcd/members")


def etcd(cid, kw, title, body, fail):
    return fact(cid, kw, title, ETCD_EV, ETCD_LABEL, [[f"every m in input.etcd.members {{ {body} }}"]], fail, ETCD_MISS)


def eflag(name, value, member=1):
    return add(f"/etcd/members/{member}/flags/{name}", value)


NODE_EV = ["_kubelet_nodes_collected"]
NODE_LABEL = "kubelet.nodes[].config"
NODE_MISS = rm("/kubelet/nodes")


def node(cid, kw, title, body, fail):
    return fact(cid, kw, title, NODE_EV, NODE_LABEL, [[f"every n in input.kubelet.nodes {{ {body} }}"]], fail, NODE_MISS)


def ncfg(path, value, n=1):
    return add(f"/kubelet/nodes/{n}/config/{path}", value)


SCC_EV = ["_scc_collected"]
SCC_LABEL = "scc.items / collection_status.scc"
SCC_MISS = rm("/collection_status/scc")


def scc(cid, kw, title, cond, fail_field, fail_value):
    """At least one SCC meets cond; the fail patch sets fail_field on every SCC in the green list."""
    fail = [op for i in range(3) for op in add(f"/scc/items/{i}/{fail_field}", fail_value)]
    return fact(cid, kw, title, SCC_EV, SCC_LABEL, [[f"some s in input.scc.items", cond]], fail, SCC_MISS)


def probe(component):
    return f'_probe_protected("{component}")'


SP = "/etc/kubernetes/static-pod-resources"
SPC = "/etc/kubernetes/static-pod-certs"
DEFAULT_UNAUTH = ["self-access-reviewers", "system:oauth-token-deleters", "system:openshift:public-info-viewer",
                  "system:public-info-viewer", "system:scope-impersonation", "system:webhooks"]
STRONG_GO = ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
             "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
             "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
             "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256"]
# the same suites under their IANA names (Go accepts both spellings) and the TLS 1.3 AEAD suites OpenShift lists
STRONG_ALIASES = ["TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                  "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
# the same set in the OpenSSL spelling the ingress controller reports
STRONG_OPENSSL = ["ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305",
                  "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384",
                  "AES256-GCM-SHA384", "AES128-GCM-SHA256",
                  "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]


def rset(xs):
    return "{" + ", ".join(f'"{x}"' for x in sorted(xs)) + "}"


HELPERS = r'''# ── profile ──────────────────────────────────────────────────────────────────
default _cis_profile := {}

_cis_profile := p if {
	p := input.cis_profile
	is_object(p)
}

default level := 2

level := 1 if _cis_profile.level == 1

_selected_profiles := {sprintf("Level %d", [l]) | some l in numbers.range(1, level)}

in_scope contains id if {
	some id, r in recommendations
	some p in r.profiles
	p in _selected_profiles
}

_applies(id) if id in in_scope

# ── values ───────────────────────────────────────────────────────────────────
_nonempty(s) if {
	is_string(s)
	trim_space(s) != ""
}

_bool(v) := "true" if lower(trim_space(v)) in {"1", "t", "true"}

_bool(v) := "false" if lower(trim_space(v)) in {"0", "f", "false"}

# Endpoint and container ports are numbers in the API objects; a string in their place is not a port.
_port(p) := p if is_number(p)

# ── OpenShift objects and config files under input.openshift ─────────────────
_obj(name) := o if {
	o := object.get(input, ["openshift", name], null)
	is_object(o)
}

_collected(name) if _obj(name)

# Argument maps become component flags, and the flag parser treats "_" and "-" alike, so argument names are
# normalised ("--a_b" == "a-b"). _named_list reads <name> from such a map as a list of strings: [] when no key
# normalises to it, undefined when two keys do (ambiguous) or the value is not a list of strings, so a malformed
# or ambiguous value fails every check.
_norm(k) := replace(trim_left(k, "-"), "_", "-")

_named_list(m, name) := [] if {
	is_object(m)
	count([k | some k, _ in m; _norm(k) == name]) == 0
}

_named_list(m, name) := l if {
	is_object(m)
	ks := [k | some k, _ in m; _norm(k) == name]
	count(ks) == 1
	l := m[ks[0]]
	is_array(l)
	every x in l { is_string(x) }
}

# <field>[<name>] of a parsed OpenShift config file; undefined when the file was not collected
_arg(o, field, name) := _named_list(object.get(_obj(o), field, {}), name)

_kas(name) := _arg("kube_apiserver_config", "apiServerArguments", name)

_oas(name) := _arg("openshift_apiserver_config", "apiServerArguments", name)

_kcm(name) := _arg("kube_controller_manager_config", "extendedArguments", name)

# comma-separated entries of a list argument as a set
_list_set(l) := {trim_space(x) | some e in l; some x in split(e, ","); trim_space(x) != ""}

_kas_set(name) := _list_set(_kas(name))

# the argument is readable and does not list <x>
_kas_lacks(name, x) if {
	s := _kas_set(name)
	not x in s
}

_all_eq(l, v) if {
	count(l) > 0
	every x in l { trim_space(x) == v }
}

_all_nonempty(l) if {
	count(l) > 0
	every x in l { _nonempty(x) }
}

_all_num_min(l, n) if {
	count(l) > 0
	every x in l {
		regex.match(`^[0-9]+$`, trim_space(x))
		to_number(trim_space(x)) >= n
	}
}

_all_true(l) if {
	count(l) > 0
	every x in l { _bool(x) == "true" }
}

# an optional boolean argument: absent, or every value true
_absent_or_true(l) if every x in l { _bool(x) == "true" }

# feature gates of the kube-apiserver operator's observed configuration ("Name=bool" entries)
_op_args(name) := _named_list(object.get(_obj("kubeapiserver"), ["spec", "observedConfig", "apiServerArguments"], {}), name)

_gate_vals(name) := [_gate_val(p) |
	some e in _list_set(_op_args("feature-gates"))
	p := split(e, "=")
	trim_space(p[0]) == name
]

_gate_val(p) := b if {
	count(p) == 2
	b := _bool(p[1])
}

_gate_val(p) := "invalid" if count(p) != 2

_gate_val(p) := "invalid" if {
	count(p) == 2
	not _bool(p[1])
}

# never switched off (an absent gate keeps its default)
_gate_never_false(name) if {
	vals := _gate_vals(name)
	every v in vals { v == "true" }
}

_gate_never_true(name) if {
	vals := _gate_vals(name)
	every v in vals { v == "false" }
}

_ports_all(name, port) if {
	l := object.get(input, ["openshift", name], null)
	is_array(l)
	count(l) > 0
	every p in l { _port(p) == port }
}

_ports_collected(name) if {
	l := object.get(input, ["openshift", name], null)
	is_array(l)
	count(l) > 0
}

_serving_cert_ok if {
	s := _obj("openshift_apiserver_serving_cert")
	s.type == "kubernetes.io/tls"
	is_array(s.data_keys)
	"tls.crt" in s.data_keys
	"tls.key" in s.data_keys
}

# ── metrics endpoint probes ──────────────────────────────────────────────────
_probe(c) := p if {
	p := object.get(input, ["openshift", "metrics_probes", c], null)
	is_object(p)
	every k in ["unauthenticated", "service_account", "cluster_admin"] { is_number(p[k]) }
}

_denied(code) if code in {401, 403}

_probe_protected(c) if {
	p := _probe(c)
	_denied(p.unauthenticated)
	_denied(p.service_account)
	p.cluster_admin == 200
}

_container(o, cname) := c if {
	some c in _obj(o).spec.containers
	c.name == cname
}

_healthz(p) if trim_prefix(p, "/") == "healthz"

_probes_healthz(o, cname) if {
	c := _container(o, cname)
	_healthz(c.livenessProbe.httpGet.path)
	_healthz(c.readinessProbe.httpGet.path)
}

# every whitespace-separated token of a container's command and args
_container_tokens(o, cname) := toks if {
	c := _container(o, cname)
	words := array.concat(object.get(c, "command", []), object.get(c, "args", []))
	toks := [t | some a in words; is_string(a); some t in regex.split(`\s+`, trim_space(a)); t != ""]
}

# the flag name of a "--name=value" or "--name" token, normalised like the flag parser does; undefined for a
# token that is not a flag
_flag_name(t) := _norm(split(t, "=")[0]) if startswith(t, "-")

_bind_or_port_flag(t) if _flag_name(t) in {"bind-address", "port"}

_scheduler_no_bind_or_port if {
	toks := _container_tokens("kube_scheduler_pod", "kube-scheduler")
	every t in toks { not _bind_or_port_flag(t) }
}

# ── TLS ──────────────────────────────────────────────────────────────────────
_tls_ok(v) if v in {"VersionTLS12", "VersionTLS13"}

_tls_profile := object.get(_obj("apiserver"), ["spec", "tlsSecurityProfile"], null)

# absent or empty means the Intermediate default
_tls_profile_ok if _tls_profile in {null, {}}

_tls_profile_ok if _tls_profile.type in {"Intermediate", "Modern"}

_tls_profile_ok if {
	_tls_profile.type == "Custom"
	_tls_ok(_tls_profile.custom.minTLSVersion)
}

_strong_go := __STRONG_GO__

_strong_openssl := __STRONG_OPENSSL__

_suites_strong(l) if {
	is_array(l)
	count(l) > 0
	every s in l { s in _strong_go }
}

# ── etcd members, kubelet nodes, SCCs ────────────────────────────────────────
default _etcd_members_collected := false

_etcd_members_collected if {
	ms := input.etcd.members
	is_array(ms)
	count(ms) > 0
	every m in ms { is_object(m.flags) }
}

# etcd flag names are normalised with _norm ("--a_b" == "a-b"); a value is read only when exactly one key matches

_mkeys(m, name) := [k | some k, _ in m.flags; _norm(k) == name]

_munset(m, name) if count(_mkeys(m, name)) == 0

_mfl(m, name) := v if {
	ks := _mkeys(m, name)
	count(ks) == 1
	v := m.flags[ks[0]]
	is_string(v)
}

_m_nonempty(m, name) if _nonempty(_mfl(m, name))

_m_true(m, name) if _bool(_mfl(m, name)) == "true"

_m_not_true(m, name) if _munset(m, name)

_m_not_true(m, name) if _bool(_mfl(m, name)) == "false"

_m_is(m, name, v) if trim_space(_mfl(m, name)) == v

default _kubelet_nodes_collected := false

_kubelet_nodes_collected if {
	ns := input.kubelet.nodes
	is_array(ns)
	count(ns) > 0
	every n in ns { is_object(n.config) }
}

# streamingConnectionIdleTimeout: absent or null keeps the 4h default; 0 disables the timeout
_idle_ok(c) if not "streamingConnectionIdleTimeout" in object.keys(c)

_idle_ok(c) if c.streamingConnectionIdleTimeout == null

_idle_ok(c) if {
	v := c.streamingConnectionIdleTimeout
	is_string(v)
	time.parse_duration_ns(v) > 0
}

default _kube_proxy_files_collected := false

_kube_proxy_files_collected if input.kube_proxy.running == false

_kube_proxy_files_collected if {
	input.kube_proxy.running == true
	count(_files("kube_proxy_kubeconfig")) > 0
}

default _scc_collected := false

_scc_collected if {
	is_array(input.scc.items)
	count(input.scc.items) > 0
	input.collection_status.scc == "ok"
}

# The SCC allow* fields are booleans in the API object. A string or a number in their place is a collection
# error: it is not read as a refusal, and it is reported under the recommendation that reads the field.
_scc_boolean_fields := [
	["allowPrivilegedContainer", "5.2.1"],
	["allowHostPID", "5.2.2"],
	["allowHostIPC", "5.2.3"],
	["allowHostNetwork", "5.2.4"],
	["allowPrivilegeEscalation", "5.2.5"],
]

_v_policies contains sprintf("%s: evidence invalid — SCC %v: %s must be true or false, got %s", [id, object.get(s, ["metadata", "name"], "<unnamed>"), field, type_name(s[field])]) if {
	some [field, id] in _scc_boolean_fields
	_applies(id)
	_scc_collected
	some s in input.scc.items
	not is_null(s[field])
	not is_boolean(s[field])
}

# allowPrivilegedContainer, allowHostPID, allowHostIPC and allowHostNetwork are required fields of the SCC API
# object, so `oc get scc -o json` always carries them. An SCC collected without one (or with null) was not
# collected whole: it is reported under the recommendation that reads the field, even when another SCC meets
# it. allowPrivilegeEscalation is optional in the API (unset means escalation is allowed) and is not listed.
_scc_required_fields := {"allowPrivilegedContainer", "allowHostPID", "allowHostIPC", "allowHostNetwork"}

_v_policies contains sprintf("%s: evidence missing — SCC %v: %s not collected", [id, object.get(s, ["metadata", "name"], "<unnamed>"), field]) if {
	some [field, id] in _scc_boolean_fields
	field in _scc_required_fields
	_applies(id)
	_scc_collected
	some s in input.scc.items
	is_null(object.get(s, field, null))
}

# the audit names exactly two objects as expected in the default namespace: the kubernetes and openshift Services
_default_ns_allowed(r) if r in {"service/kubernetes", "service/openshift"}

_unauthenticated_default := __UNAUTH__

# ── files ────────────────────────────────────────────────────────────────────
# a collected, non-empty file list (an empty list proves nothing)
_files(g) := fs if {
	fs := object.get(input, ["files", g], null)
	is_array(fs)
	count(fs) > 0
}

_base(p) := b if {
	parts := split(trim_right(p, "/"), "/")
	b := parts[count(parts) - 1]
}

_stem(p) := regex.replace(_base(p), `\.(yaml|yml|json|manifest)$`, "")

# entries whose file name (less a manifest extension) is <stem>
_named(g, stem) := [x | some x in _files(g); is_string(x.path); _stem(x.path) == stem]

_has_named(g, stem) if count(_named(g, stem)) > 0

_owned(x, owner, group) if {
	x.owner == owner
	x.group == group
}

_pki_certs(g) := [x | some x in _files(g); is_string(x.path); endswith(x.path, ".crt")]

_pki_keys(g) := [x | some x in _files(g); is_string(x.path); endswith(x.path, ".key")]

# Parse an octal permission STRING ("600", "0600", "0o600") to an integer. A number is ambiguous (644 decimal
# or octal?) and anything else is not a mode: both are undefined, so the check fails.
octal(s) := n if {
	is_string(s)
	t := trim_prefix(lower(trim_space(s)), "0o")
	regex.match(`^[0-7]{1,4}$`, t)
	p := concat("", [substring("0000", 0, 4 - count(t)), t])
	ds := [to_number(substring(p, i, 1)) | some i in numbers.range(0, 3)]
	n := ((ds[0] * 512) + (ds[1] * 64)) + ((ds[2] * 8) + ds[3])
}

# true when mode sets no permission bit (setuid, setgid and sticky included) beyond max
mode_within(mode, max) if bits.and(octal(mode), bits.and(bits.negate(octal(max)), 4095)) == 0

'''.replace("__STRONG_GO__", rset(STRONG_GO + STRONG_ALIASES)) \
   .replace("__STRONG_OPENSSL__", rset(STRONG_OPENSSL)) \
   .replace("__UNAUTH__", rset(DEFAULT_UNAUTH))

M = "manifests"
OAS_EV = ['_collected("openshift_apiserver_config")']

C1 = [
    # ── 1.1 control plane node configuration files (stat in the static pods) ───────────────────────────────
    fmode("1.1.1", "api server pod", "kube-apiserver static pod specification file mode must be 600 or stricter", M, "kube-apiserver-pod", "600", 0),
    fown("1.1.2", "api server pod", "kube-apiserver static pod specification file must be owned by root:root", M, "kube-apiserver-pod", 0),
    fmode("1.1.3", "controller manager pod", "kube-controller-manager static pod specification file mode must be 600 or stricter", M, "kube-controller-manager-pod", "600", 1),
    fown("1.1.4", "controller manager pod", "kube-controller-manager static pod specification file must be owned by root:root", M, "kube-controller-manager-pod", 1),
    fmode("1.1.5", "scheduler pod", "kube-scheduler static pod specification file mode must be 600 or stricter", M, "kube-scheduler-pod", "600", 2),
    fown("1.1.6", "scheduler pod", "kube-scheduler static pod specification file must be owned by root:root", M, "kube-scheduler-pod", 2),
    fmode("1.1.7", "etcd pod", "etcd static pod specification file mode must be 600 or stricter", M, "etcd-pod", "600", 3),
    fown("1.1.8", "etcd pod", "etcd static pod specification file must be owned by root:root", M, "etcd-pod", 3),
    fact("1.1.9", "container network interface", "every multus, openshift-sdn and Open vSwitch file mode must be 600 or stricter",
         ['count(_files("cni")) > 0', 'count(_files("ovs")) > 0'], "files.cni and files.ovs",
         [['every f in array.concat(_files("cni"), _files("ovs")) { mode_within(f.mode, "600") }']],
         add("/files/ovs/0/mode", "0644"), rm("/files/ovs")),
    fact("1.1.10", "container network interface", "multus and openshift-sdn files must be owned by root:root and Open vSwitch files by openvswitch:openvswitch",
         ['count(_files("cni")) > 0', 'count(_files("ovs")) > 0'], "files.cni and files.ovs",
         [['every f in _files("cni") { _owned(f, "root", "root") }',
           'every f in _files("ovs") { _owned(f, "openvswitch", "openvswitch") }']],
         add("/files/ovs/0/owner", "root"), rm("/files/cni")),
    gmode("1.1.11", "etcd data directory", "etcd data directory (/var/lib/etcd/member) mode must be 700 or stricter", "etcd_data", "700"),
    gown("1.1.12", "etcd data directory", "etcd data directory (/var/lib/etcd/member) must be owned by root:root", "etcd_data"),
    gmode("1.1.13", "kubeconfig file permissions", "/etc/kubernetes/kubeconfig mode must be 600 or stricter on every node", "node_kubeconfig", "600"),
    gown("1.1.14", "kubeconfig file ownership", "/etc/kubernetes/kubeconfig must be owned by root:root on every node", "node_kubeconfig"),
    gmode("1.1.15", "scheduler kubeconfig", "kube-scheduler kubeconfig mode must be 600 or stricter", "scheduler_kubeconfig", "600"),
    gown("1.1.16", "scheduler kubeconfig", "kube-scheduler kubeconfig must be owned by root:root", "scheduler_kubeconfig"),
    gmode("1.1.17", "controller manager kubeconfig", "kube-controller-manager kubeconfig mode must be 600 or stricter", "controller_manager_kubeconfig", "600"),
    gown("1.1.18", "controller manager kubeconfig", "kube-controller-manager kubeconfig must be owned by root:root", "controller_manager_kubeconfig"),
    gown("1.1.19", "pki directory", "every file and directory under the static pod secrets trees must be owned by root:root", "pki"),
    gmode("1.1.20", "pki certificate", "every static pod .crt file mode must be 600 or stricter", "pki", "600",
          sel="_pki_certs", label="files.pki entries ending in .crt", idx=1),
    gmode("1.1.21", "pki key", "every static pod .key file mode must be 600 or stricter", "pki", "600",
          sel="_pki_keys", label="files.pki entries ending in .key", idx=2),
    # ── 1.2 API server ─────────────────────────────────────────────────────────────────────────────────────
    fact("1.2.1", "anonymous requests", "ClusterRoleBindings for system:unauthenticated must be only the built-in set, or be attested (attest.unauthenticated_bindings_reviewed)",
         ["is_array(input.openshift.unauthenticated_cluster_role_bindings)", 'input.collection_status.unauthenticated_bindings == "ok"'],
         "openshift.unauthenticated_cluster_role_bindings / collection_status.unauthenticated_bindings",
         [["every n in input.openshift.unauthenticated_cluster_role_bindings { n in _unauthenticated_default }"],
          ["input.attest.unauthenticated_bindings_reviewed == true"]],
         add("/openshift/unauthenticated_cluster_role_bindings/-", "anonymous-admin"), rm("/collection_status/unauthenticated_bindings")),
    fact("1.2.2", "https for kubelet", "kube-apiserver must hold a kubelet client certificate and key, kubelet-https must not be false, and the openshift-apiserver serving-cert must be a TLS secret",
         KAS_EV + ['_collected("openshift_apiserver_serving_cert")'], f"{KAS} and openshift.openshift_apiserver_serving_cert",
         [['_all_nonempty(_kas("kubelet-client-certificate"))', '_all_nonempty(_kas("kubelet-client-key"))',
           '_absent_or_true(_kas("kubelet-https"))', "_serving_cert_ok"]],
         kas_set("kubelet-https", ["false"]), rm("/openshift/openshift_apiserver_serving_cert")),
    fact("1.2.3", "certificates to authenticate", "kube-apiserver must hold a kubelet client certificate and key and the openshift-apiserver serving-cert must be a TLS secret",
         KAS_EV + ['_collected("openshift_apiserver_serving_cert")'], f"{KAS} and openshift.openshift_apiserver_serving_cert",
         [['_all_nonempty(_kas("kubelet-client-certificate"))', '_all_nonempty(_kas("kubelet-client-key"))', "_serving_cert_ok"]],
         add("/openshift/openshift_apiserver_serving_cert/type", "Opaque"), KAS_MISS),
    kas("1.2.4", "kubelet certificate authority", "kube-apiserver kubelet-certificate-authority must be given",
        [['_all_nonempty(_kas("kubelet-certificate-authority"))']], kas_set("kubelet-certificate-authority", [])),
    kas("1.2.5", "alwaysallow", "kube-apiserver authorization-mode must be given and must exclude AlwaysAllow",
        [['count(_kas_set("authorization-mode")) > 0', '_kas_lacks("authorization-mode", "AlwaysAllow")']],
        kas_set("authorization-mode", ["RBAC", "AlwaysAllow"])),
    kas("1.2.6", "rbac", "kube-apiserver authorization-mode must list RBAC",
        [['"RBAC" in _kas_set("authorization-mode")']], kas_set("authorization-mode", ["Node"])),
    fact("1.2.7", "apipriorityandfairness", "the APIPriorityAndFairness feature gate must not be switched off in the kube-apiserver observed configuration",
         ['_collected("kubeapiserver")'], "openshift.kubeapiserver",
         [['_gate_never_false("APIPriorityAndFairness")']],
         add("/openshift/kubeapiserver/spec/observedConfig/apiServerArguments/feature-gates", ["APIPriorityAndFairness=false"]),
         rm("/openshift/kubeapiserver")),
    kas("1.2.8", "alwaysadmit", "kube-apiserver enable-admission-plugins must exclude AlwaysAdmit",
        [['_kas_lacks("enable-admission-plugins", "AlwaysAdmit")']], kas_set("enable-admission-plugins", ["NodeRestriction,AlwaysAdmit"])),
    kas("1.2.9", "alwayspullimages", "kube-apiserver enable-admission-plugins must exclude AlwaysPullImages",
        [['_kas_lacks("enable-admission-plugins", "AlwaysPullImages")']], kas_set("enable-admission-plugins", ["AlwaysPullImages"])),
    kas("1.2.10", "serviceaccount", "kube-apiserver enable-admission-plugins must list ServiceAccount",
        [['"ServiceAccount" in _kas_set("enable-admission-plugins")']], kas_set("enable-admission-plugins", ["NodeRestriction"])),
    kas("1.2.11", "namespacelifecycle", "kube-apiserver enable-admission-plugins must list NamespaceLifecycle",
        [['"NamespaceLifecycle" in _kas_set("enable-admission-plugins")']], kas_set("enable-admission-plugins", ["NodeRestriction"])),
    kas("1.2.12", "securitycontextconstraint", "kube-apiserver enable-admission-plugins must list security.openshift.io/SecurityContextConstraint",
        [['"security.openshift.io/SecurityContextConstraint" in _kas_set("enable-admission-plugins")']],
        kas_set("enable-admission-plugins", ["NodeRestriction"])),
    kas("1.2.13", "noderestriction", "kube-apiserver enable-admission-plugins must list NodeRestriction",
        [['"NodeRestriction" in _kas_set("enable-admission-plugins")']], kas_set("enable-admission-plugins", ["ServiceAccount"])),
    fact("1.2.14", "insecure-bind-address", "InsecureBindAddress must not be switched on and the API server endpoints must serve on 6443 (kube) and 8443 (openshift) only",
         ['_collected("kubeapiserver")', '_ports_collected("kube_apiserver_endpoint_ports")', '_ports_collected("openshift_apiserver_endpoint_ports")'],
         "openshift.kubeapiserver, openshift.kube_apiserver_endpoint_ports and openshift.openshift_apiserver_endpoint_ports",
         [['_gate_never_true("InsecureBindAddress")', '_ports_all("kube_apiserver_endpoint_ports", 6443)',
           '_ports_all("openshift_apiserver_endpoint_ports", 8443)']],
         add("/openshift/openshift_apiserver_endpoint_ports/-", 8080), rm("/openshift/openshift_apiserver_endpoint_ports")),
    fact("1.2.15", "insecure-port", "the kube-apiserver endpoints must serve on port 6443 only",
         ['_ports_collected("kube_apiserver_endpoint_ports")'], "openshift.kube_apiserver_endpoint_ports",
         [['_ports_all("kube_apiserver_endpoint_ports", 6443)']],
         add("/openshift/kube_apiserver_endpoint_ports/-", 8080), rm("/openshift/kube_apiserver_endpoint_ports")),
    fact("1.2.16", "secure-port", "the kube-apiserver serving bind address must be 0.0.0.0:6443 and its container must expose port 6443 only",
         ['_collected("kubeapiserver")', '_ports_collected("kube_apiserver_container_ports")'],
         "openshift.kubeapiserver and openshift.kube_apiserver_container_ports",
         [['_obj("kubeapiserver").spec.observedConfig.servingInfo.bindAddress == "0.0.0.0:6443"',
           '_ports_all("kube_apiserver_container_ports", 6443)']],
         add("/openshift/kubeapiserver/spec/observedConfig/servingInfo/bindAddress", "0.0.0.0:0"), rm("/openshift/kube_apiserver_container_ports")),
    fact("1.2.17", "healthz endpoint", "the kube-apiserver metrics endpoint must refuse unauthenticated and unprivileged requests and answer a cluster administrator",
         ['_probe("kube_apiserver")'], "openshift.metrics_probes.kube_apiserver",
         [[probe("kube_apiserver")]], add("/openshift/metrics_probes/kube_apiserver/unauthenticated", 200),
         rm("/openshift/metrics_probes/kube_apiserver")),
    fact("1.2.18", "audit-log-path", "kube-apiserver and openshift-apiserver audit-log-path must be their default audit.log paths and both logs must exist",
         KAS_EV + OAS_EV + ["is_object(input.openshift.audit_logs)"],
         f"{KAS}, openshift.openshift_apiserver_config and openshift.audit_logs",
         [['_all_eq(_kas("audit-log-path"), "/var/log/kube-apiserver/audit.log")',
           '_all_eq(_oas("audit-log-path"), "/var/log/openshift-apiserver/audit.log")',
           "input.openshift.audit_logs.kube_apiserver_file_present == true",
           "input.openshift.audit_logs.openshift_apiserver_file_present == true"]],
         add("/openshift/audit_logs/openshift_apiserver_file_present", False), rm("/openshift/openshift_apiserver_config")),
    att("1.2.19", "forwarded off the cluster", "API audit logs must be forwarded to a store outside the cluster", "audit_log_forwarding_configured"),
    kas("1.2.20", "maximumretainedfiles", "kube-apiserver audit-log-maxbackup must be 10 or more",
        [['_all_num_min(_kas("audit-log-maxbackup"), 10)']], kas_set("audit-log-maxbackup", ["5"])),
    kas("1.2.21", "maximum audit log size", "kube-apiserver audit-log-maxsize must be 100 or more",
        [['_all_num_min(_kas("audit-log-maxsize"), 100)']], kas_set("audit-log-maxsize", ["0"])),
    kas("1.2.22", "request-timeout", "kube-apiserver min-request-timeout must be 3600",
        [['_all_eq(_kas("min-request-timeout"), "3600")']], kas_set("min-request-timeout", ["60"])),
    kas("1.2.23", "service-account-lookup", "kube-apiserver service-account-lookup must be true when given",
        [['_absent_or_true(_kas("service-account-lookup"))']], kas_set("service-account-lookup", ["false"])),
    kas("1.2.24", "service-account-key-file", "kube-apiserver serviceAccountPublicKeyFiles must list the sa-token-signing-certs and bound-sa-token-signing-certs directories",
        [['l := _obj("kube_apiserver_config").serviceAccountPublicKeyFiles', "is_array(l)",
          f'"{SP}/configmaps/sa-token-signing-certs" in l', f'"{SP}/configmaps/bound-sa-token-signing-certs" in l']],
        add("/openshift/kube_apiserver_config/serviceAccountPublicKeyFiles", [f"{SP}/configmaps/sa-token-signing-certs"])),
    kas("1.2.25", "etcd-certfile", "kube-apiserver etcd-certfile and etcd-keyfile must be the cluster-managed etcd-client pair",
        [[f'_all_eq(_kas("etcd-certfile"), "{SP}/secrets/etcd-client/tls.crt")',
          f'_all_eq(_kas("etcd-keyfile"), "{SP}/secrets/etcd-client/tls.key")']], kas_set("etcd-keyfile", [])),
    kas("1.2.26", "tls-cert-file", "kube-apiserver tls-cert-file and tls-private-key-file must be the service-network-serving-certkey pair",
        [[f'_all_eq(_kas("tls-cert-file"), "{SPC}/secrets/service-network-serving-certkey/tls.crt")',
          f'_all_eq(_kas("tls-private-key-file"), "{SPC}/secrets/service-network-serving-certkey/tls.key")']],
        kas_set("tls-cert-file", ["/tmp/other.crt"])),
    kas("1.2.27", "client-ca-file", "kube-apiserver client-ca-file (or servingInfo.clientCA) must be the cluster-managed client-ca bundle",
        [[f'"{SPC}/configmaps/client-ca/ca-bundle.crt" in _kas("client-ca-file")'],
         [f'_obj("kube_apiserver_config").servingInfo.clientCA == "{SPC}/configmaps/client-ca/ca-bundle.crt"']],
        kas_set("client-ca-file", ["/tmp/ca.crt"])),
    kas("1.2.28", "etcd-cafile", "kube-apiserver etcd-cafile must be the etcd-serving-ca bundle",
        [[f'_all_eq(_kas("etcd-cafile"), "{SP}/configmaps/etcd-serving-ca/ca-bundle.crt")']], kas_set("etcd-cafile", [])),
    fact("1.2.29", "encryption providers", "the OpenShift API server Encrypted condition must report EncryptionCompleted",
         ['_collected("openshiftapiserver")'], "openshift.openshiftapiserver",
         [['some c in _obj("openshiftapiserver").status.conditions', 'c.type == "Encrypted"', 'c.reason == "EncryptionCompleted"']],
         add("/openshift/openshiftapiserver/status/conditions/0/reason", "EncryptionInProgress"), rm("/openshift/openshiftapiserver")),
    fact("1.2.30", "strong cryptographic ciphers", "the TLS security profile must not be Old and the API servers, OAuth server and default ingress must require TLS 1.2 or later",
         ['_collected("apiserver")', '_collected("kubeapiserver")', '_collected("openshiftapiserver")',
          '_collected("authentication_cliconfig")', '_collected("ingresscontroller_default")'],
         "openshift.apiserver, kubeapiserver, openshiftapiserver, authentication_cliconfig and ingresscontroller_default",
         [["_tls_profile_ok", '_tls_ok(_obj("authentication_cliconfig").servingInfo.minTLSVersion)',
           '_tls_ok(_obj("kubeapiserver").spec.observedConfig.servingInfo.minTLSVersion)',
           '_tls_ok(_obj("openshiftapiserver").spec.observedConfig.servingInfo.minTLSVersion)',
           '_tls_ok(_obj("ingresscontroller_default").status.tlsProfile.minTLSVersion)']],
         add("/openshift/apiserver/spec/tlsSecurityProfile", {"type": "Old", "old": {}}), rm("/openshift/ingresscontroller_default")),
    fact("1.2.31", "unsupported configuration overrides", "the kube-apiserver operator must carry no unsupportedConfigOverrides",
         ['_collected("kubeapiserver")'], "openshift.kubeapiserver",
         [['object.get(_obj("kubeapiserver"), ["spec", "unsupportedConfigOverrides"], null) == null']],
         add("/openshift/kubeapiserver/spec/unsupportedConfigOverrides", {"apiServerArguments": {"x": ["y"]}}), rm("/openshift/kubeapiserver")),
    # ── 1.3 controller manager, 1.4 scheduler ──────────────────────────────────────────────────────────────
    fact("1.3.1", "controller manager healthz", "the kube-controller-manager probes must use healthz and its metrics endpoint must refuse unauthenticated and unprivileged requests",
         ['_probe("kube_controller_manager")', '_collected("kube_controller_manager_pod")'],
         "openshift.metrics_probes.kube_controller_manager and openshift.kube_controller_manager_pod",
         [[probe("kube_controller_manager"), '_probes_healthz("kube_controller_manager_pod", "kube-controller-manager")']],
         add("/openshift/metrics_probes/kube_controller_manager/service_account", 200), rm("/openshift/kube_controller_manager_pod")),
    kcm("1.3.2", "use-service-account-credentials", "kube-controller-manager use-service-account-credentials must be true",
        [['_all_true(_kcm("use-service-account-credentials"))']],
        add("/openshift/kube_controller_manager_config/extendedArguments/use-service-account-credentials", ["false"])),
    kcm("1.3.3", "service-account-private-key-file", "kube-controller-manager service-account-private-key-file must be the cluster-managed key",
        [[f'_all_eq(_kcm("service-account-private-key-file"), "{SP}/secrets/service-account-private-key/service-account.key")']],
        rm("/openshift/kube_controller_manager_config/extendedArguments/service-account-private-key-file")),
    kcm("1.3.4", "root-ca-file", "kube-controller-manager root-ca-file must be the serviceaccount-ca bundle",
        [[f'_all_eq(_kcm("root-ca-file"), "{SP}/configmaps/serviceaccount-ca/ca-bundle.crt")']],
        add("/openshift/kube_controller_manager_config/extendedArguments/root-ca-file", ["/tmp/ca.crt"])),
    fact("1.4.1", "healthz endpoints for the scheduler", "the kube-scheduler probes must use healthz and its metrics endpoint must refuse unauthenticated and unprivileged requests",
         ['_probe("kube_scheduler")', '_collected("kube_scheduler_pod")'],
         "openshift.metrics_probes.kube_scheduler and openshift.kube_scheduler_pod",
         [[probe("kube_scheduler"), '_probes_healthz("kube_scheduler_pod", "kube-scheduler")']],
         add("/openshift/metrics_probes/kube_scheduler/cluster_admin", 403), rm("/openshift/metrics_probes/kube_scheduler")),
    fact("1.4.2", "scheduler api service", "kube-scheduler must run without bind-address or port arguments and its pod-IP metrics endpoint must refuse unauthenticated and unprivileged requests",
         ['_probe("kube_scheduler_pod_ip")', '_collected("kube_scheduler_pod")'],
         "openshift.metrics_probes.kube_scheduler_pod_ip and openshift.kube_scheduler_pod",
         [[probe("kube_scheduler_pod_ip"), "_scheduler_no_bind_or_port"]],
         add("/openshift/kube_scheduler_pod/spec/containers/0/args/-", "--port=10251"), rm("/openshift/kube_scheduler_pod")),
]

C2_5 = [
    # ── 2 etcd (each member's command line) ────────────────────────────────────────────────────────────────
    etcd("2.1", "--cert-file", "every etcd member must be started with --cert-file and --key-file",
         '_m_nonempty(m, "cert-file"); _m_nonempty(m, "key-file")', eflag("key-file", "")),
    etcd("2.2", "--client-cert-auth", "every etcd member must run with --client-cert-auth=true",
         '_m_true(m, "client-cert-auth")', eflag("client-cert-auth", "false")),
    etcd("2.3", "--auto-tls", "etcd members must not run with --auto-tls=true",
         '_m_not_true(m, "auto-tls")', eflag("auto-tls", "true")),
    etcd("2.4", "--peer-cert-file", "every etcd member must be started with --peer-cert-file and --peer-key-file",
         '_m_nonempty(m, "peer-cert-file"); _m_nonempty(m, "peer-key-file")', eflag("peer-cert-file", " ")),
    etcd("2.5", "--peer-client-cert-auth", "every etcd member must run with --peer-client-cert-auth=true",
         '_m_true(m, "peer-client-cert-auth")', eflag("peer-client-cert-auth", "False")),
    etcd("2.6", "--peer-auto-tls", "etcd members must not run with --peer-auto-tls=true",
         '_m_not_true(m, "peer-auto-tls")', eflag("peer_auto_tls", "TRUE")),
    etcd("2.7", "unique certificate authority", "every etcd member must trust the etcd-serving-ca bundle for clients and the etcd-peer-client-ca bundle for peers",
         f'_m_is(m, "trusted-ca-file", "{SPC}/configmaps/etcd-serving-ca/ca-bundle.crt"); '
         f'_m_is(m, "peer-trusted-ca-file", "{SPC}/configmaps/etcd-peer-client-ca/ca-bundle.crt")',
         eflag("trusted-ca-file", f"{SPC}/configmaps/client-ca/ca-bundle.crt")),
    # ── 3 control plane configuration ──────────────────────────────────────────────────────────────────────
    fact("3.1.1", "client certificate authentication", "users must sign in through a configured identity provider: one or more identity providers, a User bound to cluster-admin, and no kubeadmin secret",
         ["is_array(input.oauth.identity_providers)", "is_boolean(input.cluster.kubeadmin_user_exists)",
          "is_array(input.openshift.cluster_admin_bindings)", 'input.collection_status.cluster_admin_bindings == "ok"'],
         "oauth.identity_providers, cluster.kubeadmin_user_exists and openshift.cluster_admin_bindings",
         [["count(input.oauth.identity_providers) > 0", "input.cluster.kubeadmin_user_exists == false",
           "some cb in input.openshift.cluster_admin_bindings", "some s in cb.subjects", 's.kind == "User"']],
         add("/oauth/identity_providers", []), rm("/oauth")),
    fact("3.2.1", "minimal audit policy", "the API server audit profile must not be None, audit logs must be returned for both API servers, and the audit configuration must be attested as reviewed (attest.audit_retention_reviewed)",
         ["is_string(input.api_server.audit_profile)", "is_object(input.openshift.audit_logs)"],
         "api_server.audit_profile and openshift.audit_logs",
         [['input.api_server.audit_profile != "None"', "input.openshift.audit_logs.kube_apiserver_node_logs == true",
           "input.openshift.audit_logs.openshift_apiserver_node_logs == true", "input.attest.audit_retention_reviewed == true"]],
         add("/api_server/audit_profile", "None"), rm("/api_server/audit_profile"), needs_attest=["audit_retention_reviewed"]),
    att("3.2.2", "key security concerns", "the audit policies must be reviewed against the security events they have to record", "audit_policy_coverage_reviewed"),
    # ── 4.1 worker node configuration files (stat on every node) ───────────────────────────────────────────
    gmode("4.1.1", "kubelet service file permissions", "kubelet.service mode must be 644 or stricter on every node", "kubelet_service", "644"),
    gown("4.1.2", "kubelet service file ownership", "kubelet.service must be owned by root:root on every node", "kubelet_service"),
    fact("4.1.3", "kube proxy configuration", "kube-proxy-config.yaml in the sdn pods must be mode 644 or stricter while kube-proxy runs there",
         ["_kube_proxy_files_collected"],
         "kube_proxy.running (and files.kube_proxy_kubeconfig when it runs)",
         [["input.kube_proxy.running == false"],
          ["input.kube_proxy.running == true", 'every f in _files("kube_proxy_kubeconfig") { mode_within(f.mode, "644") }']],
         add("/files/kube_proxy_kubeconfig/0/mode", "0666"), rm("/kube_proxy/running")),
    fact("4.1.4", "proxy kubeconfig", "kube-proxy-config.yaml in the sdn pods must be owned by root:root while kube-proxy runs there",
         ["_kube_proxy_files_collected"],
         "kube_proxy.running (and files.kube_proxy_kubeconfig when it runs)",
         [["input.kube_proxy.running == false"],
          ["input.kube_proxy.running == true", 'every f in _files("kube_proxy_kubeconfig") { _owned(f, "root", "root") }']],
         add("/files/kube_proxy_kubeconfig/0/owner", "nobody"), rm("/files/kube_proxy_kubeconfig")),
    gmode("4.1.5", "kubelet.conf file permissions", "/etc/kubernetes/kubelet.conf mode must be 644 or stricter on every node", "kubelet_kubeconfig", "644"),
    gown("4.1.6", "kubelet.conf file ownership", "/etc/kubernetes/kubelet.conf must be owned by root:root on every node", "kubelet_kubeconfig"),
    gmode("4.1.7", "certificate authorities file permissions", "the kubelet client CA file mode must be 644 or stricter on every node", "kubelet_client_ca", "644"),
    gown("4.1.8", "certificate authorities file ownership", "the kubelet client CA file must be owned by root:root on every node", "kubelet_client_ca"),
    gmode("4.1.9", "configuration file has permissions", "the kubelet config.json mode must be 600 or stricter on every node", "kubelet_config_yaml", "600"),
    gown("4.1.10", "configuration file ownership", "the kubelet config.json must be owned by root:root on every node", "kubelet_config_yaml"),
    # ── 4.2 kubelet (configz of every node) ────────────────────────────────────────────────────────────────
    att("4.2.1", "garbage collection", "kubelet eviction and image garbage collection thresholds must be reviewed as suited to the nodes", "kubelet_garbage_collection_reviewed"),
    node("4.2.2", "--anonymous-auth", "kubelet anonymous authentication must be off on every node (authentication.anonymous.enabled)",
         "n.config.authentication.anonymous.enabled == false", ncfg("authentication/anonymous/enabled", True)),
    node("4.2.3", "alwaysallow", "kubelet authorization.mode must be given and must not be AlwaysAllow on any node",
         "_nonempty(n.config.authorization.mode); n.config.authorization.mode != \"AlwaysAllow\"", ncfg("authorization/mode", "AlwaysAllow")),
    node("4.2.4", "--client-ca-file", "kubelet authentication.x509.clientCAFile must be /etc/kubernetes/kubelet-ca.crt on every node",
         'n.config.authentication.x509.clientCAFile == "/etc/kubernetes/kubelet-ca.crt"', ncfg("authentication/x509/clientCAFile", "")),
    kas("4.2.5", "read only port", "kube-apiserver kubelet-read-only-port must be 0",
        [['l := _kas("kubelet-read-only-port")', "count(l) > 0", "every x in l { trim_space(x) == \"0\" }"]],
        kas_set("kubelet-read-only-port", ["10255"])),
    node("4.2.6", "--streaming-connection-idle-timeout", "kubelet streamingConnectionIdleTimeout must not be 0 on any node",
         "_idle_ok(n.config)", ncfg("streamingConnectionIdleTimeout", "0s")),
    node("4.2.7", "--make-iptables-util-chains", "kubelet makeIPTablesUtilChains must be true on every node",
         "n.config.makeIPTablesUtilChains == true", ncfg("makeIPTablesUtilChains", False)),
    att("4.2.8", "kubeapiqps", "kubelet kubeAPIQPS must be reviewed as suited to the cluster's event volume", "kubelet_kube_api_qps_reviewed"),
    kas("4.2.9", "--tls-cert-file", "kube-apiserver kubelet-client-certificate and kubelet-client-key must include the kubelet-client pair",
        [[f'"{SPC}/secrets/kubelet-client/tls.crt" in _kas("kubelet-client-certificate")',
          f'"{SPC}/secrets/kubelet-client/tls.key" in _kas("kubelet-client-key")']],
        kas_set("kubelet-client-key", ["/tmp/k.key"])),
    node("4.2.10", "--rotate-certificates", "kubelet rotateCertificates must be true on every node",
         "n.config.rotateCertificates == true", ncfg("rotateCertificates", False)),
    node("4.2.11", "rotatekubeletservercertificate", "kubelet featureGates.RotateKubeletServerCertificate and rotateCertificates must be true on every node",
         "n.config.featureGates.RotateKubeletServerCertificate == true; n.config.rotateCertificates == true",
         ncfg("featureGates/RotateKubeletServerCertificate", False)),
    fact("4.2.12", "strong cryptographic ciphers", "the API servers, OAuth server and default ingress must offer only strong cipher suites",
         ['_collected("kubeapiserver")', '_collected("openshiftapiserver")', '_collected("authentication_cliconfig")',
          '_collected("ingresscontroller_default")'],
         "openshift.kubeapiserver, openshiftapiserver, authentication_cliconfig and ingresscontroller_default",
         [['_suites_strong(_obj("kubeapiserver").spec.observedConfig.servingInfo.cipherSuites)',
           '_suites_strong(_obj("openshiftapiserver").spec.observedConfig.servingInfo.cipherSuites)',
           '_suites_strong(_obj("authentication_cliconfig").servingInfo.cipherSuites)',
           'l := _obj("ingresscontroller_default").status.tlsProfile.ciphers', "is_array(l)", "count(l) > 0",
           "every s in l { s in _strong_openssl }"]],
         add("/openshift/ingresscontroller_default/status/tlsProfile/ciphers/-", "DHE-RSA-AES128-GCM-SHA256"),
         rm("/openshift/authentication_cliconfig")),
    # ── 5 policies ─────────────────────────────────────────────────────────────────────────────────────────
    fact("5.1.1", "cluster-admin", "the kubeadmin secret must be removed and every cluster-admin binding must be attested as needed (attest.cluster_admin_bindings_reviewed)",
         ["is_boolean(input.cluster.kubeadmin_user_exists)"], "cluster.kubeadmin_user_exists",
         [["input.cluster.kubeadmin_user_exists == false", "input.attest.cluster_admin_bindings_reviewed == true"]],
         add("/cluster/kubeadmin_user_exists", True), rm("/cluster/kubeadmin_user_exists"), needs_attest=["cluster_admin_bindings_reviewed"]),
    att("5.1.2", "secrets", "get, list and watch rights on Secrets must be reviewed and kept small", "secret_access_reviewed"),
    att("5.1.3", "wildcard", "wildcards in Role and ClusterRole rules must be reviewed and kept small", "rbac_wildcards_reviewed"),
    att("5.1.4", "create pods", "the right to create Pods must be reviewed and kept small", "pod_create_access_reviewed"),
    att("5.1.5", "default service accounts", "workloads must not run under a project's default ServiceAccount except where reviewed", "default_service_accounts_not_used"),
    att("5.1.6", "tokens are only mounted", "Pods and ServiceAccounts that mount an API token must be reviewed as needing it", "service_account_token_mounts_reviewed"),
    scc("5.2.1", "privileged containers", "one or more SCCs must refuse privileged containers", "s.allowPrivilegedContainer == false",
        "allowPrivilegedContainer", True),
    scc("5.2.2", "host process id", "one or more SCCs must refuse the host PID namespace (allowHostPID false)", "s.allowHostPID == false",
        "allowHostPID", True),
    scc("5.2.3", "host ipc", "one or more SCCs must refuse the host IPC namespace", "s.allowHostIPC == false", "allowHostIPC", True),
    scc("5.2.4", "host network", "one or more SCCs must refuse the host network namespace", "s.allowHostNetwork == false",
        "allowHostNetwork", True),
    scc("5.2.5", "allowprivilegeescalation", "one or more SCCs must set allowPrivilegeEscalation to false", "s.allowPrivilegeEscalation == false",
        "allowPrivilegeEscalation", True),
    scc("5.2.6", "root containers", "one or more SCCs must require MustRunAsNonRoot", 's.runAsUser.type == "MustRunAsNonRoot"',
        "runAsUser", {"type": "RunAsAny"}),
    scc("5.2.7", "net_raw", "one or more SCCs must drop ALL capabilities", '"ALL" in s.requiredDropCapabilities',
        "requiredDropCapabilities", ["KILL"]),
    fact("5.2.8", "added capabilities", "one or more SCCs must allow no added capabilities and one or more must add none by default",
         SCC_EV, SCC_LABEL,
         [["some s1 in input.scc.items", 'object.get(s1, "allowedCapabilities", null) == null',
           "some s2 in input.scc.items", 'object.get(s2, "defaultAddCapabilities", null) == null']],
         [op for i in range(3) for op in add(f"/scc/items/{i}/allowedCapabilities", ["NET_BIND_SERVICE"])], SCC_MISS),
    scc("5.2.9", "capabilities assigned", "one or more SCCs must drop ALL capabilities from containers", '"ALL" in s.requiredDropCapabilities',
        "requiredDropCapabilities", []),
    att("5.2.10", "privileged security context", "users and groups with access to privileged or host-level SCCs must be reviewed as needing it", "privileged_scc_access_reviewed"),
    att("5.3.1", "supports network policies", "the cluster network plugin must be confirmed to enforce ingress and egress NetworkPolicy", "cni_enforces_network_policies"),
    fact("5.3.2", "network policies defined", "every namespace must have at least one NetworkPolicy",
         ["is_array(input.network_policies.namespaces_without_policy)", 'input.collection_status.network_policies == "ok"'],
         "network_policies.namespaces_without_policy / collection_status.network_policies",
         [["count(input.network_policies.namespaces_without_policy) == 0"]],
         add("/network_policies/namespaces_without_policy/-", "payments"), rm("/collection_status/network_policies")),
    fact("5.4.1", "environment variables", "workloads must not read Secrets through environment variables",
         ["is_number(input.secrets.env_var_usage_count)", 'input.collection_status.secret_env_scan == "ok"'],
         "secrets.env_var_usage_count / collection_status.secret_env_scan",
         [["input.secrets.env_var_usage_count == 0"]],
         add("/secrets/env_var_usage_count", 3), rm("/secrets")),
    att("5.4.2", "external secret storage", "an external secret store must be evaluated and the decision recorded", "external_secret_storage_reviewed"),
    fact("5.5.1", "image provenance", "image.config registrySources must be set and attested as appropriate (attest.image_provenance_reviewed)",
         ['_collected("image_config")'], "openshift.image_config",
         [['rs := _obj("image_config").spec.registrySources', "is_object(rs)", "count(rs) > 0",
           "input.attest.image_provenance_reviewed == true"]],
         rm("/openshift/image_config/spec/registrySources"), rm("/openshift/image_config"), needs_attest=["image_provenance_reviewed"]),
    att("5.7.1", "administrative boundaries", "the non-system namespaces must be reviewed as the administrative boundaries in use", "namespace_boundaries_reviewed"),
    fact("5.7.2", "seccomp profile", "every non-system pod must set a pod seccompProfile",
         ["is_array(input.openshift.pods_without_seccomp_profile)", 'input.collection_status.pod_seccomp == "ok"'],
         "openshift.pods_without_seccomp_profile / collection_status.pod_seccomp",
         [["count(input.openshift.pods_without_seccomp_profile) == 0"]],
         add("/openshift/pods_without_seccomp_profile/-", "payments/api-0"), rm("/collection_status/pod_seccomp")),
    att("5.7.3", "security context", "pods on the privileged SCC or on no SCC must be reviewed", "pod_security_contexts_reviewed"),
    fact("5.7.4", "default namespace", "the default namespace must hold nothing but the kubernetes and openshift Services",
         ['is_array(input.cluster.namespace_resources["default"])', 'input.collection_status.namespace_resources == "ok"'],
         "cluster.namespace_resources.default / collection_status.namespace_resources",
         [['every r in input.cluster.namespace_resources["default"] { _default_ns_allowed(r) }']],
         add("/cluster/namespace_resources/default/-", "pod/debug"), rm("/collection_status/namespace_resources")),
]


def _idkey(c):
    return [int(p) for p in c["id"].split(".")]


C = sorted(C1 + C2_5, key=_idkey)


def f(path, mode, owner="root"):
    return {"path": path, "mode": mode, "owner": owner, "group": owner}


def member(name):
    dns = f"{name}.example.internal"
    return {"name": name, "flags": {
        "cert-file": f"{SPC}/secrets/etcd-all-serving/etcd-serving-{dns}.crt",
        "key-file": f"{SPC}/secrets/etcd-all-serving/etcd-serving-{dns}.key",
        "client-cert-auth": "true",
        "peer-cert-file": f"{SPC}/secrets/etcd-all-peer/etcd-peer-{dns}.crt",
        "peer-key-file": f"{SPC}/secrets/etcd-all-peer/etcd-peer-{dns}.key",
        "peer-client-cert-auth": "true",
        "trusted-ca-file": f"{SPC}/configmaps/etcd-serving-ca/ca-bundle.crt",
        "peer-trusted-ca-file": f"{SPC}/configmaps/etcd-peer-client-ca/ca-bundle.crt",
        "data-dir": "/var/lib/etcd"}}


def kubelet_node(name):
    return {"name": name, "config": {
        # only what a recommendation reads: no authentication.webhook (4.2.2 reads anonymous.enabled) and no
        # kubeAPIQPS (4.2.8 is a manual review decided by its attestation)
        "authentication": {"anonymous": {"enabled": False}, "x509": {"clientCAFile": "/etc/kubernetes/kubelet-ca.crt"}},
        "authorization": {"mode": "Webhook"}, "streamingConnectionIdleTimeout": "4h0m0s",
        "makeIPTablesUtilChains": True, "rotateCertificates": True,
        "featureGates": {"RotateKubeletServerCertificate": True}}}


def sccobj(name, **kw):
    base = {"metadata": {"name": name}, "allowPrivilegedContainer": True, "allowHostPID": True, "allowHostIPC": True,
            "allowHostNetwork": True, "allowPrivilegeEscalation": True, "runAsUser": {"type": "RunAsAny"},
            "requiredDropCapabilities": None, "allowedCapabilities": ["*"], "defaultAddCapabilities": None}
    base.update(kw)
    return base


TLS = {"minTLSVersion": "VersionTLS12", "cipherSuites": ["TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                                         "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"]}
GREEN = {
    "openshift": {
        "kube_apiserver_config": {
            "apiServerArguments": {
                "kubelet-client-certificate": [f"{SPC}/secrets/kubelet-client/tls.crt"],
                "kubelet-client-key": [f"{SPC}/secrets/kubelet-client/tls.key"],
                "kubelet-certificate-authority": [f"{SP}/configmaps/kubelet-serving-ca/ca-bundle.crt"],
                "authorization-mode": ["Scope", "SystemMasters", "RBAC", "Node"],
                "enable-admission-plugins": ["NamespaceLifecycle", "NodeRestriction", "ServiceAccount",
                                             "security.openshift.io/SecurityContextConstraint"],
                "audit-log-path": ["/var/log/kube-apiserver/audit.log"],
                "audit-log-maxbackup": ["10"], "audit-log-maxsize": ["100"], "min-request-timeout": ["3600"],
                "etcd-certfile": [f"{SP}/secrets/etcd-client/tls.crt"], "etcd-keyfile": [f"{SP}/secrets/etcd-client/tls.key"],
                "tls-cert-file": [f"{SPC}/secrets/service-network-serving-certkey/tls.crt"],
                "tls-private-key-file": [f"{SPC}/secrets/service-network-serving-certkey/tls.key"],
                "client-ca-file": [f"{SPC}/configmaps/client-ca/ca-bundle.crt"],
                "etcd-cafile": [f"{SP}/configmaps/etcd-serving-ca/ca-bundle.crt"],
                "kubelet-read-only-port": ["0"],
            },
            "serviceAccountPublicKeyFiles": [f"{SP}/configmaps/sa-token-signing-certs",
                                             f"{SP}/configmaps/bound-sa-token-signing-certs"],
        },
        "openshift_apiserver_config": {"apiServerArguments": {"audit-log-path": ["/var/log/openshift-apiserver/audit.log"]}},
        "kube_controller_manager_config": {"extendedArguments": {
            "use-service-account-credentials": ["true"],
            "service-account-private-key-file": [f"{SP}/secrets/service-account-private-key/service-account.key"],
            "root-ca-file": [f"{SP}/configmaps/serviceaccount-ca/ca-bundle.crt"]}},
        "kube_controller_manager_pod": {"spec": {"containers": [
            # the probe path is what 1.3.x / 1.4.x read; the probe port is not, so the fixture does not carry it
            {"name": "kube-controller-manager", "livenessProbe": {"httpGet": {"path": "healthz"}},
             "readinessProbe": {"httpGet": {"path": "healthz"}}}]}},
        "kube_scheduler_pod": {"spec": {"containers": [
            {"name": "kube-scheduler", "command": ["hyperkube", "kube-scheduler"],
             "args": ["--config=/etc/kubernetes/static-pod-resources/configmaps/config/config.yaml", "--v=2"],
             "livenessProbe": {"httpGet": {"path": "healthz"}},
             "readinessProbe": {"httpGet": {"path": "healthz"}}}]}},
        "kubeapiserver": {"spec": {"observedConfig": {
            "apiServerArguments": {"feature-gates": ["APIPriorityAndFairness=true", "RotateKubeletServerCertificate=true"]},
            "servingInfo": dict(TLS, bindAddress="0.0.0.0:6443")}}},
        "openshiftapiserver": {"spec": {"observedConfig": {"servingInfo": TLS}},
                               "status": {"conditions": [{"type": "Encrypted", "reason": "EncryptionCompleted"}]}},
        "apiserver": {"spec": {"tlsSecurityProfile": {"type": "Intermediate", "intermediate": {}}}},
        "ingresscontroller_default": {"status": {"tlsProfile": {"minTLSVersion": "VersionTLS12",
                                                                "ciphers": ["TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"]}}},
        "authentication_cliconfig": {"servingInfo": TLS},
        "image_config": {"spec": {"registrySources": {"allowedRegistries": ["registry.redhat.io", "quay.io"]}}},
        "openshift_apiserver_serving_cert": {"type": "kubernetes.io/tls", "data_keys": ["tls.crt", "tls.key"]},
        "kube_apiserver_endpoint_ports": [6443, 6443, 6443],
        "openshift_apiserver_endpoint_ports": [8443],
        "kube_apiserver_container_ports": [6443],
        "metrics_probes": {c: {"unauthenticated": 403, "service_account": 403, "cluster_admin": 200}
                           for c in ("kube_apiserver", "kube_controller_manager", "kube_scheduler", "kube_scheduler_pod_ip")},
        "audit_logs": {"kube_apiserver_file_present": True, "openshift_apiserver_file_present": True,
                       "kube_apiserver_node_logs": True, "openshift_apiserver_node_logs": True},
        "unauthenticated_cluster_role_bindings": ["system:public-info-viewer", "system:webhooks"],
        "cluster_admin_bindings": [{"name": "platform-admins", "subjects": [{"kind": "User", "name": "alice"}]}],
        "pods_without_seccomp_profile": [],
    },
    "etcd": {"members": [member("master-0"), member("master-1"), member("master-2")]},
    "kubelet": {"nodes": [kubelet_node("master-0"), kubelet_node("worker-0")]},
    "kube_proxy": {"running": True},
    "files": {
        "manifests": [f(f"{SP}/kube-apiserver-pod.yaml", "0600"), f(f"{SP}/kube-controller-manager-pod.yaml", "0600"),
                      f(f"{SP}/kube-scheduler-pod.yaml", "0600"), f("/etc/kubernetes/manifests/etcd-pod.yaml", "0600")],
        "cni": [f("/host/etc/cni/net.d/00-multus.conf", "0600")],
        "ovs": [f("/etc/openvswitch/conf.db", "0600", "openvswitch"), f("/run/openvswitch/ovs-vswitchd.pid", "0600", "openvswitch")],
        "etcd_data": [f("/var/lib/etcd/member", "0700")],
        "node_kubeconfig": [f("/etc/kubernetes/kubeconfig", "0600"), f("/etc/kubernetes/kubeconfig", "0600")],
        "scheduler_kubeconfig": [f(f"{SP}/configmaps/scheduler-kubeconfig/kubeconfig", "0600")],
        "controller_manager_kubeconfig": [f(f"{SP}/configmaps/controller-manager-kubeconfig/kubeconfig", "0600")],
        "pki": [f(f"{SPC}/secrets", "0755"), f(f"{SPC}/secrets/kubelet-client/tls.crt", "0600"),
                f(f"{SPC}/secrets/kubelet-client/tls.key", "0600")],
        "kubelet_service": [f("/etc/systemd/system/kubelet.service", "0644")],
        "kube_proxy_kubeconfig": [f("/config/kube-proxy-config.yaml", "0644")],
        "kubelet_kubeconfig": [f("/etc/kubernetes/kubelet.conf", "0644")],
        "kubelet_client_ca": [f("/etc/kubernetes/kubelet-ca.crt", "0644")],
        "kubelet_config_yaml": [f("/var/data/kubelet/config.json", "0600")],
    },
    "scc": {"items": [
        sccobj("privileged"),
        sccobj("restricted-v2", allowPrivilegedContainer=False, allowHostPID=False, allowHostIPC=False, allowHostNetwork=False,
               allowPrivilegeEscalation=False, runAsUser={"type": "MustRunAsRange"}, requiredDropCapabilities=["ALL"],
               allowedCapabilities=["NET_BIND_SERVICE"]),
        sccobj("nonroot-v2", allowPrivilegedContainer=False, allowHostPID=False, allowHostIPC=False, allowHostNetwork=False,
               allowPrivilegeEscalation=False, runAsUser={"type": "MustRunAsNonRoot"}, requiredDropCapabilities=["ALL"],
               allowedCapabilities=None),
    ]},
    "api_server": {"audit_profile": "Default"},
    "oauth": {"identity_providers": [{"type": "OpenID", "name": "corporate-idp"}]},
    "cluster": {"kubeadmin_user_exists": False, "namespace_resources": {"default": ["service/kubernetes", "service/openshift"]}},
    "network_policies": {"namespaces_without_policy": []},
    "secrets": {"env_var_usage_count": 0},
    "collection_status": {"network_policies": "ok", "secret_env_scan": "ok", "namespace_resources": "ok", "scc": "ok",
                          "cluster_admin_bindings": "ok", "unauthenticated_bindings": "ok", "pod_seccomp": "ok"},
}

EXTRA_TESTS = r'''# file modes are octal bit masks: 0460 is numerically below 0600 but grants group access
test_mode_is_a_bit_mask if {
	b.mode_within("0600", "600")
	b.mode_within("400", "600")
	not b.mode_within("0460", "600")
	not b.mode_within("4600", "600")
	not b.mode_within(600, "600")
	not b.mode_within("rw-------", "600")
}

test_1_1_1_group_readable_or_numeric_mode_fails if {
	_has_id(b.violations, "1.1.1") with input as _patched([{"op": "add", "path": "/files/manifests/0/mode", "value": "0460"}])
	_has_id(b.violations, "1.1.1") with input as _patched([{"op": "add", "path": "/files/manifests/0/mode", "value": 600}])
	not _has_id(b.violations, "1.1.1") with input as _patched([{"op": "add", "path": "/files/manifests/0/mode", "value": "400"}])
}

test_api_server_arguments_must_be_string_lists if {
	_has_id(b.violations, "1.2.20") with input as _patched([{"op": "add", "path": "/openshift/kube_apiserver_config/apiServerArguments/audit-log-maxbackup", "value": "10"}])
	_has_id(b.violations, "1.2.20") with input as _patched([{"op": "add", "path": "/openshift/kube_apiserver_config/apiServerArguments/audit-log-maxbackup", "value": [10]}])
	_has_id(b.violations, "1.2.20") with input as _patched([{"op": "add", "path": "/openshift/kube_apiserver_config/apiServerArguments/audit-log-maxbackup", "value": ["10", "3"]}])
	_has_id(b.violations, "1.2.8") with input as _patched([{"op": "add", "path": "/openshift/kube_apiserver_config/apiServerArguments", "value": "x"}])
}

test_absent_arguments if {
	# 1.2.8, 1.2.9 and 1.2.23 pass when the argument is absent; 1.2.10 does not
	vs := b.violations with input as _patched([{"op": "remove", "path": "/openshift/kube_apiserver_config/apiServerArguments/enable-admission-plugins"}])
	not _has_id(vs, "1.2.8")
	not _has_id(vs, "1.2.9")
	not _has_id(vs, "1.2.23")
	_has_id(vs, "1.2.10")
	not _has_id(b.violations, "1.2.23") with input as _patched([{"op": "add", "path": "/openshift/kube_apiserver_config/apiServerArguments/service-account-lookup", "value": ["true"]}])
	not _has_id(b.violations, "1.2.31") with input as _patched([{"op": "add", "path": "/openshift/kubeapiserver/spec/unsupportedConfigOverrides", "value": null}])
}

test_1_2_1_extra_unauthenticated_binding_needs_attestation if {
	ops := [{"op": "add", "path": "/openshift/unauthenticated_cluster_role_bindings/-", "value": "anonymous-admin"}]
	_has_id(b.violations, "1.2.1") with input as _patched(ops)
	ok := array.concat(ops, [{"op": "add", "path": "/attest/unauthenticated_bindings_reviewed", "value": true}])
	not _has_id(b.violations, "1.2.1") with input as _patched(ok)
}

test_1_2_7_absent_gate_passes if {
	not _has_id(b.violations, "1.2.7") with input as _patched([{"op": "remove", "path": "/openshift/kubeapiserver/spec/observedConfig/apiServerArguments/feature-gates"}])
	_has_id(b.violations, "1.2.7") with input as _patched([{"op": "add", "path": "/openshift/kubeapiserver/spec/observedConfig/apiServerArguments/feature-gates", "value": ["APIPriorityAndFairness=maybe"]}])
	_has_id(b.violations, "1.2.14") with input as _patched([{"op": "add", "path": "/openshift/kubeapiserver/spec/observedConfig/apiServerArguments/feature-gates", "value": ["InsecureBindAddress=true"]}])
}

test_1_2_30_tls_profiles if {
	not _has_id(b.violations, "1.2.30") with input as _patched([{"op": "remove", "path": "/openshift/apiserver/spec/tlsSecurityProfile"}])
	not _has_id(b.violations, "1.2.30") with input as _patched([{"op": "add", "path": "/openshift/apiserver/spec/tlsSecurityProfile", "value": {"type": "Custom", "custom": {"minTLSVersion": "VersionTLS13"}}}])
	_has_id(b.violations, "1.2.30") with input as _patched([{"op": "add", "path": "/openshift/apiserver/spec/tlsSecurityProfile", "value": {"type": "Custom", "custom": {"minTLSVersion": "VersionTLS11"}}}])
	_has_id(b.violations, "1.2.30") with input as _patched([{"op": "add", "path": "/openshift/authentication_cliconfig/servingInfo/minTLSVersion", "value": "VersionTLS10"}])
}

test_every_kubelet_node_must_pass if {
	_has_id(b.violations, "4.2.2") with input as _patched([{"op": "remove", "path": "/kubelet/nodes/1/config/authentication/anonymous"}])
	"4.2.2: evidence missing — kubelet.nodes[].config not collected" in b.violations with input as _patched([{"op": "add", "path": "/kubelet/nodes", "value": []}])
	_has_id(b.violations, "4.2.6") with input as _patched([{"op": "add", "path": "/kubelet/nodes/0/config/streamingConnectionIdleTimeout", "value": "0"}])
	not _has_id(b.violations, "4.2.6") with input as _patched([{"op": "remove", "path": "/kubelet/nodes/0/config/streamingConnectionIdleTimeout"}])
}

test_every_etcd_member_must_pass if {
	_has_id(b.violations, "2.2") with input as _patched([{"op": "remove", "path": "/etcd/members/2/flags/client-cert-auth"}])
	not _has_id(b.violations, "2.2") with input as _patched([{"op": "add", "path": "/etcd/members/2/flags/--client-cert-auth", "value": "True"}, {"op": "remove", "path": "/etcd/members/2/flags/client-cert-auth"}])
	# a flag under two spellings is ambiguous
	_has_id(b.violations, "2.2") with input as _patched([{"op": "add", "path": "/etcd/members/0/flags/client_cert_auth", "value": "true"}])
	_has_id(b.violations, "2.3") with input as _patched([{"op": "add", "path": "/etcd/members/0/flags/auto-tls", "value": "yes"}])
}

test_kube_proxy_not_running if {
	inp := json.patch(green, [{"op": "add", "path": "/kube_proxy/running", "value": false}, {"op": "remove", "path": "/files/kube_proxy_kubeconfig"}])
	count(b.violations) == 0 with input as inp
}

test_5_2_least_privileged_scc_needed if {
	inp := json.patch(green, [{"op": "add", "path": "/scc/items", "value": [{"metadata": {"name": "privileged"}, "allowPrivilegedContainer": true, "allowHostPID": true}]}])
	vs := b.violations with input as inp
	_has_id(vs, "5.2.1")
	_has_id(vs, "5.2.2")
	_has_id(vs, "5.2.5")
	not _has_id(vs, "5.2.8")
}

test_5_7_4_only_the_platform_services if {
	_has_id(b.violations, "5.7.4") with input as _patched([{"op": "add", "path": "/cluster/namespace_resources/default/-", "value": "service/openshift-apiserver"}])
	_has_id(b.violations, "5.7.4") with input as _patched([{"op": "add", "path": "/cluster/namespace_resources/default/-", "value": "service/kubernetes-dashboard"}])
	_has_id(b.violations, "5.7.4") with input as _patched([{"op": "add", "path": "/cluster/namespace_resources/default/-", "value": "deployment/kubernetes-dashboard"}])
}

test_composite_checks_need_their_attestation if {
	_has_id(b.violations, "3.2.1") with input as _patched([{"op": "remove", "path": "/attest/audit_retention_reviewed"}])
	_has_id(b.violations, "5.1.1") with input as _patched([{"op": "remove", "path": "/attest/cluster_admin_bindings_reviewed"}])
	_has_id(b.violations, "5.5.1") with input as _patched([{"op": "add", "path": "/attest/image_provenance_reviewed", "value": false}])
}

test_underscore_flag_spellings_are_the_same_flag if {
	# kube-scheduler args: --bind_address and --port are the flags the check refuses
	_has_id(b.violations, "1.4.2") with input as _patched([{"op": "add", "path": "/openshift/kube_scheduler_pod/spec/containers/0/args/-", "value": "--bind_address=0.0.0.0"}])
	_has_id(b.violations, "1.4.2") with input as _patched([{"op": "add", "path": "/openshift/kube_scheduler_pod/spec/containers/0/args/-", "value": "--port"}])
	not _has_id(b.violations, "1.4.2") with input as _patched([{"op": "add", "path": "/openshift/kube_scheduler_pod/spec/containers/0/args/-", "value": "--secure-port=10259"}])
	# apiServerArguments: an underscore key is the same argument, and two spellings are ambiguous
	_has_id(b.violations, "1.2.8") with input as _patched([{"op": "add", "path": "/openshift/kube_apiserver_config/apiServerArguments/enable_admission_plugins", "value": ["AlwaysAdmit"]}, {"op": "remove", "path": "/openshift/kube_apiserver_config/apiServerArguments/enable-admission-plugins"}])
	_has_id(b.violations, "1.2.9") with input as _patched([{"op": "add", "path": "/openshift/kube_apiserver_config/apiServerArguments/enable_admission_plugins", "value": ["NodeRestriction"]}])
	_has_id(b.violations, "1.2.23") with input as _patched([{"op": "add", "path": "/openshift/kube_apiserver_config/apiServerArguments/service_account_lookup", "value": ["false"]}])
	not _has_id(b.violations, "1.2.20") with input as _patched([{"op": "add", "path": "/openshift/kube_apiserver_config/apiServerArguments/audit_log_maxbackup", "value": ["10"]}, {"op": "remove", "path": "/openshift/kube_apiserver_config/apiServerArguments/audit-log-maxbackup"}])
	# extendedArguments and the operator's observed arguments
	_has_id(b.violations, "1.3.2") with input as _patched([{"op": "add", "path": "/openshift/kube_controller_manager_config/extendedArguments/use_service_account_credentials", "value": ["false"]}])
	_has_id(b.violations, "1.2.14") with input as _patched([{"op": "add", "path": "/openshift/kubeapiserver/spec/observedConfig/apiServerArguments/feature_gates", "value": ["InsecureBindAddress=true"]}, {"op": "remove", "path": "/openshift/kubeapiserver/spec/observedConfig/apiServerArguments/feature-gates"}])
	# etcd command lines
	_has_id(b.violations, "2.3") with input as _patched([{"op": "add", "path": "/etcd/members/0/flags/auto_tls", "value": "true"}])
}

test_metrics_probe_codes if {
	not _has_id(b.violations, "1.2.17") with input as _patched([{"op": "add", "path": "/openshift/metrics_probes/kube_apiserver/unauthenticated", "value": 401}])
	"1.2.17: evidence missing — openshift.metrics_probes.kube_apiserver not collected" in b.violations with input as _patched([{"op": "add", "path": "/openshift/metrics_probes/kube_apiserver/cluster_admin", "value": "200"}])
}
'''
