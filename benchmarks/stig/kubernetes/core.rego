# METADATA
# title: "DISA STIG — Kubernetes Security Technical Implementation Guide"
# custom:
#   class: security
#   framework: stig_kubernetes
#   source: disa
#   domains: [kubernetes, container]
#   coverage:
#     checks: 92
#     cited: 92
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package stig.kubernetes.core

# DISA STIG — Kubernetes Security Technical Implementation Guide
# V2R6 | Release: 6 Benchmark Date: 01 Apr 2026
# 92 rules — every rule in the catalog (18 CAT I): 84 machine-checked,
# 1 machine-checked plus an attestation, 7 attestation-only (DISA's check is a
# documentation review or human judgment). IDs/severities/titles verified against the
# DISA XCCDF on 2026-10-21 (tools/stig_generators/gen_k8s.py; regenerate, don't hand-edit).
# FAIL-CLOSED: a rule whose evidence is absent is Open with detail
# "<STIG-ID>: evidence missing — <field> not collected"; attestations are Open until
# input.attest.<key> is true. Input contract: gen_k8s.py docstring, summarised here:
#   Kubernetes input contract (one evaluation per control-plane node; kubelet facts are that node's).
#   Flag maps hold the flags as the component was started with them: name -> string value. Spellings are
#   normalised the way the components do ("--a_b" == "a-b"); a flag present under two spellings, or given
#   twice (collect it as a list), is ambiguous and fails its check. Booleans compare as the exact strings
#   "true"/"false"; --feature-gates entries are parsed like Go's strconv.ParseBool and any unparseable entry
#   for a checked gate fails. Config files are given as the component decodes them (typed YAML values).
#     input.api_server.flags[<flag>]           : string value of --<flag> from the kube-apiserver manifest
#     input.api_server.audit_policy            : parsed --audit-policy-file {apiVersion, kind, rules[{level, ...}]}
#     input.api_server.encryption_config       : parsed --encryption-provider-config
#                                                {resources: [{resources: ["secrets"], providers: ["aescbc", "identity"]}]}
#                                                (providers = provider names in file order)
#     input.controller_manager.flags / input.scheduler.flags / input.etcd.flags : manifest flags
#     input.kubelet.flags[<flag>]              : kubelet command-line args (ps -ef / systemd ExecStart), {} if none
#     input.kubelet.config                     : the KubeletConfiguration file (--config) as parsed YAML
#                                                (authentication.anonymous.enabled, authorization.mode,
#                                                authentication.x509.clientCAFile, readOnlyPort, staticPodPath,
#                                                featureGates, streamingConnectionIdleTimeout, tlsCertFile,
#                                                tlsPrivateKeyFile, protectKernelDefaults). Legacy flattened keys
#                                                authentication_anonymous_enabled / authorization_mode still accepted.
#     input.cluster.version                    : server version ("v1.30.2")
#     input.cluster.namespace_resources[<ns>]  : `kubectl get all` names for default / kube-public / kube-node-lease
#     input.cluster.dashboard_pods             : pods matching k8s-app=kubernetes-dashboard (list)
#     input.cluster.images                     : every container image ref running in the cluster (list)
#     input.kubectl.client_versions            : kubectl client version on the control plane and each node (list)
#     input.worker_nodes                       : [{name, sshd_active, sshd_enabled}]
#     input.workloads.user_pod_host_ports      : host ports used by pods in user namespaces (list of numbers)
#     input.secrets.env_var_usage_count        : number of secretKeyRef env vars in workloads (0 = none)
#     input.pod_security.policies              : PodSecurityPolicies (only read for clusters older than 1.25)
#     input.kube_proxy.running                 : bool
#     input.files.<group>                      : [{path, mode ("0644"), owner, group}] for groups manifests,
#                                                kubelet_config_file, kubelet_client_ca, kube_proxy_kubeconfig,
#                                                etcd_data, control_plane_confs, pki, kubelet_kubeconfig,
#                                                kubeadm_conf, kubelet_config_yaml
#     input.attest.<key>                       : organizational attestations (see each rule)
#   

import rego.v1

# ── shared helpers ─────────────────────────────────────────────────────────────────────────────
# evidence present: the value exists at the path (an explicit null counts as not collected)
_collected(path) if object.get(input, path, null) != null

_nonempty(s) if {
	is_string(s)
	trim_space(s) != ""
}

# ── flag lookup, robust to the ways one flag can be spelled ─────────────────────────────────────
# Components normalise flag names (pflag WordSepNormalizeFunc: "_" == "-"), so "basic_auth_file",
# "--basic-auth-file" and "basic-auth-file" are the same flag. A check reads a flag only when exactly one
# key normalises to its name; two spellings (or a repeated flag collected as a list) leave it undefined,
# so the check fails rather than passing on whichever spelling it happened to read.
_norm(k) := replace(trim_left(k, "-"), "_", "-")

_flag_count(flags, name) := count([k | some k in object.keys(flags); _norm(k) == name])

_flag(flags, name) := flags[k] if {
	ks := [k | some k in object.keys(flags); _norm(k) == name]
	count(ks) == 1
	k := ks[0]
}

_flag_or_empty(flags, name) := "" if _flag_count(flags, name) == 0

_flag_or_empty(flags, name) := v if {
	_flag_count(flags, name) == 1
	v := _flag(flags, name)
	is_string(v)
}

# comma-separated flag as a trimmed set ({} when unset; undefined when ambiguous or not a string)
_csv_set(flags, name) := {trim_space(x) | some x in split(_flag_or_empty(flags, name), ","); trim_space(x) != ""}

# --feature-gates "A=true,B=false": every entry for <name>, parsed the way Go's strconv.ParseBool does
# ("1", "t", "T", "TRUE", "true", "True" are true); anything else is "invalid" and fails the check.
_gate_vals(flags, name) := [_boolish(p) |
	some kv in split(_flag_or_empty(flags, "feature-gates"), ",")
	p := split(trim_space(kv), "=")
	trim_space(p[0]) == name
]

_boolish(p) := "true" if {
	count(p) == 2
	lower(trim_space(p[1])) in {"1", "t", "true"}
}

_boolish(p) := "false" if {
	count(p) == 2
	lower(trim_space(p[1])) in {"0", "f", "false"}
}

_boolish(p) := "invalid" if count(p) != 2

_boolish(p) := "invalid" if {
	count(p) == 2
	not lower(trim_space(p[1])) in {"0", "f", "false", "1", "t", "true"}
}

# the gate is never set to <val> (and never unparseable): unset passes
_gate_never(flags, name, val) if {
	vals := _gate_vals(flags, name)
	every v in vals {
		v != val
		v != "invalid"
	}
}

# the gate is set, and every entry for it is <val>
_gate_all(flags, name, val) if {
	vals := _gate_vals(flags, name)
	count(vals) > 0
	every v in vals {
		v == val
	}
}

# EncryptionConfiguration is first-match per resource: the first entry naming secrets (or a wildcard
# covering them) decides which provider writes Secrets.
_first_secrets_entry(resources) := resources[i] if {
	idx := [j | some j in numbers.range(0, count(resources) - 1); _covers_secrets(resources[j])]
	count(idx) > 0
	i := idx[0]
}

_covers_secrets(r) if {
	some n in r.resources
	n in {"secrets", "secrets.", "*.", "*.*"}
}

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

# CNTR-K8-000150 | V-242376 | CAT II | machine
missing_r_cntr_k8_000150 := [concat(".", p) | some p in [["controller_manager", "flags"]]; not _collected(p)]

default r_cntr_k8_000150 := false

r_cntr_k8_000150 if {
	count(missing_r_cntr_k8_000150) == 0
	_flag(input.controller_manager.flags, "tls-min-version") in {"VersionTLS12", "VersionTLS13"}
}

default detail_r_cntr_k8_000150 := ""

detail_r_cntr_k8_000150 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000150", concat(", ", missing_r_cntr_k8_000150)]) if count(missing_r_cntr_k8_000150) > 0

detail_r_cntr_k8_000150 := "CNTR-K8-000150: check failed — controller_manager.flags --tls-min-version must be one of VersionTLS12, VersionTLS13" if {
	count(missing_r_cntr_k8_000150) == 0
	not r_cntr_k8_000150
}

detail_r_cntr_k8_000150 := "CNTR-K8-000150: Not_a_Finding" if r_cntr_k8_000150

finding_r_cntr_k8_000150 := {
	"vuln_id": "V-242376",
	"stig_id": "CNTR-K8-000150",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Controller Manager must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000150,
	"detail": detail_r_cntr_k8_000150,
}

status_r_cntr_k8_000150 := "Not_a_Finding" if r_cntr_k8_000150

status_r_cntr_k8_000150 := "Open" if not r_cntr_k8_000150

# CNTR-K8-000160 | V-242377 | CAT II | machine
missing_r_cntr_k8_000160 := [concat(".", p) | some p in [["scheduler", "flags"]]; not _collected(p)]

default r_cntr_k8_000160 := false

r_cntr_k8_000160 if {
	count(missing_r_cntr_k8_000160) == 0
	_flag(input.scheduler.flags, "tls-min-version") in {"VersionTLS12", "VersionTLS13"}
}

default detail_r_cntr_k8_000160 := ""

detail_r_cntr_k8_000160 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000160", concat(", ", missing_r_cntr_k8_000160)]) if count(missing_r_cntr_k8_000160) > 0

detail_r_cntr_k8_000160 := "CNTR-K8-000160: check failed — scheduler.flags --tls-min-version must be one of VersionTLS12, VersionTLS13" if {
	count(missing_r_cntr_k8_000160) == 0
	not r_cntr_k8_000160
}

detail_r_cntr_k8_000160 := "CNTR-K8-000160: Not_a_Finding" if r_cntr_k8_000160

finding_r_cntr_k8_000160 := {
	"vuln_id": "V-242377",
	"stig_id": "CNTR-K8-000160",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Scheduler must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000160,
	"detail": detail_r_cntr_k8_000160,
}

status_r_cntr_k8_000160 := "Not_a_Finding" if r_cntr_k8_000160

status_r_cntr_k8_000160 := "Open" if not r_cntr_k8_000160

# CNTR-K8-000170 | V-242378 | CAT II | machine
missing_r_cntr_k8_000170 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_000170 := false

r_cntr_k8_000170 if {
	count(missing_r_cntr_k8_000170) == 0
	_flag(input.api_server.flags, "tls-min-version") in {"VersionTLS12", "VersionTLS13"}
}

default detail_r_cntr_k8_000170 := ""

detail_r_cntr_k8_000170 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000170", concat(", ", missing_r_cntr_k8_000170)]) if count(missing_r_cntr_k8_000170) > 0

detail_r_cntr_k8_000170 := "CNTR-K8-000170: check failed — api_server.flags --tls-min-version must be one of VersionTLS12, VersionTLS13" if {
	count(missing_r_cntr_k8_000170) == 0
	not r_cntr_k8_000170
}

detail_r_cntr_k8_000170 := "CNTR-K8-000170: Not_a_Finding" if r_cntr_k8_000170

finding_r_cntr_k8_000170 := {
	"vuln_id": "V-242378",
	"stig_id": "CNTR-K8-000170",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API Server must use TLS 1.2, at a minimum, to protect the confidentiality of sensitive data during electronic dissemination.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000170,
	"detail": detail_r_cntr_k8_000170,
}

status_r_cntr_k8_000170 := "Not_a_Finding" if r_cntr_k8_000170

status_r_cntr_k8_000170 := "Open" if not r_cntr_k8_000170

# CNTR-K8-000180 | V-242379 | CAT II | machine
missing_r_cntr_k8_000180 := [concat(".", p) | some p in [["etcd", "flags"]]; not _collected(p)]

default r_cntr_k8_000180 := false

r_cntr_k8_000180 if {
	count(missing_r_cntr_k8_000180) == 0
	_flag(input.etcd.flags, "auto-tls") == "false"
}

default detail_r_cntr_k8_000180 := ""

detail_r_cntr_k8_000180 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000180", concat(", ", missing_r_cntr_k8_000180)]) if count(missing_r_cntr_k8_000180) > 0

detail_r_cntr_k8_000180 := "CNTR-K8-000180: check failed — etcd.flags --auto-tls must be \"false\"" if {
	count(missing_r_cntr_k8_000180) == 0
	not r_cntr_k8_000180
}

detail_r_cntr_k8_000180 := "CNTR-K8-000180: Not_a_Finding" if r_cntr_k8_000180

finding_r_cntr_k8_000180 := {
	"vuln_id": "V-242379",
	"stig_id": "CNTR-K8-000180",
	"severity": "CAT II",
	"rule_title": "The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000180,
	"detail": detail_r_cntr_k8_000180,
}

status_r_cntr_k8_000180 := "Not_a_Finding" if r_cntr_k8_000180

status_r_cntr_k8_000180 := "Open" if not r_cntr_k8_000180

# CNTR-K8-000190 | V-242380 | CAT II | machine
missing_r_cntr_k8_000190 := [concat(".", p) | some p in [["etcd", "flags"]]; not _collected(p)]

default r_cntr_k8_000190 := false

r_cntr_k8_000190 if {
	count(missing_r_cntr_k8_000190) == 0
	_flag(input.etcd.flags, "peer-auto-tls") == "false"
}

default detail_r_cntr_k8_000190 := ""

detail_r_cntr_k8_000190 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000190", concat(", ", missing_r_cntr_k8_000190)]) if count(missing_r_cntr_k8_000190) > 0

detail_r_cntr_k8_000190 := "CNTR-K8-000190: check failed — etcd.flags --peer-auto-tls must be \"false\"" if {
	count(missing_r_cntr_k8_000190) == 0
	not r_cntr_k8_000190
}

detail_r_cntr_k8_000190 := "CNTR-K8-000190: Not_a_Finding" if r_cntr_k8_000190

finding_r_cntr_k8_000190 := {
	"vuln_id": "V-242380",
	"stig_id": "CNTR-K8-000190",
	"severity": "CAT II",
	"rule_title": "The Kubernetes etcd must use TLS to protect the confidentiality of sensitive data during electronic dissemination.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000190,
	"detail": detail_r_cntr_k8_000190,
}

status_r_cntr_k8_000190 := "Not_a_Finding" if r_cntr_k8_000190

status_r_cntr_k8_000190 := "Open" if not r_cntr_k8_000190

# CNTR-K8-000220 | V-242381 | CAT I | machine
missing_r_cntr_k8_000220 := [concat(".", p) | some p in [["controller_manager", "flags"]]; not _collected(p)]

default r_cntr_k8_000220 := false

r_cntr_k8_000220 if {
	count(missing_r_cntr_k8_000220) == 0
	_flag(input.controller_manager.flags, "use-service-account-credentials") == "true"
}

default detail_r_cntr_k8_000220 := ""

detail_r_cntr_k8_000220 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000220", concat(", ", missing_r_cntr_k8_000220)]) if count(missing_r_cntr_k8_000220) > 0

detail_r_cntr_k8_000220 := "CNTR-K8-000220: check failed — controller_manager.flags --use-service-account-credentials must be \"true\"" if {
	count(missing_r_cntr_k8_000220) == 0
	not r_cntr_k8_000220
}

detail_r_cntr_k8_000220 := "CNTR-K8-000220: Not_a_Finding" if r_cntr_k8_000220

finding_r_cntr_k8_000220 := {
	"vuln_id": "V-242381",
	"stig_id": "CNTR-K8-000220",
	"severity": "CAT I",
	"rule_title": "The Kubernetes Controller Manager must create unique service accounts for each work payload.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000220,
	"detail": detail_r_cntr_k8_000220,
}

status_r_cntr_k8_000220 := "Not_a_Finding" if r_cntr_k8_000220

status_r_cntr_k8_000220 := "Open" if not r_cntr_k8_000220

# CNTR-K8-000270 | V-242382 | CAT II | machine
missing_r_cntr_k8_000270 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_000270 := false

r_cntr_k8_000270 if {
	count(missing_r_cntr_k8_000270) == 0
	_nonempty(_flag(input.api_server.flags, "authorization-mode"))
	_list_has_all(_flag(input.api_server.flags, "authorization-mode"), ["Node", "RBAC"])
	modes := _csv_set(input.api_server.flags, "authorization-mode")
	not "AlwaysAllow" in modes
}

default detail_r_cntr_k8_000270 := ""

detail_r_cntr_k8_000270 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000270", concat(", ", missing_r_cntr_k8_000270)]) if count(missing_r_cntr_k8_000270) > 0

detail_r_cntr_k8_000270 := "CNTR-K8-000270: check failed — api_server --authorization-mode must include Node and RBAC and not AlwaysAllow" if {
	count(missing_r_cntr_k8_000270) == 0
	not r_cntr_k8_000270
}

detail_r_cntr_k8_000270 := "CNTR-K8-000270: Not_a_Finding" if r_cntr_k8_000270

finding_r_cntr_k8_000270 := {
	"vuln_id": "V-242382",
	"stig_id": "CNTR-K8-000270",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API Server must enable Node,RBAC as the authorization mode.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000270,
	"detail": detail_r_cntr_k8_000270,
}

status_r_cntr_k8_000270 := "Not_a_Finding" if r_cntr_k8_000270

status_r_cntr_k8_000270 := "Open" if not r_cntr_k8_000270

# CNTR-K8-000290 | V-242383 | CAT I | machine
missing_r_cntr_k8_000290 := [concat(".", p) | some p in [["cluster", "namespace_resources"]]; not _collected(p)]

default r_cntr_k8_000290 := false

r_cntr_k8_000290 if {
	count(missing_r_cntr_k8_000290) == 0
	_only_kubernetes_service(input.cluster.namespace_resources)
}

default detail_r_cntr_k8_000290 := ""

detail_r_cntr_k8_000290 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000290", concat(", ", missing_r_cntr_k8_000290)]) if count(missing_r_cntr_k8_000290) > 0

detail_r_cntr_k8_000290 := "CNTR-K8-000290: check failed — default, kube-public and kube-node-lease must hold nothing but service/kubernetes" if {
	count(missing_r_cntr_k8_000290) == 0
	not r_cntr_k8_000290
}

detail_r_cntr_k8_000290 := "CNTR-K8-000290: Not_a_Finding" if r_cntr_k8_000290

finding_r_cntr_k8_000290 := {
	"vuln_id": "V-242383",
	"stig_id": "CNTR-K8-000290",
	"severity": "CAT I",
	"rule_title": "User-managed resources must be created in dedicated namespaces.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000290,
	"detail": detail_r_cntr_k8_000290,
}

status_r_cntr_k8_000290 := "Not_a_Finding" if r_cntr_k8_000290

status_r_cntr_k8_000290 := "Open" if not r_cntr_k8_000290

# CNTR-K8-000300 | V-242384 | CAT II | machine
missing_r_cntr_k8_000300 := [concat(".", p) | some p in [["scheduler", "flags"]]; not _collected(p)]

default r_cntr_k8_000300 := false

r_cntr_k8_000300 if {
	count(missing_r_cntr_k8_000300) == 0
	_flag(input.scheduler.flags, "bind-address") == "127.0.0.1"
}

default detail_r_cntr_k8_000300 := ""

detail_r_cntr_k8_000300 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000300", concat(", ", missing_r_cntr_k8_000300)]) if count(missing_r_cntr_k8_000300) > 0

detail_r_cntr_k8_000300 := "CNTR-K8-000300: check failed — scheduler.flags --bind-address must be \"127.0.0.1\"" if {
	count(missing_r_cntr_k8_000300) == 0
	not r_cntr_k8_000300
}

detail_r_cntr_k8_000300 := "CNTR-K8-000300: Not_a_Finding" if r_cntr_k8_000300

finding_r_cntr_k8_000300 := {
	"vuln_id": "V-242384",
	"stig_id": "CNTR-K8-000300",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Scheduler must have secure binding.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000300,
	"detail": detail_r_cntr_k8_000300,
}

status_r_cntr_k8_000300 := "Not_a_Finding" if r_cntr_k8_000300

status_r_cntr_k8_000300 := "Open" if not r_cntr_k8_000300

# CNTR-K8-000310 | V-242385 | CAT II | machine
missing_r_cntr_k8_000310 := [concat(".", p) | some p in [["controller_manager", "flags"]]; not _collected(p)]

default r_cntr_k8_000310 := false

r_cntr_k8_000310 if {
	count(missing_r_cntr_k8_000310) == 0
	_flag(input.controller_manager.flags, "bind-address") == "127.0.0.1"
}

default detail_r_cntr_k8_000310 := ""

detail_r_cntr_k8_000310 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000310", concat(", ", missing_r_cntr_k8_000310)]) if count(missing_r_cntr_k8_000310) > 0

detail_r_cntr_k8_000310 := "CNTR-K8-000310: check failed — controller_manager.flags --bind-address must be \"127.0.0.1\"" if {
	count(missing_r_cntr_k8_000310) == 0
	not r_cntr_k8_000310
}

detail_r_cntr_k8_000310 := "CNTR-K8-000310: Not_a_Finding" if r_cntr_k8_000310

finding_r_cntr_k8_000310 := {
	"vuln_id": "V-242385",
	"stig_id": "CNTR-K8-000310",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Controller Manager must have secure binding.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000310,
	"detail": detail_r_cntr_k8_000310,
}

status_r_cntr_k8_000310 := "Not_a_Finding" if r_cntr_k8_000310

status_r_cntr_k8_000310 := "Open" if not r_cntr_k8_000310

# CNTR-K8-000330 | V-242387 | CAT I | machine
missing_r_cntr_k8_000330 := [concat(".", p) | some p in [["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_000330 := false

r_cntr_k8_000330 if {
	count(missing_r_cntr_k8_000330) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "read-only-port") == 0
	is_object(input.kubelet.config)
	object.get(input.kubelet.config, ["readOnlyPort"], 0) == 0
}

default detail_r_cntr_k8_000330 := ""

detail_r_cntr_k8_000330 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000330", concat(", ", missing_r_cntr_k8_000330)]) if count(missing_r_cntr_k8_000330) > 0

detail_r_cntr_k8_000330 := "CNTR-K8-000330: check failed — kubelet.flags --read-only-port must not be set; kubelet config readOnlyPort must be 0 (or unset)" if {
	count(missing_r_cntr_k8_000330) == 0
	not r_cntr_k8_000330
}

detail_r_cntr_k8_000330 := "CNTR-K8-000330: Not_a_Finding" if r_cntr_k8_000330

finding_r_cntr_k8_000330 := {
	"vuln_id": "V-242387",
	"stig_id": "CNTR-K8-000330",
	"severity": "CAT I",
	"rule_title": "The Kubernetes Kubelet must have the \"readOnlyPort\" flag disabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000330,
	"detail": detail_r_cntr_k8_000330,
}

status_r_cntr_k8_000330 := "Not_a_Finding" if r_cntr_k8_000330

status_r_cntr_k8_000330 := "Open" if not r_cntr_k8_000330

# CNTR-K8-000350 | V-242389 | CAT II | machine
missing_r_cntr_k8_000350 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_000350 := false

r_cntr_k8_000350 if {
	count(missing_r_cntr_k8_000350) == 0
	_nonempty(_flag(input.api_server.flags, "secure-port"))
	to_number(_flag(input.api_server.flags, "secure-port")) > 0
	to_number(_flag(input.api_server.flags, "secure-port")) <= 65535
}

default detail_r_cntr_k8_000350 := ""

detail_r_cntr_k8_000350 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000350", concat(", ", missing_r_cntr_k8_000350)]) if count(missing_r_cntr_k8_000350) > 0

detail_r_cntr_k8_000350 := "CNTR-K8-000350: check failed — api_server --secure-port must be set to a port other than 0" if {
	count(missing_r_cntr_k8_000350) == 0
	not r_cntr_k8_000350
}

detail_r_cntr_k8_000350 := "CNTR-K8-000350: Not_a_Finding" if r_cntr_k8_000350

finding_r_cntr_k8_000350 := {
	"vuln_id": "V-242389",
	"stig_id": "CNTR-K8-000350",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API server must have the secure port set.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000350,
	"detail": detail_r_cntr_k8_000350,
}

status_r_cntr_k8_000350 := "Not_a_Finding" if r_cntr_k8_000350

status_r_cntr_k8_000350 := "Open" if not r_cntr_k8_000350

# CNTR-K8-000360 | V-242390 | CAT I | machine
missing_r_cntr_k8_000360 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_000360 := false

r_cntr_k8_000360 if {
	count(missing_r_cntr_k8_000360) == 0
	_flag(input.api_server.flags, "anonymous-auth") == "false"
}

default detail_r_cntr_k8_000360 := ""

detail_r_cntr_k8_000360 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000360", concat(", ", missing_r_cntr_k8_000360)]) if count(missing_r_cntr_k8_000360) > 0

detail_r_cntr_k8_000360 := "CNTR-K8-000360: check failed — api_server.flags --anonymous-auth must be \"false\"" if {
	count(missing_r_cntr_k8_000360) == 0
	not r_cntr_k8_000360
}

detail_r_cntr_k8_000360 := "CNTR-K8-000360: Not_a_Finding" if r_cntr_k8_000360

finding_r_cntr_k8_000360 := {
	"vuln_id": "V-242390",
	"stig_id": "CNTR-K8-000360",
	"severity": "CAT I",
	"rule_title": "The Kubernetes API server must have anonymous authentication disabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000360,
	"detail": detail_r_cntr_k8_000360,
}

status_r_cntr_k8_000360 := "Not_a_Finding" if r_cntr_k8_000360

status_r_cntr_k8_000360 := "Open" if not r_cntr_k8_000360

# CNTR-K8-000370 | V-242391 | CAT I | machine
missing_r_cntr_k8_000370 := [concat(".", p) | some p in [["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_000370 := false

r_cntr_k8_000370 if {
	count(missing_r_cntr_k8_000370) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "anonymous-auth") == 0
	is_object(input.kubelet.config)
	object.get(input.kubelet.config, ["authentication", "anonymous", "enabled"], null) == false
}

r_cntr_k8_000370 if {
	count(missing_r_cntr_k8_000370) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "anonymous-auth") == 0
	object.get(input.kubelet.config, ["authentication", "anonymous", "enabled"], null) == null
	is_object(input.kubelet.config)
	object.get(input.kubelet.config, ["authentication_anonymous_enabled"], null) == false
}

default detail_r_cntr_k8_000370 := ""

detail_r_cntr_k8_000370 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000370", concat(", ", missing_r_cntr_k8_000370)]) if count(missing_r_cntr_k8_000370) > 0

detail_r_cntr_k8_000370 := "CNTR-K8-000370: check failed — kubelet.flags --anonymous-auth must not be set; kubelet config authentication.anonymous.enabled must be false" if {
	count(missing_r_cntr_k8_000370) == 0
	not r_cntr_k8_000370
}

detail_r_cntr_k8_000370 := "CNTR-K8-000370: Not_a_Finding" if r_cntr_k8_000370

finding_r_cntr_k8_000370 := {
	"vuln_id": "V-242391",
	"stig_id": "CNTR-K8-000370",
	"severity": "CAT I",
	"rule_title": "The Kubernetes Kubelet must have anonymous authentication disabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000370,
	"detail": detail_r_cntr_k8_000370,
}

status_r_cntr_k8_000370 := "Not_a_Finding" if r_cntr_k8_000370

status_r_cntr_k8_000370 := "Open" if not r_cntr_k8_000370

# CNTR-K8-000380 | V-242392 | CAT I | machine
missing_r_cntr_k8_000380 := [concat(".", p) | some p in [["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_000380 := false

r_cntr_k8_000380 if {
	count(missing_r_cntr_k8_000380) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "authorization-mode") == 0
	is_object(input.kubelet.config)
	object.get(input.kubelet.config, ["authorization", "mode"], null) == "Webhook"
}

r_cntr_k8_000380 if {
	count(missing_r_cntr_k8_000380) == 0
	_flag(input.kubelet.flags, "authorization-mode") == "Webhook"
}

r_cntr_k8_000380 if {
	count(missing_r_cntr_k8_000380) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "authorization-mode") == 0
	object.get(input.kubelet.config, ["authorization", "mode"], null) == null
	is_object(input.kubelet.config)
	object.get(input.kubelet.config, ["authorization_mode"], null) == "Webhook"
}

default detail_r_cntr_k8_000380 := ""

detail_r_cntr_k8_000380 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000380", concat(", ", missing_r_cntr_k8_000380)]) if count(missing_r_cntr_k8_000380) > 0

detail_r_cntr_k8_000380 := "CNTR-K8-000380: check failed — kubelet authorization mode must be Webhook" if {
	count(missing_r_cntr_k8_000380) == 0
	not r_cntr_k8_000380
}

detail_r_cntr_k8_000380 := "CNTR-K8-000380: Not_a_Finding" if r_cntr_k8_000380

finding_r_cntr_k8_000380 := {
	"vuln_id": "V-242392",
	"stig_id": "CNTR-K8-000380",
	"severity": "CAT I",
	"rule_title": "The Kubernetes kubelet must enable explicit authorization.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000380,
	"detail": detail_r_cntr_k8_000380,
}

status_r_cntr_k8_000380 := "Not_a_Finding" if r_cntr_k8_000380

status_r_cntr_k8_000380 := "Open" if not r_cntr_k8_000380

# CNTR-K8-000400 | V-242393 | CAT II | machine
missing_r_cntr_k8_000400 := [concat(".", p) | some p in [["worker_nodes"]]; not _collected(p)]

default r_cntr_k8_000400 := false

r_cntr_k8_000400 if {
	count(missing_r_cntr_k8_000400) == 0
	is_array(input.worker_nodes)
	count(input.worker_nodes) > 0
	every n in input.worker_nodes {
		n.sshd_active == false
	}
}

default detail_r_cntr_k8_000400 := ""

detail_r_cntr_k8_000400 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000400", concat(", ", missing_r_cntr_k8_000400)]) if count(missing_r_cntr_k8_000400) > 0

detail_r_cntr_k8_000400 := "CNTR-K8-000400: check failed — sshd must not be running on any worker node" if {
	count(missing_r_cntr_k8_000400) == 0
	not r_cntr_k8_000400
}

detail_r_cntr_k8_000400 := "CNTR-K8-000400: Not_a_Finding" if r_cntr_k8_000400

finding_r_cntr_k8_000400 := {
	"vuln_id": "V-242393",
	"stig_id": "CNTR-K8-000400",
	"severity": "CAT II",
	"rule_title": "Kubernetes Worker Nodes must not have sshd service running.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000400,
	"detail": detail_r_cntr_k8_000400,
}

status_r_cntr_k8_000400 := "Not_a_Finding" if r_cntr_k8_000400

status_r_cntr_k8_000400 := "Open" if not r_cntr_k8_000400

# CNTR-K8-000410 | V-242394 | CAT II | machine
missing_r_cntr_k8_000410 := [concat(".", p) | some p in [["worker_nodes"]]; not _collected(p)]

default r_cntr_k8_000410 := false

r_cntr_k8_000410 if {
	count(missing_r_cntr_k8_000410) == 0
	is_array(input.worker_nodes)
	count(input.worker_nodes) > 0
	every n in input.worker_nodes {
		n.sshd_enabled == false
	}
}

default detail_r_cntr_k8_000410 := ""

detail_r_cntr_k8_000410 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000410", concat(", ", missing_r_cntr_k8_000410)]) if count(missing_r_cntr_k8_000410) > 0

detail_r_cntr_k8_000410 := "CNTR-K8-000410: check failed — sshd must not be enabled on any worker node" if {
	count(missing_r_cntr_k8_000410) == 0
	not r_cntr_k8_000410
}

detail_r_cntr_k8_000410 := "CNTR-K8-000410: Not_a_Finding" if r_cntr_k8_000410

finding_r_cntr_k8_000410 := {
	"vuln_id": "V-242394",
	"stig_id": "CNTR-K8-000410",
	"severity": "CAT II",
	"rule_title": "Kubernetes Worker Nodes must not have the sshd service enabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000410,
	"detail": detail_r_cntr_k8_000410,
}

status_r_cntr_k8_000410 := "Not_a_Finding" if r_cntr_k8_000410

status_r_cntr_k8_000410 := "Open" if not r_cntr_k8_000410

# CNTR-K8-000420 | V-242395 | CAT II | machine
missing_r_cntr_k8_000420 := [concat(".", p) | some p in [["cluster", "dashboard_pods"]]; not _collected(p)]

default r_cntr_k8_000420 := false

r_cntr_k8_000420 if {
	count(missing_r_cntr_k8_000420) == 0
	is_array(input.cluster.dashboard_pods)
	count(input.cluster.dashboard_pods) == 0
}

default detail_r_cntr_k8_000420 := ""

detail_r_cntr_k8_000420 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000420", concat(", ", missing_r_cntr_k8_000420)]) if count(missing_r_cntr_k8_000420) > 0

detail_r_cntr_k8_000420 := "CNTR-K8-000420: check failed — no pods labelled k8s-app=kubernetes-dashboard may run" if {
	count(missing_r_cntr_k8_000420) == 0
	not r_cntr_k8_000420
}

detail_r_cntr_k8_000420 := "CNTR-K8-000420: Not_a_Finding" if r_cntr_k8_000420

finding_r_cntr_k8_000420 := {
	"vuln_id": "V-242395",
	"stig_id": "CNTR-K8-000420",
	"severity": "CAT II",
	"rule_title": "Kubernetes dashboard must not be enabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000420,
	"detail": detail_r_cntr_k8_000420,
}

status_r_cntr_k8_000420 := "Not_a_Finding" if r_cntr_k8_000420

status_r_cntr_k8_000420 := "Open" if not r_cntr_k8_000420

# CNTR-K8-000430 | V-242396 | CAT II | machine
missing_r_cntr_k8_000430 := [concat(".", p) | some p in [["kubectl", "client_versions"]]; not _collected(p)]

default r_cntr_k8_000430 := false

r_cntr_k8_000430 if {
	count(missing_r_cntr_k8_000430) == 0
	is_array(input.kubectl.client_versions)
	count(input.kubectl.client_versions) > 0
	every v in input.kubectl.client_versions {
		_ver_at_least(v, 1, 12, 9)
	}
}

default detail_r_cntr_k8_000430 := ""

detail_r_cntr_k8_000430 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000430", concat(", ", missing_r_cntr_k8_000430)]) if count(missing_r_cntr_k8_000430) > 0

detail_r_cntr_k8_000430 := "CNTR-K8-000430: check failed — kubectl must be 1.12.9 or newer on the control plane and every node" if {
	count(missing_r_cntr_k8_000430) == 0
	not r_cntr_k8_000430
}

detail_r_cntr_k8_000430 := "CNTR-K8-000430: Not_a_Finding" if r_cntr_k8_000430

finding_r_cntr_k8_000430 := {
	"vuln_id": "V-242396",
	"stig_id": "CNTR-K8-000430",
	"severity": "CAT II",
	"rule_title": "Kubernetes Kubectl cp command must give expected access and results.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000430,
	"detail": detail_r_cntr_k8_000430,
}

status_r_cntr_k8_000430 := "Not_a_Finding" if r_cntr_k8_000430

status_r_cntr_k8_000430 := "Open" if not r_cntr_k8_000430

# CNTR-K8-000440 | V-242397 | CAT I | machine
missing_r_cntr_k8_000440 := [concat(".", p) | some p in [["kubelet", "config"], ["kubelet", "flags"]]; not _collected(p)]

default r_cntr_k8_000440 := false

r_cntr_k8_000440 if {
	count(missing_r_cntr_k8_000440) == 0
	is_object(input.kubelet.config)
	object.get(input.kubelet.config, ["staticPodPath"], null) == null
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "pod-manifest-path") == 0
}

default detail_r_cntr_k8_000440 := ""

detail_r_cntr_k8_000440 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000440", concat(", ", missing_r_cntr_k8_000440)]) if count(missing_r_cntr_k8_000440) > 0

detail_r_cntr_k8_000440 := "CNTR-K8-000440: check failed — kubelet config staticPodPath must not be set; kubelet.flags --pod-manifest-path must not be set" if {
	count(missing_r_cntr_k8_000440) == 0
	not r_cntr_k8_000440
}

detail_r_cntr_k8_000440 := "CNTR-K8-000440: Not_a_Finding" if r_cntr_k8_000440

finding_r_cntr_k8_000440 := {
	"vuln_id": "V-242397",
	"stig_id": "CNTR-K8-000440",
	"severity": "CAT I",
	"rule_title": "The Kubernetes kubelet staticPodPath must not enable static pods.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000440,
	"detail": detail_r_cntr_k8_000440,
}

status_r_cntr_k8_000440 := "Not_a_Finding" if r_cntr_k8_000440

status_r_cntr_k8_000440 := "Open" if not r_cntr_k8_000440

# CNTR-K8-000450 | V-242398 | CAT II | machine
missing_r_cntr_k8_000450 := [concat(".", p) | some p in [["api_server", "flags"], ["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_000450 := false

r_cntr_k8_000450 if {
	count(missing_r_cntr_k8_000450) == 0
	is_object(input.api_server.flags)
	_gate_never(input.api_server.flags, "DynamicAuditing", "true")
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "feature-gates") == 0
	is_object(input.kubelet.config)
	object.get(input.kubelet.config, ["featureGates", "DynamicAuditing"], null) in {null, false}
}

default detail_r_cntr_k8_000450 := ""

detail_r_cntr_k8_000450 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000450", concat(", ", missing_r_cntr_k8_000450)]) if count(missing_r_cntr_k8_000450) > 0

detail_r_cntr_k8_000450 := "CNTR-K8-000450: check failed — api_server.flags --feature-gates must not set DynamicAuditing=true; kubelet.flags --feature-gates must not be set; kubelet config featureGates.DynamicAuditing must not be true" if {
	count(missing_r_cntr_k8_000450) == 0
	not r_cntr_k8_000450
}

detail_r_cntr_k8_000450 := "CNTR-K8-000450: Not_a_Finding" if r_cntr_k8_000450

finding_r_cntr_k8_000450 := {
	"vuln_id": "V-242398",
	"stig_id": "CNTR-K8-000450",
	"severity": "CAT II",
	"rule_title": "Kubernetes DynamicAuditing must not be enabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000450,
	"detail": detail_r_cntr_k8_000450,
}

status_r_cntr_k8_000450 := "Not_a_Finding" if r_cntr_k8_000450

status_r_cntr_k8_000450 := "Open" if not r_cntr_k8_000450

# CNTR-K8-000460 | V-242399 | CAT II | machine
missing_r_cntr_k8_000460 := [concat(".", p) | some p in [["cluster", "version"]]; not _collected(p)]

default r_cntr_k8_000460 := false

r_cntr_k8_000460 if {
	count(missing_r_cntr_k8_000460) == 0
	_k8s_minor > 25
}

r_cntr_k8_000460 if {
	count(missing_r_cntr_k8_000460) == 0
	_k8s_minor <= 25
	every c in [input.api_server.flags, input.controller_manager.flags, input.scheduler.flags] {
		_gate_all(c, "DynamicKubeletConfig", "false")
	}
	object.get(input.kubelet.config, ["featureGates", "DynamicKubeletConfig"], null) == false
	_flag_count(input.kubelet.flags, "feature-gates") == 0
}

default detail_r_cntr_k8_000460 := ""

detail_r_cntr_k8_000460 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000460", concat(", ", missing_r_cntr_k8_000460)]) if count(missing_r_cntr_k8_000460) > 0

detail_r_cntr_k8_000460 := "CNTR-K8-000460: check failed — Kubernetes 1.25 and older: DynamicKubeletConfig=false in every manifest and the kubelet config" if {
	count(missing_r_cntr_k8_000460) == 0
	not r_cntr_k8_000460
}

detail_r_cntr_k8_000460 := "CNTR-K8-000460: Not_a_Finding" if r_cntr_k8_000460

finding_r_cntr_k8_000460 := {
	"vuln_id": "V-242399",
	"stig_id": "CNTR-K8-000460",
	"severity": "CAT II",
	"rule_title": "Kubernetes DynamicKubeletConfig must not be enabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000460,
	"detail": detail_r_cntr_k8_000460,
}

status_r_cntr_k8_000460 := "Not_a_Finding" if r_cntr_k8_000460

status_r_cntr_k8_000460 := "Open" if not r_cntr_k8_000460

# CNTR-K8-000470 | V-242400 | CAT II | machine
missing_r_cntr_k8_000470 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_000470 := false

r_cntr_k8_000470 if {
	count(missing_r_cntr_k8_000470) == 0
	is_object(input.api_server.flags)
	_gate_never(input.api_server.flags, "AllAlpha", "true")
}

default detail_r_cntr_k8_000470 := ""

detail_r_cntr_k8_000470 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000470", concat(", ", missing_r_cntr_k8_000470)]) if count(missing_r_cntr_k8_000470) > 0

detail_r_cntr_k8_000470 := "CNTR-K8-000470: check failed — api_server.flags --feature-gates must not set AllAlpha=true" if {
	count(missing_r_cntr_k8_000470) == 0
	not r_cntr_k8_000470
}

detail_r_cntr_k8_000470 := "CNTR-K8-000470: Not_a_Finding" if r_cntr_k8_000470

finding_r_cntr_k8_000470 := {
	"vuln_id": "V-242400",
	"stig_id": "CNTR-K8-000470",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API server must have Alpha APIs disabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000470,
	"detail": detail_r_cntr_k8_000470,
}

status_r_cntr_k8_000470 := "Not_a_Finding" if r_cntr_k8_000470

status_r_cntr_k8_000470 := "Open" if not r_cntr_k8_000470

# CNTR-K8-000610 | V-242402 | CAT II | machine
missing_r_cntr_k8_000610 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_000610 := false

r_cntr_k8_000610 if {
	count(missing_r_cntr_k8_000610) == 0
	_nonempty(_flag(input.api_server.flags, "audit-log-path"))
}

default detail_r_cntr_k8_000610 := ""

detail_r_cntr_k8_000610 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000610", concat(", ", missing_r_cntr_k8_000610)]) if count(missing_r_cntr_k8_000610) > 0

detail_r_cntr_k8_000610 := "CNTR-K8-000610: check failed — api_server.flags --audit-log-path must be set to a non-empty value" if {
	count(missing_r_cntr_k8_000610) == 0
	not r_cntr_k8_000610
}

detail_r_cntr_k8_000610 := "CNTR-K8-000610: Not_a_Finding" if r_cntr_k8_000610

finding_r_cntr_k8_000610 := {
	"vuln_id": "V-242402",
	"stig_id": "CNTR-K8-000610",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API Server must have an audit log path set.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000610,
	"detail": detail_r_cntr_k8_000610,
}

status_r_cntr_k8_000610 := "Not_a_Finding" if r_cntr_k8_000610

status_r_cntr_k8_000610 := "Open" if not r_cntr_k8_000610

# CNTR-K8-000700 | V-242403 | CAT II | machine
missing_r_cntr_k8_000700 := [concat(".", p) | some p in [["api_server", "flags"], ["api_server", "audit_policy"]]; not _collected(p)]

default r_cntr_k8_000700 := false

r_cntr_k8_000700 if {
	count(missing_r_cntr_k8_000700) == 0
	_nonempty(_flag(input.api_server.flags, "audit-policy-file"))
	startswith(input.api_server.audit_policy.apiVersion, "audit.k8s.io/")
	input.api_server.audit_policy.kind == "Policy"
	count(input.api_server.audit_policy.rules) > 0
	every r in input.api_server.audit_policy.rules {
		r.level == "RequestResponse"
	}
}

default detail_r_cntr_k8_000700 := ""

detail_r_cntr_k8_000700 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000700", concat(", ", missing_r_cntr_k8_000700)]) if count(missing_r_cntr_k8_000700) > 0

detail_r_cntr_k8_000700 := "CNTR-K8-000700: check failed — --audit-policy-file set; policy logs all requests at RequestResponse" if {
	count(missing_r_cntr_k8_000700) == 0
	not r_cntr_k8_000700
}

detail_r_cntr_k8_000700 := "CNTR-K8-000700: Not_a_Finding" if r_cntr_k8_000700

finding_r_cntr_k8_000700 := {
	"vuln_id": "V-242403",
	"stig_id": "CNTR-K8-000700",
	"severity": "CAT II",
	"rule_title": "Kubernetes API Server must generate audit records that identify what type of event has occurred, identify the source of the event, contain the event results, identify any users, and identify any containers associated wit",
	"check_type": "machine",
	"status": status_r_cntr_k8_000700,
	"detail": detail_r_cntr_k8_000700,
}

status_r_cntr_k8_000700 := "Not_a_Finding" if r_cntr_k8_000700

status_r_cntr_k8_000700 := "Open" if not r_cntr_k8_000700

# CNTR-K8-000850 | V-242404 | CAT II | machine
missing_r_cntr_k8_000850 := [concat(".", p) | some p in [["kubelet", "flags"]]; not _collected(p)]

default r_cntr_k8_000850 := false

r_cntr_k8_000850 if {
	count(missing_r_cntr_k8_000850) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "hostname-override") == 0
}

default detail_r_cntr_k8_000850 := ""

detail_r_cntr_k8_000850 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000850", concat(", ", missing_r_cntr_k8_000850)]) if count(missing_r_cntr_k8_000850) > 0

detail_r_cntr_k8_000850 := "CNTR-K8-000850: check failed — kubelet.flags --hostname-override must not be set" if {
	count(missing_r_cntr_k8_000850) == 0
	not r_cntr_k8_000850
}

detail_r_cntr_k8_000850 := "CNTR-K8-000850: Not_a_Finding" if r_cntr_k8_000850

finding_r_cntr_k8_000850 := {
	"vuln_id": "V-242404",
	"stig_id": "CNTR-K8-000850",
	"severity": "CAT II",
	"rule_title": "Kubernetes Kubelet must deny hostname override.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000850,
	"detail": detail_r_cntr_k8_000850,
}

status_r_cntr_k8_000850 := "Not_a_Finding" if r_cntr_k8_000850

status_r_cntr_k8_000850 := "Open" if not r_cntr_k8_000850

# CNTR-K8-000860 | V-242405 | CAT II | machine
missing_r_cntr_k8_000860 := [concat(".", p) | some p in [["files", "manifests"]]; not _collected(p)]

default r_cntr_k8_000860 := false

r_cntr_k8_000860 if {
	count(missing_r_cntr_k8_000860) == 0
	_files_owned(input.files["manifests"], "root", "root")
}

default detail_r_cntr_k8_000860 := ""

detail_r_cntr_k8_000860 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000860", concat(", ", missing_r_cntr_k8_000860)]) if count(missing_r_cntr_k8_000860) > 0

detail_r_cntr_k8_000860 := "CNTR-K8-000860: check failed — every manifests file must be owned by root:root" if {
	count(missing_r_cntr_k8_000860) == 0
	not r_cntr_k8_000860
}

detail_r_cntr_k8_000860 := "CNTR-K8-000860: Not_a_Finding" if r_cntr_k8_000860

finding_r_cntr_k8_000860 := {
	"vuln_id": "V-242405",
	"stig_id": "CNTR-K8-000860",
	"severity": "CAT II",
	"rule_title": "The Kubernetes manifests must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000860,
	"detail": detail_r_cntr_k8_000860,
}

status_r_cntr_k8_000860 := "Not_a_Finding" if r_cntr_k8_000860

status_r_cntr_k8_000860 := "Open" if not r_cntr_k8_000860

# CNTR-K8-000880 | V-242406 | CAT II | machine
missing_r_cntr_k8_000880 := [concat(".", p) | some p in [["files", "kubelet_config_file"]]; not _collected(p)]

default r_cntr_k8_000880 := false

r_cntr_k8_000880 if {
	count(missing_r_cntr_k8_000880) == 0
	_files_owned(input.files["kubelet_config_file"], "root", "root")
}

default detail_r_cntr_k8_000880 := ""

detail_r_cntr_k8_000880 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000880", concat(", ", missing_r_cntr_k8_000880)]) if count(missing_r_cntr_k8_000880) > 0

detail_r_cntr_k8_000880 := "CNTR-K8-000880: check failed — every kubelet_config_file file must be owned by root:root" if {
	count(missing_r_cntr_k8_000880) == 0
	not r_cntr_k8_000880
}

detail_r_cntr_k8_000880 := "CNTR-K8-000880: Not_a_Finding" if r_cntr_k8_000880

finding_r_cntr_k8_000880 := {
	"vuln_id": "V-242406",
	"stig_id": "CNTR-K8-000880",
	"severity": "CAT II",
	"rule_title": "The Kubernetes KubeletConfiguration file must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000880,
	"detail": detail_r_cntr_k8_000880,
}

status_r_cntr_k8_000880 := "Not_a_Finding" if r_cntr_k8_000880

status_r_cntr_k8_000880 := "Open" if not r_cntr_k8_000880

# CNTR-K8-000890 | V-242407 | CAT II | machine
missing_r_cntr_k8_000890 := [concat(".", p) | some p in [["files", "kubelet_config_file"]]; not _collected(p)]

default r_cntr_k8_000890 := false

r_cntr_k8_000890 if {
	count(missing_r_cntr_k8_000890) == 0
	_files_mode_le(input.files["kubelet_config_file"], "644")
}

default detail_r_cntr_k8_000890 := ""

detail_r_cntr_k8_000890 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000890", concat(", ", missing_r_cntr_k8_000890)]) if count(missing_r_cntr_k8_000890) > 0

detail_r_cntr_k8_000890 := "CNTR-K8-000890: check failed — every kubelet_config_file file must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_000890) == 0
	not r_cntr_k8_000890
}

detail_r_cntr_k8_000890 := "CNTR-K8-000890: Not_a_Finding" if r_cntr_k8_000890

finding_r_cntr_k8_000890 := {
	"vuln_id": "V-242407",
	"stig_id": "CNTR-K8-000890",
	"severity": "CAT II",
	"rule_title": "The Kubernetes KubeletConfiguration files must have file permissions set to 644 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000890,
	"detail": detail_r_cntr_k8_000890,
}

status_r_cntr_k8_000890 := "Not_a_Finding" if r_cntr_k8_000890

status_r_cntr_k8_000890 := "Open" if not r_cntr_k8_000890

# CNTR-K8-000900 | V-242408 | CAT II | machine
missing_r_cntr_k8_000900 := [concat(".", p) | some p in [["files", "manifests"]]; not _collected(p)]

default r_cntr_k8_000900 := false

r_cntr_k8_000900 if {
	count(missing_r_cntr_k8_000900) == 0
	_files_mode_le(input.files["manifests"], "644")
}

default detail_r_cntr_k8_000900 := ""

detail_r_cntr_k8_000900 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000900", concat(", ", missing_r_cntr_k8_000900)]) if count(missing_r_cntr_k8_000900) > 0

detail_r_cntr_k8_000900 := "CNTR-K8-000900: check failed — every manifests file must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_000900) == 0
	not r_cntr_k8_000900
}

detail_r_cntr_k8_000900 := "CNTR-K8-000900: Not_a_Finding" if r_cntr_k8_000900

finding_r_cntr_k8_000900 := {
	"vuln_id": "V-242408",
	"stig_id": "CNTR-K8-000900",
	"severity": "CAT II",
	"rule_title": "The Kubernetes manifest files must have least privileges.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000900,
	"detail": detail_r_cntr_k8_000900,
}

status_r_cntr_k8_000900 := "Not_a_Finding" if r_cntr_k8_000900

status_r_cntr_k8_000900 := "Open" if not r_cntr_k8_000900

# CNTR-K8-000910 | V-242409 | CAT II | machine
missing_r_cntr_k8_000910 := [concat(".", p) | some p in [["controller_manager", "flags"]]; not _collected(p)]

default r_cntr_k8_000910 := false

r_cntr_k8_000910 if {
	count(missing_r_cntr_k8_000910) == 0
	_flag(input.controller_manager.flags, "profiling") == "false"
}

default detail_r_cntr_k8_000910 := ""

detail_r_cntr_k8_000910 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000910", concat(", ", missing_r_cntr_k8_000910)]) if count(missing_r_cntr_k8_000910) > 0

detail_r_cntr_k8_000910 := "CNTR-K8-000910: check failed — controller_manager.flags --profiling must be \"false\"" if {
	count(missing_r_cntr_k8_000910) == 0
	not r_cntr_k8_000910
}

detail_r_cntr_k8_000910 := "CNTR-K8-000910: Not_a_Finding" if r_cntr_k8_000910

finding_r_cntr_k8_000910 := {
	"vuln_id": "V-242409",
	"stig_id": "CNTR-K8-000910",
	"severity": "CAT II",
	"rule_title": "Kubernetes Controller Manager must disable profiling.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000910,
	"detail": detail_r_cntr_k8_000910,
}

status_r_cntr_k8_000910 := "Not_a_Finding" if r_cntr_k8_000910

status_r_cntr_k8_000910 := "Open" if not r_cntr_k8_000910

# CNTR-K8-000920 | V-242410 | CAT II | attestation
missing_r_cntr_k8_000920 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_k8_000920 := false

r_cntr_k8_000920 if {
	count(missing_r_cntr_k8_000920) == 0
	input.attest.api_server_pps_ppsm_cal_compliant == true
}

default detail_r_cntr_k8_000920 := ""

detail_r_cntr_k8_000920 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000920", concat(", ", missing_r_cntr_k8_000920)]) if count(missing_r_cntr_k8_000920) > 0

detail_r_cntr_k8_000920 := "CNTR-K8-000920: not attested — input.attest.api_server_pps_ppsm_cal_compliant must be true (api_server ports, protocols and services reviewed against the PPSM CAL and system documentation)" if {
	count(missing_r_cntr_k8_000920) == 0
	not r_cntr_k8_000920
}

detail_r_cntr_k8_000920 := "CNTR-K8-000920: Not_a_Finding" if r_cntr_k8_000920

finding_r_cntr_k8_000920 := {
	"vuln_id": "V-242410",
	"stig_id": "CNTR-K8-000920",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API Server must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
	"check_type": "attestation",
	"status": status_r_cntr_k8_000920,
	"detail": detail_r_cntr_k8_000920,
}

status_r_cntr_k8_000920 := "Not_a_Finding" if r_cntr_k8_000920

status_r_cntr_k8_000920 := "Open" if not r_cntr_k8_000920

# CNTR-K8-000930 | V-242411 | CAT II | attestation
missing_r_cntr_k8_000930 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_k8_000930 := false

r_cntr_k8_000930 if {
	count(missing_r_cntr_k8_000930) == 0
	input.attest.scheduler_pps_ppsm_cal_compliant == true
}

default detail_r_cntr_k8_000930 := ""

detail_r_cntr_k8_000930 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000930", concat(", ", missing_r_cntr_k8_000930)]) if count(missing_r_cntr_k8_000930) > 0

detail_r_cntr_k8_000930 := "CNTR-K8-000930: not attested — input.attest.scheduler_pps_ppsm_cal_compliant must be true (scheduler ports, protocols and services reviewed against the PPSM CAL and system documentation)" if {
	count(missing_r_cntr_k8_000930) == 0
	not r_cntr_k8_000930
}

detail_r_cntr_k8_000930 := "CNTR-K8-000930: Not_a_Finding" if r_cntr_k8_000930

finding_r_cntr_k8_000930 := {
	"vuln_id": "V-242411",
	"stig_id": "CNTR-K8-000930",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Scheduler must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
	"check_type": "attestation",
	"status": status_r_cntr_k8_000930,
	"detail": detail_r_cntr_k8_000930,
}

status_r_cntr_k8_000930 := "Not_a_Finding" if r_cntr_k8_000930

status_r_cntr_k8_000930 := "Open" if not r_cntr_k8_000930

# CNTR-K8-000940 | V-242412 | CAT II | attestation
missing_r_cntr_k8_000940 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_k8_000940 := false

r_cntr_k8_000940 if {
	count(missing_r_cntr_k8_000940) == 0
	input.attest.controller_manager_pps_ppsm_cal_compliant == true
}

default detail_r_cntr_k8_000940 := ""

detail_r_cntr_k8_000940 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000940", concat(", ", missing_r_cntr_k8_000940)]) if count(missing_r_cntr_k8_000940) > 0

detail_r_cntr_k8_000940 := "CNTR-K8-000940: not attested — input.attest.controller_manager_pps_ppsm_cal_compliant must be true (controller_manager ports, protocols and services reviewed against the PPSM CAL and system documentation)" if {
	count(missing_r_cntr_k8_000940) == 0
	not r_cntr_k8_000940
}

detail_r_cntr_k8_000940 := "CNTR-K8-000940: Not_a_Finding" if r_cntr_k8_000940

finding_r_cntr_k8_000940 := {
	"vuln_id": "V-242412",
	"stig_id": "CNTR-K8-000940",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Controllers must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
	"check_type": "attestation",
	"status": status_r_cntr_k8_000940,
	"detail": detail_r_cntr_k8_000940,
}

status_r_cntr_k8_000940 := "Not_a_Finding" if r_cntr_k8_000940

status_r_cntr_k8_000940 := "Open" if not r_cntr_k8_000940

# CNTR-K8-000950 | V-242413 | CAT II | attestation
missing_r_cntr_k8_000950 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_k8_000950 := false

r_cntr_k8_000950 if {
	count(missing_r_cntr_k8_000950) == 0
	input.attest.etcd_pps_ppsm_cal_compliant == true
}

default detail_r_cntr_k8_000950 := ""

detail_r_cntr_k8_000950 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000950", concat(", ", missing_r_cntr_k8_000950)]) if count(missing_r_cntr_k8_000950) > 0

detail_r_cntr_k8_000950 := "CNTR-K8-000950: not attested — input.attest.etcd_pps_ppsm_cal_compliant must be true (etcd ports, protocols and services reviewed against the PPSM CAL and system documentation)" if {
	count(missing_r_cntr_k8_000950) == 0
	not r_cntr_k8_000950
}

detail_r_cntr_k8_000950 := "CNTR-K8-000950: Not_a_Finding" if r_cntr_k8_000950

finding_r_cntr_k8_000950 := {
	"vuln_id": "V-242413",
	"stig_id": "CNTR-K8-000950",
	"severity": "CAT II",
	"rule_title": "The Kubernetes etcd must enforce ports, protocols, and services (PPS) that adhere to the Ports, Protocols, and Services Management Category Assurance List (PPSM CAL).",
	"check_type": "attestation",
	"status": status_r_cntr_k8_000950,
	"detail": detail_r_cntr_k8_000950,
}

status_r_cntr_k8_000950 := "Not_a_Finding" if r_cntr_k8_000950

status_r_cntr_k8_000950 := "Open" if not r_cntr_k8_000950

# CNTR-K8-000960 | V-242414 | CAT II | machine
missing_r_cntr_k8_000960 := [concat(".", p) | some p in [["workloads", "user_pod_host_ports"]]; not _collected(p)]

default r_cntr_k8_000960 := false

r_cntr_k8_000960 if {
	count(missing_r_cntr_k8_000960) == 0
	is_array(input.workloads.user_pod_host_ports)
	every p in input.workloads.user_pod_host_ports {
		to_number(p) >= 1024
	}
}

default detail_r_cntr_k8_000960 := ""

detail_r_cntr_k8_000960 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-000960", concat(", ", missing_r_cntr_k8_000960)]) if count(missing_r_cntr_k8_000960) > 0

detail_r_cntr_k8_000960 := "CNTR-K8-000960: check failed — pods in user namespaces must not use privileged (<1024) host ports" if {
	count(missing_r_cntr_k8_000960) == 0
	not r_cntr_k8_000960
}

detail_r_cntr_k8_000960 := "CNTR-K8-000960: Not_a_Finding" if r_cntr_k8_000960

finding_r_cntr_k8_000960 := {
	"vuln_id": "V-242414",
	"stig_id": "CNTR-K8-000960",
	"severity": "CAT II",
	"rule_title": "The Kubernetes cluster must use non-privileged host ports for user pods.",
	"check_type": "machine",
	"status": status_r_cntr_k8_000960,
	"detail": detail_r_cntr_k8_000960,
}

status_r_cntr_k8_000960 := "Not_a_Finding" if r_cntr_k8_000960

status_r_cntr_k8_000960 := "Open" if not r_cntr_k8_000960

# CNTR-K8-001160 | V-242415 | CAT I | machine
missing_r_cntr_k8_001160 := [concat(".", p) | some p in [["secrets", "env_var_usage_count"]]; not _collected(p)]

default r_cntr_k8_001160 := false

r_cntr_k8_001160 if {
	count(missing_r_cntr_k8_001160) == 0
	input.secrets.env_var_usage_count == 0
}

default detail_r_cntr_k8_001160 := ""

detail_r_cntr_k8_001160 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001160", concat(", ", missing_r_cntr_k8_001160)]) if count(missing_r_cntr_k8_001160) > 0

detail_r_cntr_k8_001160 := "CNTR-K8-001160: check failed — no workload may load a Secret into an environment variable" if {
	count(missing_r_cntr_k8_001160) == 0
	not r_cntr_k8_001160
}

detail_r_cntr_k8_001160 := "CNTR-K8-001160: Not_a_Finding" if r_cntr_k8_001160

finding_r_cntr_k8_001160 := {
	"vuln_id": "V-242415",
	"stig_id": "CNTR-K8-001160",
	"severity": "CAT I",
	"rule_title": "Secrets in Kubernetes must not be stored as environment variables.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001160,
	"detail": detail_r_cntr_k8_001160,
}

status_r_cntr_k8_001160 := "Not_a_Finding" if r_cntr_k8_001160

status_r_cntr_k8_001160 := "Open" if not r_cntr_k8_001160

# CNTR-K8-001161 | V-274883 | CAT I | attestation
missing_r_cntr_k8_001161 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_k8_001161 := false

r_cntr_k8_001161 if {
	count(missing_r_cntr_k8_001161) == 0
	input.attest.sensitive_data_only_in_secrets == true
}

default detail_r_cntr_k8_001161 := ""

detail_r_cntr_k8_001161 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001161", concat(", ", missing_r_cntr_k8_001161)]) if count(missing_r_cntr_k8_001161) > 0

detail_r_cntr_k8_001161 := "CNTR-K8-001161: not attested — input.attest.sensitive_data_only_in_secrets must be true (manual review of all resources and ConfigMaps found no sensitive information outside Secrets or an external store)" if {
	count(missing_r_cntr_k8_001161) == 0
	not r_cntr_k8_001161
}

detail_r_cntr_k8_001161 := "CNTR-K8-001161: Not_a_Finding" if r_cntr_k8_001161

finding_r_cntr_k8_001161 := {
	"vuln_id": "V-274883",
	"stig_id": "CNTR-K8-001161",
	"severity": "CAT I",
	"rule_title": "Sensitive information must be stored using Kubernetes Secrets or an external Secret store provider.",
	"check_type": "attestation",
	"status": status_r_cntr_k8_001161,
	"detail": detail_r_cntr_k8_001161,
}

status_r_cntr_k8_001161 := "Not_a_Finding" if r_cntr_k8_001161

status_r_cntr_k8_001161 := "Open" if not r_cntr_k8_001161

# CNTR-K8-001162 | V-274882 | CAT I | machine
missing_r_cntr_k8_001162 := [concat(".", p) | some p in [["api_server", "flags"], ["api_server", "encryption_config"]]; not _collected(p)]

default r_cntr_k8_001162 := false

r_cntr_k8_001162 if {
	count(missing_r_cntr_k8_001162) == 0
	_nonempty(_flag(input.api_server.flags, "encryption-provider-config"))
	first := _first_secrets_entry(input.api_server.encryption_config.resources)
	is_string(first.providers[0])
	first.providers[0] != "identity"
}

default detail_r_cntr_k8_001162 := ""

detail_r_cntr_k8_001162 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001162", concat(", ", missing_r_cntr_k8_001162)]) if count(missing_r_cntr_k8_001162) > 0

detail_r_cntr_k8_001162 := "CNTR-K8-001162: check failed — --encryption-provider-config set; secrets covered; identity not the first provider" if {
	count(missing_r_cntr_k8_001162) == 0
	not r_cntr_k8_001162
}

detail_r_cntr_k8_001162 := "CNTR-K8-001162: Not_a_Finding" if r_cntr_k8_001162

finding_r_cntr_k8_001162 := {
	"vuln_id": "V-274882",
	"stig_id": "CNTR-K8-001162",
	"severity": "CAT I",
	"rule_title": "Kubernetes Secrets must be encrypted at rest.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001162,
	"detail": detail_r_cntr_k8_001162,
}

status_r_cntr_k8_001162 := "Not_a_Finding" if r_cntr_k8_001162

status_r_cntr_k8_001162 := "Open" if not r_cntr_k8_001162

# CNTR-K8-001163 | V-274884 | CAT II | attestation
missing_r_cntr_k8_001163 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_k8_001163 := false

r_cntr_k8_001163 if {
	count(missing_r_cntr_k8_001163) == 0
	input.attest.secret_access_need_to_know == true
}

default detail_r_cntr_k8_001163 := ""

detail_r_cntr_k8_001163 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001163", concat(", ", missing_r_cntr_k8_001163)]) if count(missing_r_cntr_k8_001163) > 0

detail_r_cntr_k8_001163 := "CNTR-K8-001163: not attested — input.attest.secret_access_need_to_know must be true (read access to Secrets and Secrets attached to workloads are limited to documented requirements)" if {
	count(missing_r_cntr_k8_001163) == 0
	not r_cntr_k8_001163
}

detail_r_cntr_k8_001163 := "CNTR-K8-001163: Not_a_Finding" if r_cntr_k8_001163

finding_r_cntr_k8_001163 := {
	"vuln_id": "V-274884",
	"stig_id": "CNTR-K8-001163",
	"severity": "CAT II",
	"rule_title": "Kubernetes must limit Secret access on a need-to-know basis.",
	"check_type": "attestation",
	"status": status_r_cntr_k8_001163,
	"detail": detail_r_cntr_k8_001163,
}

status_r_cntr_k8_001163 := "Not_a_Finding" if r_cntr_k8_001163

status_r_cntr_k8_001163 := "Open" if not r_cntr_k8_001163

# CNTR-K8-001300 | V-245541 | CAT II | machine
missing_r_cntr_k8_001300 := [concat(".", p) | some p in [["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_001300 := false

r_cntr_k8_001300 if {
	count(missing_r_cntr_k8_001300) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "streaming-connection-idle-timeout") == 0
	_nonempty(object.get(input.kubelet.config, ["streamingConnectionIdleTimeout"], ""))
	_duration_ge(object.get(input.kubelet.config, ["streamingConnectionIdleTimeout"], ""), "5m")
}

default detail_r_cntr_k8_001300 := ""

detail_r_cntr_k8_001300 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001300", concat(", ", missing_r_cntr_k8_001300)]) if count(missing_r_cntr_k8_001300) > 0

detail_r_cntr_k8_001300 := "CNTR-K8-001300: check failed — kubelet.flags --streaming-connection-idle-timeout must not be set; kubelet config streamingConnectionIdleTimeout must be at least 5m" if {
	count(missing_r_cntr_k8_001300) == 0
	not r_cntr_k8_001300
}

detail_r_cntr_k8_001300 := "CNTR-K8-001300: Not_a_Finding" if r_cntr_k8_001300

finding_r_cntr_k8_001300 := {
	"vuln_id": "V-245541",
	"stig_id": "CNTR-K8-001300",
	"severity": "CAT II",
	"rule_title": "Kubernetes Kubelet must not disable timeouts.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001300,
	"detail": detail_r_cntr_k8_001300,
}

status_r_cntr_k8_001300 := "Not_a_Finding" if r_cntr_k8_001300

status_r_cntr_k8_001300 := "Open" if not r_cntr_k8_001300

# CNTR-K8-001360 | V-242417 | CAT II | attestation
missing_r_cntr_k8_001360 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_k8_001360 := false

r_cntr_k8_001360 if {
	count(missing_r_cntr_k8_001360) == 0
	input.attest.no_user_pods_in_system_namespaces == true
}

default detail_r_cntr_k8_001360 := ""

detail_r_cntr_k8_001360 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001360", concat(", ", missing_r_cntr_k8_001360)]) if count(missing_r_cntr_k8_001360) > 0

detail_r_cntr_k8_001360 := "CNTR-K8-001360: not attested — input.attest.no_user_pods_in_system_namespaces must be true (review found no user pods in kube-system, kube-public or kube-node-lease)" if {
	count(missing_r_cntr_k8_001360) == 0
	not r_cntr_k8_001360
}

detail_r_cntr_k8_001360 := "CNTR-K8-001360: Not_a_Finding" if r_cntr_k8_001360

finding_r_cntr_k8_001360 := {
	"vuln_id": "V-242417",
	"stig_id": "CNTR-K8-001360",
	"severity": "CAT II",
	"rule_title": "Kubernetes must separate user functionality.",
	"check_type": "attestation",
	"status": status_r_cntr_k8_001360,
	"detail": detail_r_cntr_k8_001360,
}

status_r_cntr_k8_001360 := "Not_a_Finding" if r_cntr_k8_001360

status_r_cntr_k8_001360 := "Open" if not r_cntr_k8_001360

# CNTR-K8-001400 | V-242418 | CAT II | machine
missing_r_cntr_k8_001400 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_001400 := false

r_cntr_k8_001400 if {
	count(missing_r_cntr_k8_001400) == 0
	_nonempty(_flag(input.api_server.flags, "tls-cipher-suites"))
	_list_has_all(_flag(input.api_server.flags, "tls-cipher-suites"), ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"])
}

default detail_r_cntr_k8_001400 := ""

detail_r_cntr_k8_001400 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001400", concat(", ", missing_r_cntr_k8_001400)]) if count(missing_r_cntr_k8_001400) > 0

detail_r_cntr_k8_001400 := "CNTR-K8-001400: check failed — api_server.flags --tls-cipher-suites must include TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" if {
	count(missing_r_cntr_k8_001400) == 0
	not r_cntr_k8_001400
}

detail_r_cntr_k8_001400 := "CNTR-K8-001400: Not_a_Finding" if r_cntr_k8_001400

finding_r_cntr_k8_001400 := {
	"vuln_id": "V-242418",
	"stig_id": "CNTR-K8-001400",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API server must use approved cipher suites.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001400,
	"detail": detail_r_cntr_k8_001400,
}

status_r_cntr_k8_001400 := "Not_a_Finding" if r_cntr_k8_001400

status_r_cntr_k8_001400 := "Open" if not r_cntr_k8_001400

# CNTR-K8-001410 | V-242419 | CAT II | machine
missing_r_cntr_k8_001410 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_001410 := false

r_cntr_k8_001410 if {
	count(missing_r_cntr_k8_001410) == 0
	_nonempty(_flag(input.api_server.flags, "client-ca-file"))
}

default detail_r_cntr_k8_001410 := ""

detail_r_cntr_k8_001410 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001410", concat(", ", missing_r_cntr_k8_001410)]) if count(missing_r_cntr_k8_001410) > 0

detail_r_cntr_k8_001410 := "CNTR-K8-001410: check failed — api_server.flags --client-ca-file must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001410) == 0
	not r_cntr_k8_001410
}

detail_r_cntr_k8_001410 := "CNTR-K8-001410: Not_a_Finding" if r_cntr_k8_001410

finding_r_cntr_k8_001410 := {
	"vuln_id": "V-242419",
	"stig_id": "CNTR-K8-001410",
	"severity": "CAT II",
	"rule_title": "Kubernetes API Server must have the SSL Certificate Authority set.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001410,
	"detail": detail_r_cntr_k8_001410,
}

status_r_cntr_k8_001410 := "Not_a_Finding" if r_cntr_k8_001410

status_r_cntr_k8_001410 := "Open" if not r_cntr_k8_001410

# CNTR-K8-001420 | V-242420 | CAT II | machine
missing_r_cntr_k8_001420 := [concat(".", p) | some p in [["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_001420 := false

r_cntr_k8_001420 if {
	count(missing_r_cntr_k8_001420) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "client-ca-file") == 0
	_nonempty(object.get(input.kubelet.config, ["authentication", "x509", "clientCAFile"], ""))
}

default detail_r_cntr_k8_001420 := ""

detail_r_cntr_k8_001420 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001420", concat(", ", missing_r_cntr_k8_001420)]) if count(missing_r_cntr_k8_001420) > 0

detail_r_cntr_k8_001420 := "CNTR-K8-001420: check failed — kubelet.flags --client-ca-file must not be set; kubelet config authentication.x509.clientCAFile must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001420) == 0
	not r_cntr_k8_001420
}

detail_r_cntr_k8_001420 := "CNTR-K8-001420: Not_a_Finding" if r_cntr_k8_001420

finding_r_cntr_k8_001420 := {
	"vuln_id": "V-242420",
	"stig_id": "CNTR-K8-001420",
	"severity": "CAT II",
	"rule_title": "Kubernetes Kubelet must have the SSL Certificate Authority set.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001420,
	"detail": detail_r_cntr_k8_001420,
}

status_r_cntr_k8_001420 := "Not_a_Finding" if r_cntr_k8_001420

status_r_cntr_k8_001420 := "Open" if not r_cntr_k8_001420

# CNTR-K8-001430 | V-242421 | CAT II | machine
missing_r_cntr_k8_001430 := [concat(".", p) | some p in [["controller_manager", "flags"]]; not _collected(p)]

default r_cntr_k8_001430 := false

r_cntr_k8_001430 if {
	count(missing_r_cntr_k8_001430) == 0
	_nonempty(_flag(input.controller_manager.flags, "root-ca-file"))
}

default detail_r_cntr_k8_001430 := ""

detail_r_cntr_k8_001430 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001430", concat(", ", missing_r_cntr_k8_001430)]) if count(missing_r_cntr_k8_001430) > 0

detail_r_cntr_k8_001430 := "CNTR-K8-001430: check failed — controller_manager.flags --root-ca-file must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001430) == 0
	not r_cntr_k8_001430
}

detail_r_cntr_k8_001430 := "CNTR-K8-001430: Not_a_Finding" if r_cntr_k8_001430

finding_r_cntr_k8_001430 := {
	"vuln_id": "V-242421",
	"stig_id": "CNTR-K8-001430",
	"severity": "CAT II",
	"rule_title": "Kubernetes Controller Manager must have the SSL Certificate Authority set.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001430,
	"detail": detail_r_cntr_k8_001430,
}

status_r_cntr_k8_001430 := "Not_a_Finding" if r_cntr_k8_001430

status_r_cntr_k8_001430 := "Open" if not r_cntr_k8_001430

# CNTR-K8-001440 | V-242422 | CAT II | machine
missing_r_cntr_k8_001440 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_001440 := false

r_cntr_k8_001440 if {
	count(missing_r_cntr_k8_001440) == 0
	_nonempty(_flag(input.api_server.flags, "tls-cert-file"))
	_nonempty(_flag(input.api_server.flags, "tls-private-key-file"))
}

default detail_r_cntr_k8_001440 := ""

detail_r_cntr_k8_001440 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001440", concat(", ", missing_r_cntr_k8_001440)]) if count(missing_r_cntr_k8_001440) > 0

detail_r_cntr_k8_001440 := "CNTR-K8-001440: check failed — api_server.flags --tls-cert-file must be set to a non-empty value; api_server.flags --tls-private-key-file must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001440) == 0
	not r_cntr_k8_001440
}

detail_r_cntr_k8_001440 := "CNTR-K8-001440: Not_a_Finding" if r_cntr_k8_001440

finding_r_cntr_k8_001440 := {
	"vuln_id": "V-242422",
	"stig_id": "CNTR-K8-001440",
	"severity": "CAT II",
	"rule_title": "Kubernetes API Server must have a certificate for communication.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001440,
	"detail": detail_r_cntr_k8_001440,
}

status_r_cntr_k8_001440 := "Not_a_Finding" if r_cntr_k8_001440

status_r_cntr_k8_001440 := "Open" if not r_cntr_k8_001440

# CNTR-K8-001450 | V-242423 | CAT II | machine
missing_r_cntr_k8_001450 := [concat(".", p) | some p in [["etcd", "flags"]]; not _collected(p)]

default r_cntr_k8_001450 := false

r_cntr_k8_001450 if {
	count(missing_r_cntr_k8_001450) == 0
	_flag(input.etcd.flags, "client-cert-auth") == "true"
}

default detail_r_cntr_k8_001450 := ""

detail_r_cntr_k8_001450 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001450", concat(", ", missing_r_cntr_k8_001450)]) if count(missing_r_cntr_k8_001450) > 0

detail_r_cntr_k8_001450 := "CNTR-K8-001450: check failed — etcd.flags --client-cert-auth must be \"true\"" if {
	count(missing_r_cntr_k8_001450) == 0
	not r_cntr_k8_001450
}

detail_r_cntr_k8_001450 := "CNTR-K8-001450: Not_a_Finding" if r_cntr_k8_001450

finding_r_cntr_k8_001450 := {
	"vuln_id": "V-242423",
	"stig_id": "CNTR-K8-001450",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must enable client authentication to secure service.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001450,
	"detail": detail_r_cntr_k8_001450,
}

status_r_cntr_k8_001450 := "Not_a_Finding" if r_cntr_k8_001450

status_r_cntr_k8_001450 := "Open" if not r_cntr_k8_001450

# CNTR-K8-001460 | V-242424 | CAT II | machine
missing_r_cntr_k8_001460 := [concat(".", p) | some p in [["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_001460 := false

r_cntr_k8_001460 if {
	count(missing_r_cntr_k8_001460) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "tls-private-key-file") == 0
	_nonempty(object.get(input.kubelet.config, ["tlsPrivateKeyFile"], ""))
}

default detail_r_cntr_k8_001460 := ""

detail_r_cntr_k8_001460 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001460", concat(", ", missing_r_cntr_k8_001460)]) if count(missing_r_cntr_k8_001460) > 0

detail_r_cntr_k8_001460 := "CNTR-K8-001460: check failed — kubelet.flags --tls-private-key-file must not be set; kubelet config tlsPrivateKeyFile must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001460) == 0
	not r_cntr_k8_001460
}

detail_r_cntr_k8_001460 := "CNTR-K8-001460: Not_a_Finding" if r_cntr_k8_001460

finding_r_cntr_k8_001460 := {
	"vuln_id": "V-242424",
	"stig_id": "CNTR-K8-001460",
	"severity": "CAT II",
	"rule_title": "Kubernetes Kubelet must enable tlsPrivateKeyFile for client authentication to secure service.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001460,
	"detail": detail_r_cntr_k8_001460,
}

status_r_cntr_k8_001460 := "Not_a_Finding" if r_cntr_k8_001460

status_r_cntr_k8_001460 := "Open" if not r_cntr_k8_001460

# CNTR-K8-001470 | V-242425 | CAT II | machine
missing_r_cntr_k8_001470 := [concat(".", p) | some p in [["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_001470 := false

r_cntr_k8_001470 if {
	count(missing_r_cntr_k8_001470) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "tls-cert-file") == 0
	_nonempty(object.get(input.kubelet.config, ["tlsCertFile"], ""))
}

default detail_r_cntr_k8_001470 := ""

detail_r_cntr_k8_001470 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001470", concat(", ", missing_r_cntr_k8_001470)]) if count(missing_r_cntr_k8_001470) > 0

detail_r_cntr_k8_001470 := "CNTR-K8-001470: check failed — kubelet.flags --tls-cert-file must not be set; kubelet config tlsCertFile must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001470) == 0
	not r_cntr_k8_001470
}

detail_r_cntr_k8_001470 := "CNTR-K8-001470: Not_a_Finding" if r_cntr_k8_001470

finding_r_cntr_k8_001470 := {
	"vuln_id": "V-242425",
	"stig_id": "CNTR-K8-001470",
	"severity": "CAT II",
	"rule_title": "Kubernetes Kubelet must enable tlsCertFile for client authentication to secure service.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001470,
	"detail": detail_r_cntr_k8_001470,
}

status_r_cntr_k8_001470 := "Not_a_Finding" if r_cntr_k8_001470

status_r_cntr_k8_001470 := "Open" if not r_cntr_k8_001470

# CNTR-K8-001480 | V-242426 | CAT II | machine
missing_r_cntr_k8_001480 := [concat(".", p) | some p in [["etcd", "flags"]]; not _collected(p)]

default r_cntr_k8_001480 := false

r_cntr_k8_001480 if {
	count(missing_r_cntr_k8_001480) == 0
	_flag(input.etcd.flags, "peer-client-cert-auth") == "true"
}

default detail_r_cntr_k8_001480 := ""

detail_r_cntr_k8_001480 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001480", concat(", ", missing_r_cntr_k8_001480)]) if count(missing_r_cntr_k8_001480) > 0

detail_r_cntr_k8_001480 := "CNTR-K8-001480: check failed — etcd.flags --peer-client-cert-auth must be \"true\"" if {
	count(missing_r_cntr_k8_001480) == 0
	not r_cntr_k8_001480
}

detail_r_cntr_k8_001480 := "CNTR-K8-001480: Not_a_Finding" if r_cntr_k8_001480

finding_r_cntr_k8_001480 := {
	"vuln_id": "V-242426",
	"stig_id": "CNTR-K8-001480",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must enable client authentication to secure service.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001480,
	"detail": detail_r_cntr_k8_001480,
}

status_r_cntr_k8_001480 := "Not_a_Finding" if r_cntr_k8_001480

status_r_cntr_k8_001480 := "Open" if not r_cntr_k8_001480

# CNTR-K8-001490 | V-242427 | CAT II | machine
missing_r_cntr_k8_001490 := [concat(".", p) | some p in [["etcd", "flags"]]; not _collected(p)]

default r_cntr_k8_001490 := false

r_cntr_k8_001490 if {
	count(missing_r_cntr_k8_001490) == 0
	_nonempty(_flag(input.etcd.flags, "key-file"))
}

default detail_r_cntr_k8_001490 := ""

detail_r_cntr_k8_001490 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001490", concat(", ", missing_r_cntr_k8_001490)]) if count(missing_r_cntr_k8_001490) > 0

detail_r_cntr_k8_001490 := "CNTR-K8-001490: check failed — etcd.flags --key-file must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001490) == 0
	not r_cntr_k8_001490
}

detail_r_cntr_k8_001490 := "CNTR-K8-001490: Not_a_Finding" if r_cntr_k8_001490

finding_r_cntr_k8_001490 := {
	"vuln_id": "V-242427",
	"stig_id": "CNTR-K8-001490",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must have a key file for secure communication.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001490,
	"detail": detail_r_cntr_k8_001490,
}

status_r_cntr_k8_001490 := "Not_a_Finding" if r_cntr_k8_001490

status_r_cntr_k8_001490 := "Open" if not r_cntr_k8_001490

# CNTR-K8-001500 | V-242428 | CAT II | machine
missing_r_cntr_k8_001500 := [concat(".", p) | some p in [["etcd", "flags"]]; not _collected(p)]

default r_cntr_k8_001500 := false

r_cntr_k8_001500 if {
	count(missing_r_cntr_k8_001500) == 0
	_nonempty(_flag(input.etcd.flags, "cert-file"))
}

default detail_r_cntr_k8_001500 := ""

detail_r_cntr_k8_001500 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001500", concat(", ", missing_r_cntr_k8_001500)]) if count(missing_r_cntr_k8_001500) > 0

detail_r_cntr_k8_001500 := "CNTR-K8-001500: check failed — etcd.flags --cert-file must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001500) == 0
	not r_cntr_k8_001500
}

detail_r_cntr_k8_001500 := "CNTR-K8-001500: Not_a_Finding" if r_cntr_k8_001500

finding_r_cntr_k8_001500 := {
	"vuln_id": "V-242428",
	"stig_id": "CNTR-K8-001500",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must have a certificate for communication.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001500,
	"detail": detail_r_cntr_k8_001500,
}

status_r_cntr_k8_001500 := "Not_a_Finding" if r_cntr_k8_001500

status_r_cntr_k8_001500 := "Open" if not r_cntr_k8_001500

# CNTR-K8-001510 | V-242429 | CAT II | machine
missing_r_cntr_k8_001510 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_001510 := false

r_cntr_k8_001510 if {
	count(missing_r_cntr_k8_001510) == 0
	_nonempty(_flag(input.api_server.flags, "etcd-cafile"))
}

default detail_r_cntr_k8_001510 := ""

detail_r_cntr_k8_001510 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001510", concat(", ", missing_r_cntr_k8_001510)]) if count(missing_r_cntr_k8_001510) > 0

detail_r_cntr_k8_001510 := "CNTR-K8-001510: check failed — api_server.flags --etcd-cafile must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001510) == 0
	not r_cntr_k8_001510
}

detail_r_cntr_k8_001510 := "CNTR-K8-001510: Not_a_Finding" if r_cntr_k8_001510

finding_r_cntr_k8_001510 := {
	"vuln_id": "V-242429",
	"stig_id": "CNTR-K8-001510",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must have the SSL Certificate Authority set.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001510,
	"detail": detail_r_cntr_k8_001510,
}

status_r_cntr_k8_001510 := "Not_a_Finding" if r_cntr_k8_001510

status_r_cntr_k8_001510 := "Open" if not r_cntr_k8_001510

# CNTR-K8-001520 | V-242430 | CAT II | machine
missing_r_cntr_k8_001520 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_001520 := false

r_cntr_k8_001520 if {
	count(missing_r_cntr_k8_001520) == 0
	_nonempty(_flag(input.api_server.flags, "etcd-certfile"))
}

default detail_r_cntr_k8_001520 := ""

detail_r_cntr_k8_001520 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001520", concat(", ", missing_r_cntr_k8_001520)]) if count(missing_r_cntr_k8_001520) > 0

detail_r_cntr_k8_001520 := "CNTR-K8-001520: check failed — api_server.flags --etcd-certfile must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001520) == 0
	not r_cntr_k8_001520
}

detail_r_cntr_k8_001520 := "CNTR-K8-001520: Not_a_Finding" if r_cntr_k8_001520

finding_r_cntr_k8_001520 := {
	"vuln_id": "V-242430",
	"stig_id": "CNTR-K8-001520",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must have a certificate for communication.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001520,
	"detail": detail_r_cntr_k8_001520,
}

status_r_cntr_k8_001520 := "Not_a_Finding" if r_cntr_k8_001520

status_r_cntr_k8_001520 := "Open" if not r_cntr_k8_001520

# CNTR-K8-001530 | V-242431 | CAT II | machine
missing_r_cntr_k8_001530 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_001530 := false

r_cntr_k8_001530 if {
	count(missing_r_cntr_k8_001530) == 0
	_nonempty(_flag(input.api_server.flags, "etcd-keyfile"))
}

default detail_r_cntr_k8_001530 := ""

detail_r_cntr_k8_001530 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001530", concat(", ", missing_r_cntr_k8_001530)]) if count(missing_r_cntr_k8_001530) > 0

detail_r_cntr_k8_001530 := "CNTR-K8-001530: check failed — api_server.flags --etcd-keyfile must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001530) == 0
	not r_cntr_k8_001530
}

detail_r_cntr_k8_001530 := "CNTR-K8-001530: Not_a_Finding" if r_cntr_k8_001530

finding_r_cntr_k8_001530 := {
	"vuln_id": "V-242431",
	"stig_id": "CNTR-K8-001530",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must have a key file for secure communication.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001530,
	"detail": detail_r_cntr_k8_001530,
}

status_r_cntr_k8_001530 := "Not_a_Finding" if r_cntr_k8_001530

status_r_cntr_k8_001530 := "Open" if not r_cntr_k8_001530

# CNTR-K8-001540 | V-242432 | CAT II | machine
missing_r_cntr_k8_001540 := [concat(".", p) | some p in [["etcd", "flags"]]; not _collected(p)]

default r_cntr_k8_001540 := false

r_cntr_k8_001540 if {
	count(missing_r_cntr_k8_001540) == 0
	_nonempty(_flag(input.etcd.flags, "peer-cert-file"))
}

default detail_r_cntr_k8_001540 := ""

detail_r_cntr_k8_001540 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001540", concat(", ", missing_r_cntr_k8_001540)]) if count(missing_r_cntr_k8_001540) > 0

detail_r_cntr_k8_001540 := "CNTR-K8-001540: check failed — etcd.flags --peer-cert-file must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001540) == 0
	not r_cntr_k8_001540
}

detail_r_cntr_k8_001540 := "CNTR-K8-001540: Not_a_Finding" if r_cntr_k8_001540

finding_r_cntr_k8_001540 := {
	"vuln_id": "V-242432",
	"stig_id": "CNTR-K8-001540",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must have peer-cert-file set for secure communication.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001540,
	"detail": detail_r_cntr_k8_001540,
}

status_r_cntr_k8_001540 := "Not_a_Finding" if r_cntr_k8_001540

status_r_cntr_k8_001540 := "Open" if not r_cntr_k8_001540

# CNTR-K8-001550 | V-242433 | CAT II | machine
missing_r_cntr_k8_001550 := [concat(".", p) | some p in [["etcd", "flags"]]; not _collected(p)]

default r_cntr_k8_001550 := false

r_cntr_k8_001550 if {
	count(missing_r_cntr_k8_001550) == 0
	_nonempty(_flag(input.etcd.flags, "peer-key-file"))
}

default detail_r_cntr_k8_001550 := ""

detail_r_cntr_k8_001550 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001550", concat(", ", missing_r_cntr_k8_001550)]) if count(missing_r_cntr_k8_001550) > 0

detail_r_cntr_k8_001550 := "CNTR-K8-001550: check failed — etcd.flags --peer-key-file must be set to a non-empty value" if {
	count(missing_r_cntr_k8_001550) == 0
	not r_cntr_k8_001550
}

detail_r_cntr_k8_001550 := "CNTR-K8-001550: Not_a_Finding" if r_cntr_k8_001550

finding_r_cntr_k8_001550 := {
	"vuln_id": "V-242433",
	"stig_id": "CNTR-K8-001550",
	"severity": "CAT II",
	"rule_title": "Kubernetes etcd must have a peer-key-file set for secure communication.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001550,
	"detail": detail_r_cntr_k8_001550,
}

status_r_cntr_k8_001550 := "Not_a_Finding" if r_cntr_k8_001550

status_r_cntr_k8_001550 := "Open" if not r_cntr_k8_001550

# CNTR-K8-001620 | V-242434 | CAT I | machine
missing_r_cntr_k8_001620 := [concat(".", p) | some p in [["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_001620 := false

r_cntr_k8_001620 if {
	count(missing_r_cntr_k8_001620) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "protect-kernel-defaults") == 0
	is_object(input.kubelet.config)
	object.get(input.kubelet.config, ["protectKernelDefaults"], null) == true
}

default detail_r_cntr_k8_001620 := ""

detail_r_cntr_k8_001620 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-001620", concat(", ", missing_r_cntr_k8_001620)]) if count(missing_r_cntr_k8_001620) > 0

detail_r_cntr_k8_001620 := "CNTR-K8-001620: check failed — kubelet.flags --protect-kernel-defaults must not be set; kubelet config protectKernelDefaults must be true" if {
	count(missing_r_cntr_k8_001620) == 0
	not r_cntr_k8_001620
}

detail_r_cntr_k8_001620 := "CNTR-K8-001620: Not_a_Finding" if r_cntr_k8_001620

finding_r_cntr_k8_001620 := {
	"vuln_id": "V-242434",
	"stig_id": "CNTR-K8-001620",
	"severity": "CAT I",
	"rule_title": "Kubernetes Kubelet must enable kernel protection.",
	"check_type": "machine",
	"status": status_r_cntr_k8_001620,
	"detail": detail_r_cntr_k8_001620,
}

status_r_cntr_k8_001620 := "Not_a_Finding" if r_cntr_k8_001620

status_r_cntr_k8_001620 := "Open" if not r_cntr_k8_001620

# CNTR-K8-002000 | V-242436 | CAT I | machine
missing_r_cntr_k8_002000 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_002000 := false

r_cntr_k8_002000 if {
	count(missing_r_cntr_k8_002000) == 0
	enabled := _csv_set(input.api_server.flags, "enable-admission-plugins")
	"ValidatingAdmissionWebhook" in enabled
	disabled := _csv_set(input.api_server.flags, "disable-admission-plugins")
	not "ValidatingAdmissionWebhook" in disabled
}

r_cntr_k8_002000 if {
	count(missing_r_cntr_k8_002000) == 0
	_k8s_minor >= 25
	disabled := _csv_set(input.api_server.flags, "disable-admission-plugins")
	not "ValidatingAdmissionWebhook" in disabled
}

default detail_r_cntr_k8_002000 := ""

detail_r_cntr_k8_002000 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002000", concat(", ", missing_r_cntr_k8_002000)]) if count(missing_r_cntr_k8_002000) > 0

detail_r_cntr_k8_002000 := "CNTR-K8-002000: check failed — ValidatingAdmissionWebhook must be enabled (in --enable-admission-plugins, or 1.25+ and not disabled)" if {
	count(missing_r_cntr_k8_002000) == 0
	not r_cntr_k8_002000
}

detail_r_cntr_k8_002000 := "CNTR-K8-002000: Not_a_Finding" if r_cntr_k8_002000

finding_r_cntr_k8_002000 := {
	"vuln_id": "V-242436",
	"stig_id": "CNTR-K8-002000",
	"severity": "CAT I",
	"rule_title": "The Kubernetes API server must have the ValidatingAdmissionWebhook enabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_002000,
	"detail": detail_r_cntr_k8_002000,
}

status_r_cntr_k8_002000 := "Not_a_Finding" if r_cntr_k8_002000

status_r_cntr_k8_002000 := "Open" if not r_cntr_k8_002000

# CNTR-K8-002001 | V-254801 | CAT I | machine
missing_r_cntr_k8_002001 := [concat(".", p) | some p in [["api_server", "flags"], ["controller_manager", "flags"], ["scheduler", "flags"], ["kubelet", "flags"], ["kubelet", "config"]]; not _collected(p)]

default r_cntr_k8_002001 := false

r_cntr_k8_002001 if {
	count(missing_r_cntr_k8_002001) == 0
	is_object(input.api_server.flags)
	_gate_never(input.api_server.flags, "PodSecurity", "false")
	is_object(input.controller_manager.flags)
	_gate_never(input.controller_manager.flags, "PodSecurity", "false")
	is_object(input.scheduler.flags)
	_gate_never(input.scheduler.flags, "PodSecurity", "false")
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "feature-gates") == 0
	is_object(input.kubelet.config)
	object.get(input.kubelet.config, ["featureGates", "PodSecurity"], null) in {null, true}
}

default detail_r_cntr_k8_002001 := ""

detail_r_cntr_k8_002001 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002001", concat(", ", missing_r_cntr_k8_002001)]) if count(missing_r_cntr_k8_002001) > 0

detail_r_cntr_k8_002001 := "CNTR-K8-002001: check failed — api_server.flags --feature-gates must not set PodSecurity=false; controller_manager.flags --feature-gates must not set PodSecurity=false; scheduler.flags --feature-gates must not set PodSecurity=false; kubelet.flags --feature-gates must not be set; kubelet config featureGates.PodSecurity must not be false" if {
	count(missing_r_cntr_k8_002001) == 0
	not r_cntr_k8_002001
}

detail_r_cntr_k8_002001 := "CNTR-K8-002001: Not_a_Finding" if r_cntr_k8_002001

finding_r_cntr_k8_002001 := {
	"vuln_id": "V-254801",
	"stig_id": "CNTR-K8-002001",
	"severity": "CAT I",
	"rule_title": "Kubernetes must enable PodSecurity admission controller on static pods and Kubelets.",
	"check_type": "machine",
	"status": status_r_cntr_k8_002001,
	"detail": detail_r_cntr_k8_002001,
}

status_r_cntr_k8_002001 := "Not_a_Finding" if r_cntr_k8_002001

status_r_cntr_k8_002001 := "Open" if not r_cntr_k8_002001

# CNTR-K8-002010 | V-242437 | CAT I | machine
missing_r_cntr_k8_002010 := [concat(".", p) | some p in [["cluster", "version"]]; not _collected(p)]

default r_cntr_k8_002010 := false

r_cntr_k8_002010 if {
	count(missing_r_cntr_k8_002010) == 0
	_k8s_minor >= 25
}

r_cntr_k8_002010 if {
	count(missing_r_cntr_k8_002010) == 0
	_k8s_minor < 25
	count(input.pod_security.policies) > 0
	every p in input.pod_security.policies {
		p.runAsUser.rule == "MustRunAsNonRoot"
		count(p.supplementalGroups.ranges) > 0
		every g in p.supplementalGroups.ranges {
			g.min > 0
		}
		count(p.fsGroup.ranges) > 0
		every g in p.fsGroup.ranges {
			g.min > 0
		}
	}
}

default detail_r_cntr_k8_002010 := ""

detail_r_cntr_k8_002010 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002010", concat(", ", missing_r_cntr_k8_002010)]) if count(missing_r_cntr_k8_002010) > 0

detail_r_cntr_k8_002010 := "CNTR-K8-002010: check failed — Kubernetes before 1.25: a PodSecurityPolicy with MustRunAsNonRoot and non-zero group ranges" if {
	count(missing_r_cntr_k8_002010) == 0
	not r_cntr_k8_002010
}

detail_r_cntr_k8_002010 := "CNTR-K8-002010: Not_a_Finding" if r_cntr_k8_002010

finding_r_cntr_k8_002010 := {
	"vuln_id": "V-242437",
	"stig_id": "CNTR-K8-002010",
	"severity": "CAT I",
	"rule_title": "Kubernetes must have a pod security policy set.",
	"check_type": "machine",
	"status": status_r_cntr_k8_002010,
	"detail": detail_r_cntr_k8_002010,
}

status_r_cntr_k8_002010 := "Not_a_Finding" if r_cntr_k8_002010

status_r_cntr_k8_002010 := "Open" if not r_cntr_k8_002010

# CNTR-K8-002011 | V-254800 | CAT I | machine+attestation
missing_r_cntr_k8_002011 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_002011 := false

r_cntr_k8_002011 if {
	count(missing_r_cntr_k8_002011) == 0
	_nonempty(_flag(input.api_server.flags, "admission-control-config-file"))
	input.attest.pod_security_admission_least_privilege == true
}

default detail_r_cntr_k8_002011 := ""

detail_r_cntr_k8_002011 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002011", concat(", ", missing_r_cntr_k8_002011)]) if count(missing_r_cntr_k8_002011) > 0

detail_r_cntr_k8_002011 := "CNTR-K8-002011: check failed — api_server.flags --admission-control-config-file must be set to a non-empty value; input.attest.pod_security_admission_least_privilege must be true (the PodSecurity admission configuration represents least privilege)" if {
	count(missing_r_cntr_k8_002011) == 0
	not r_cntr_k8_002011
}

detail_r_cntr_k8_002011 := "CNTR-K8-002011: Not_a_Finding" if r_cntr_k8_002011

finding_r_cntr_k8_002011 := {
	"vuln_id": "V-254800",
	"stig_id": "CNTR-K8-002011",
	"severity": "CAT I",
	"rule_title": "Kubernetes must have a Pod Security Admission control file configured.",
	"check_type": "machine+attestation",
	"status": status_r_cntr_k8_002011,
	"detail": detail_r_cntr_k8_002011,
}

status_r_cntr_k8_002011 := "Not_a_Finding" if r_cntr_k8_002011

status_r_cntr_k8_002011 := "Open" if not r_cntr_k8_002011

# CNTR-K8-002600 | V-242438 | CAT II | machine
missing_r_cntr_k8_002600 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_002600 := false

r_cntr_k8_002600 if {
	count(missing_r_cntr_k8_002600) == 0
	_nonempty(_flag(input.api_server.flags, "request-timeout"))
	time.parse_duration_ns(_flag(input.api_server.flags, "request-timeout")) > 0
}

default detail_r_cntr_k8_002600 := ""

detail_r_cntr_k8_002600 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002600", concat(", ", missing_r_cntr_k8_002600)]) if count(missing_r_cntr_k8_002600) > 0

detail_r_cntr_k8_002600 := "CNTR-K8-002600: check failed — api_server --request-timeout must be set to a non-zero duration" if {
	count(missing_r_cntr_k8_002600) == 0
	not r_cntr_k8_002600
}

detail_r_cntr_k8_002600 := "CNTR-K8-002600: Not_a_Finding" if r_cntr_k8_002600

finding_r_cntr_k8_002600 := {
	"vuln_id": "V-242438",
	"stig_id": "CNTR-K8-002600",
	"severity": "CAT II",
	"rule_title": "Kubernetes API Server must configure timeouts to limit attack surface.",
	"check_type": "machine",
	"status": status_r_cntr_k8_002600,
	"detail": detail_r_cntr_k8_002600,
}

status_r_cntr_k8_002600 := "Not_a_Finding" if r_cntr_k8_002600

status_r_cntr_k8_002600 := "Open" if not r_cntr_k8_002600

# CNTR-K8-002620 | V-245542 | CAT I | machine
missing_r_cntr_k8_002620 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_002620 := false

r_cntr_k8_002620 if {
	count(missing_r_cntr_k8_002620) == 0
	is_object(input.api_server.flags)
	_flag_count(input.api_server.flags, "basic-auth-file") == 0
}

default detail_r_cntr_k8_002620 := ""

detail_r_cntr_k8_002620 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002620", concat(", ", missing_r_cntr_k8_002620)]) if count(missing_r_cntr_k8_002620) > 0

detail_r_cntr_k8_002620 := "CNTR-K8-002620: check failed — api_server.flags --basic-auth-file must not be set" if {
	count(missing_r_cntr_k8_002620) == 0
	not r_cntr_k8_002620
}

detail_r_cntr_k8_002620 := "CNTR-K8-002620: Not_a_Finding" if r_cntr_k8_002620

finding_r_cntr_k8_002620 := {
	"vuln_id": "V-245542",
	"stig_id": "CNTR-K8-002620",
	"severity": "CAT I",
	"rule_title": "Kubernetes API Server must disable basic authentication to protect information in transit.",
	"check_type": "machine",
	"status": status_r_cntr_k8_002620,
	"detail": detail_r_cntr_k8_002620,
}

status_r_cntr_k8_002620 := "Not_a_Finding" if r_cntr_k8_002620

status_r_cntr_k8_002620 := "Open" if not r_cntr_k8_002620

# CNTR-K8-002630 | V-245543 | CAT I | machine
missing_r_cntr_k8_002630 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_002630 := false

r_cntr_k8_002630 if {
	count(missing_r_cntr_k8_002630) == 0
	is_object(input.api_server.flags)
	_flag_count(input.api_server.flags, "token-auth-file") == 0
}

default detail_r_cntr_k8_002630 := ""

detail_r_cntr_k8_002630 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002630", concat(", ", missing_r_cntr_k8_002630)]) if count(missing_r_cntr_k8_002630) > 0

detail_r_cntr_k8_002630 := "CNTR-K8-002630: check failed — api_server.flags --token-auth-file must not be set" if {
	count(missing_r_cntr_k8_002630) == 0
	not r_cntr_k8_002630
}

detail_r_cntr_k8_002630 := "CNTR-K8-002630: Not_a_Finding" if r_cntr_k8_002630

finding_r_cntr_k8_002630 := {
	"vuln_id": "V-245543",
	"stig_id": "CNTR-K8-002630",
	"severity": "CAT I",
	"rule_title": "Kubernetes API Server must disable token authentication to protect information in transit.",
	"check_type": "machine",
	"status": status_r_cntr_k8_002630,
	"detail": detail_r_cntr_k8_002630,
}

status_r_cntr_k8_002630 := "Not_a_Finding" if r_cntr_k8_002630

status_r_cntr_k8_002630 := "Open" if not r_cntr_k8_002630

# CNTR-K8-002640 | V-245544 | CAT I | machine
missing_r_cntr_k8_002640 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_002640 := false

r_cntr_k8_002640 if {
	count(missing_r_cntr_k8_002640) == 0
	_nonempty(_flag(input.api_server.flags, "kubelet-client-certificate"))
	_nonempty(_flag(input.api_server.flags, "kubelet-client-key"))
}

default detail_r_cntr_k8_002640 := ""

detail_r_cntr_k8_002640 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002640", concat(", ", missing_r_cntr_k8_002640)]) if count(missing_r_cntr_k8_002640) > 0

detail_r_cntr_k8_002640 := "CNTR-K8-002640: check failed — api_server.flags --kubelet-client-certificate must be set to a non-empty value; api_server.flags --kubelet-client-key must be set to a non-empty value" if {
	count(missing_r_cntr_k8_002640) == 0
	not r_cntr_k8_002640
}

detail_r_cntr_k8_002640 := "CNTR-K8-002640: Not_a_Finding" if r_cntr_k8_002640

finding_r_cntr_k8_002640 := {
	"vuln_id": "V-245544",
	"stig_id": "CNTR-K8-002640",
	"severity": "CAT I",
	"rule_title": "Kubernetes endpoints must use approved organizational certificate and key pair to protect information in transit.",
	"check_type": "machine",
	"status": status_r_cntr_k8_002640,
	"detail": detail_r_cntr_k8_002640,
}

status_r_cntr_k8_002640 := "Not_a_Finding" if r_cntr_k8_002640

status_r_cntr_k8_002640 := "Open" if not r_cntr_k8_002640

# CNTR-K8-002700 | V-242442 | CAT II | machine
missing_r_cntr_k8_002700 := [concat(".", p) | some p in [["cluster", "images"]]; not _collected(p)]

default r_cntr_k8_002700 := false

r_cntr_k8_002700 if {
	count(missing_r_cntr_k8_002700) == 0
	_single_version_per_image(input.cluster.images)
}

default detail_r_cntr_k8_002700 := ""

detail_r_cntr_k8_002700 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002700", concat(", ", missing_r_cntr_k8_002700)]) if count(missing_r_cntr_k8_002700) > 0

detail_r_cntr_k8_002700 := "CNTR-K8-002700: check failed — only one version of each image may run" if {
	count(missing_r_cntr_k8_002700) == 0
	not r_cntr_k8_002700
}

detail_r_cntr_k8_002700 := "CNTR-K8-002700: Not_a_Finding" if r_cntr_k8_002700

finding_r_cntr_k8_002700 := {
	"vuln_id": "V-242442",
	"stig_id": "CNTR-K8-002700",
	"severity": "CAT II",
	"rule_title": "Kubernetes must remove old components after updated versions have been installed.",
	"check_type": "machine",
	"status": status_r_cntr_k8_002700,
	"detail": detail_r_cntr_k8_002700,
}

status_r_cntr_k8_002700 := "Not_a_Finding" if r_cntr_k8_002700

status_r_cntr_k8_002700 := "Open" if not r_cntr_k8_002700

# CNTR-K8-002720 | V-242443 | CAT II | machine
missing_r_cntr_k8_002720 := [concat(".", p) | some p in [["cluster", "version"], ["kubectl", "client_versions"]]; not _collected(p)]

default r_cntr_k8_002720 := false

r_cntr_k8_002720 if {
	count(missing_r_cntr_k8_002720) == 0
	count(input.kubectl.client_versions) > 0
	every v in input.kubectl.client_versions {
		_ver_part(v, 0) == 1
		abs(_ver_part(v, 1) - _k8s_minor) <= 1
	}
}

default detail_r_cntr_k8_002720 := ""

detail_r_cntr_k8_002720 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-002720", concat(", ", missing_r_cntr_k8_002720)]) if count(missing_r_cntr_k8_002720) > 0

detail_r_cntr_k8_002720 := "CNTR-K8-002720: check failed — kubectl must be within one minor version of the cluster (version skew policy)" if {
	count(missing_r_cntr_k8_002720) == 0
	not r_cntr_k8_002720
}

detail_r_cntr_k8_002720 := "CNTR-K8-002720: Not_a_Finding" if r_cntr_k8_002720

finding_r_cntr_k8_002720 := {
	"vuln_id": "V-242443",
	"stig_id": "CNTR-K8-002720",
	"severity": "CAT II",
	"rule_title": "Kubernetes must contain the latest updates as authorized by IAVMs, CTOs, DTMs, and STIGs.",
	"check_type": "machine",
	"status": status_r_cntr_k8_002720,
	"detail": detail_r_cntr_k8_002720,
}

status_r_cntr_k8_002720 := "Not_a_Finding" if r_cntr_k8_002720

status_r_cntr_k8_002720 := "Open" if not r_cntr_k8_002720

# CNTR-K8-003110 | V-242444 | CAT II | machine
missing_r_cntr_k8_003110 := [concat(".", p) | some p in [["files", "manifests"]]; not _collected(p)]

default r_cntr_k8_003110 := false

r_cntr_k8_003110 if {
	count(missing_r_cntr_k8_003110) == 0
	_files_owned(input.files["manifests"], "root", "root")
}

default detail_r_cntr_k8_003110 := ""

detail_r_cntr_k8_003110 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003110", concat(", ", missing_r_cntr_k8_003110)]) if count(missing_r_cntr_k8_003110) > 0

detail_r_cntr_k8_003110 := "CNTR-K8-003110: check failed — every manifests file must be owned by root:root" if {
	count(missing_r_cntr_k8_003110) == 0
	not r_cntr_k8_003110
}

detail_r_cntr_k8_003110 := "CNTR-K8-003110: Not_a_Finding" if r_cntr_k8_003110

finding_r_cntr_k8_003110 := {
	"vuln_id": "V-242444",
	"stig_id": "CNTR-K8-003110",
	"severity": "CAT II",
	"rule_title": "The Kubernetes component manifests must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003110,
	"detail": detail_r_cntr_k8_003110,
}

status_r_cntr_k8_003110 := "Not_a_Finding" if r_cntr_k8_003110

status_r_cntr_k8_003110 := "Open" if not r_cntr_k8_003110

# CNTR-K8-003120 | V-242445 | CAT II | machine
missing_r_cntr_k8_003120 := [concat(".", p) | some p in [["files", "etcd_data"]]; not _collected(p)]

default r_cntr_k8_003120 := false

r_cntr_k8_003120 if {
	count(missing_r_cntr_k8_003120) == 0
	_files_owned(input.files["etcd_data"], "etcd", "etcd")
}

default detail_r_cntr_k8_003120 := ""

detail_r_cntr_k8_003120 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003120", concat(", ", missing_r_cntr_k8_003120)]) if count(missing_r_cntr_k8_003120) > 0

detail_r_cntr_k8_003120 := "CNTR-K8-003120: check failed — every etcd_data file must be owned by etcd:etcd" if {
	count(missing_r_cntr_k8_003120) == 0
	not r_cntr_k8_003120
}

detail_r_cntr_k8_003120 := "CNTR-K8-003120: Not_a_Finding" if r_cntr_k8_003120

finding_r_cntr_k8_003120 := {
	"vuln_id": "V-242445",
	"stig_id": "CNTR-K8-003120",
	"severity": "CAT II",
	"rule_title": "The Kubernetes component etcd must be owned by etcd.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003120,
	"detail": detail_r_cntr_k8_003120,
}

status_r_cntr_k8_003120 := "Not_a_Finding" if r_cntr_k8_003120

status_r_cntr_k8_003120 := "Open" if not r_cntr_k8_003120

# CNTR-K8-003130 | V-242446 | CAT II | machine
missing_r_cntr_k8_003130 := [concat(".", p) | some p in [["files", "control_plane_confs"]]; not _collected(p)]

default r_cntr_k8_003130 := false

r_cntr_k8_003130 if {
	count(missing_r_cntr_k8_003130) == 0
	_files_owned(input.files["control_plane_confs"], "root", "root")
}

default detail_r_cntr_k8_003130 := ""

detail_r_cntr_k8_003130 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003130", concat(", ", missing_r_cntr_k8_003130)]) if count(missing_r_cntr_k8_003130) > 0

detail_r_cntr_k8_003130 := "CNTR-K8-003130: check failed — every control_plane_confs file must be owned by root:root" if {
	count(missing_r_cntr_k8_003130) == 0
	not r_cntr_k8_003130
}

detail_r_cntr_k8_003130 := "CNTR-K8-003130: Not_a_Finding" if r_cntr_k8_003130

finding_r_cntr_k8_003130 := {
	"vuln_id": "V-242446",
	"stig_id": "CNTR-K8-003130",
	"severity": "CAT II",
	"rule_title": "The Kubernetes conf files must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003130,
	"detail": detail_r_cntr_k8_003130,
}

status_r_cntr_k8_003130 := "Not_a_Finding" if r_cntr_k8_003130

status_r_cntr_k8_003130 := "Open" if not r_cntr_k8_003130

# CNTR-K8-003140 | V-242447 | CAT II | machine
missing_r_cntr_k8_003140 := [concat(".", p) | some p in [["kube_proxy", "running"]]; not _collected(p)]

default r_cntr_k8_003140 := false

r_cntr_k8_003140 if {
	count(missing_r_cntr_k8_003140) == 0
	input.kube_proxy.running == true
	_files_mode_le(input.files["kube_proxy_kubeconfig"], "644")
}

r_cntr_k8_003140 if {
	count(missing_r_cntr_k8_003140) == 0
	input.kube_proxy.running == false
}

default detail_r_cntr_k8_003140 := ""

detail_r_cntr_k8_003140 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003140", concat(", ", missing_r_cntr_k8_003140)]) if count(missing_r_cntr_k8_003140) > 0

detail_r_cntr_k8_003140 := "CNTR-K8-003140: check failed — if kube-proxy runs: every kube_proxy_kubeconfig file must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_003140) == 0
	not r_cntr_k8_003140
}

detail_r_cntr_k8_003140 := "CNTR-K8-003140: Not_a_Finding" if r_cntr_k8_003140

finding_r_cntr_k8_003140 := {
	"vuln_id": "V-242447",
	"stig_id": "CNTR-K8-003140",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Kube Proxy kubeconfig must have file permissions set to 644 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003140,
	"detail": detail_r_cntr_k8_003140,
}

status_r_cntr_k8_003140 := "Not_a_Finding" if r_cntr_k8_003140

status_r_cntr_k8_003140 := "Open" if not r_cntr_k8_003140

# CNTR-K8-003150 | V-242448 | CAT II | machine
missing_r_cntr_k8_003150 := [concat(".", p) | some p in [["kube_proxy", "running"]]; not _collected(p)]

default r_cntr_k8_003150 := false

r_cntr_k8_003150 if {
	count(missing_r_cntr_k8_003150) == 0
	input.kube_proxy.running == true
	_files_owned(input.files["kube_proxy_kubeconfig"], "root", "root")
}

r_cntr_k8_003150 if {
	count(missing_r_cntr_k8_003150) == 0
	input.kube_proxy.running == false
}

default detail_r_cntr_k8_003150 := ""

detail_r_cntr_k8_003150 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003150", concat(", ", missing_r_cntr_k8_003150)]) if count(missing_r_cntr_k8_003150) > 0

detail_r_cntr_k8_003150 := "CNTR-K8-003150: check failed — if kube-proxy runs: every kube_proxy_kubeconfig file must be owned by root:root" if {
	count(missing_r_cntr_k8_003150) == 0
	not r_cntr_k8_003150
}

detail_r_cntr_k8_003150 := "CNTR-K8-003150: Not_a_Finding" if r_cntr_k8_003150

finding_r_cntr_k8_003150 := {
	"vuln_id": "V-242448",
	"stig_id": "CNTR-K8-003150",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Kube Proxy kubeconfig must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003150,
	"detail": detail_r_cntr_k8_003150,
}

status_r_cntr_k8_003150 := "Not_a_Finding" if r_cntr_k8_003150

status_r_cntr_k8_003150 := "Open" if not r_cntr_k8_003150

# CNTR-K8-003160 | V-242449 | CAT II | machine
missing_r_cntr_k8_003160 := [concat(".", p) | some p in [["kubelet", "flags"], ["files", "kubelet_client_ca"]]; not _collected(p)]

default r_cntr_k8_003160 := false

r_cntr_k8_003160 if {
	count(missing_r_cntr_k8_003160) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "client-ca-file") == 0
	_files_mode_le(input.files["kubelet_client_ca"], "644")
}

default detail_r_cntr_k8_003160 := ""

detail_r_cntr_k8_003160 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003160", concat(", ", missing_r_cntr_k8_003160)]) if count(missing_r_cntr_k8_003160) > 0

detail_r_cntr_k8_003160 := "CNTR-K8-003160: check failed — kubelet.flags --client-ca-file must not be set; every kubelet_client_ca file must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_003160) == 0
	not r_cntr_k8_003160
}

detail_r_cntr_k8_003160 := "CNTR-K8-003160: Not_a_Finding" if r_cntr_k8_003160

finding_r_cntr_k8_003160 := {
	"vuln_id": "V-242449",
	"stig_id": "CNTR-K8-003160",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Kubelet certificate authority file must have file permissions set to 644 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003160,
	"detail": detail_r_cntr_k8_003160,
}

status_r_cntr_k8_003160 := "Not_a_Finding" if r_cntr_k8_003160

status_r_cntr_k8_003160 := "Open" if not r_cntr_k8_003160

# CNTR-K8-003170 | V-242450 | CAT II | machine
missing_r_cntr_k8_003170 := [concat(".", p) | some p in [["kubelet", "flags"], ["files", "kubelet_client_ca"]]; not _collected(p)]

default r_cntr_k8_003170 := false

r_cntr_k8_003170 if {
	count(missing_r_cntr_k8_003170) == 0
	is_object(input.kubelet.flags)
	_flag_count(input.kubelet.flags, "client-ca-file") == 0
	_files_owned(input.files["kubelet_client_ca"], "root", "root")
}

default detail_r_cntr_k8_003170 := ""

detail_r_cntr_k8_003170 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003170", concat(", ", missing_r_cntr_k8_003170)]) if count(missing_r_cntr_k8_003170) > 0

detail_r_cntr_k8_003170 := "CNTR-K8-003170: check failed — kubelet.flags --client-ca-file must not be set; every kubelet_client_ca file must be owned by root:root" if {
	count(missing_r_cntr_k8_003170) == 0
	not r_cntr_k8_003170
}

detail_r_cntr_k8_003170 := "CNTR-K8-003170: Not_a_Finding" if r_cntr_k8_003170

finding_r_cntr_k8_003170 := {
	"vuln_id": "V-242450",
	"stig_id": "CNTR-K8-003170",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Kubelet certificate authority must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003170,
	"detail": detail_r_cntr_k8_003170,
}

status_r_cntr_k8_003170 := "Not_a_Finding" if r_cntr_k8_003170

status_r_cntr_k8_003170 := "Open" if not r_cntr_k8_003170

# CNTR-K8-003180 | V-242451 | CAT II | machine
missing_r_cntr_k8_003180 := [concat(".", p) | some p in [["files", "pki"]]; not _collected(p)]

default r_cntr_k8_003180 := false

r_cntr_k8_003180 if {
	count(missing_r_cntr_k8_003180) == 0
	_files_owned(input.files["pki"], "root", "root")
}

default detail_r_cntr_k8_003180 := ""

detail_r_cntr_k8_003180 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003180", concat(", ", missing_r_cntr_k8_003180)]) if count(missing_r_cntr_k8_003180) > 0

detail_r_cntr_k8_003180 := "CNTR-K8-003180: check failed — every pki file must be owned by root:root" if {
	count(missing_r_cntr_k8_003180) == 0
	not r_cntr_k8_003180
}

detail_r_cntr_k8_003180 := "CNTR-K8-003180: Not_a_Finding" if r_cntr_k8_003180

finding_r_cntr_k8_003180 := {
	"vuln_id": "V-242451",
	"stig_id": "CNTR-K8-003180",
	"severity": "CAT II",
	"rule_title": "The Kubernetes component PKI must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003180,
	"detail": detail_r_cntr_k8_003180,
}

status_r_cntr_k8_003180 := "Not_a_Finding" if r_cntr_k8_003180

status_r_cntr_k8_003180 := "Open" if not r_cntr_k8_003180

# CNTR-K8-003190 | V-242452 | CAT II | machine
missing_r_cntr_k8_003190 := [concat(".", p) | some p in [["files", "kubelet_kubeconfig"]]; not _collected(p)]

default r_cntr_k8_003190 := false

r_cntr_k8_003190 if {
	count(missing_r_cntr_k8_003190) == 0
	_files_mode_le(input.files["kubelet_kubeconfig"], "644")
}

default detail_r_cntr_k8_003190 := ""

detail_r_cntr_k8_003190 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003190", concat(", ", missing_r_cntr_k8_003190)]) if count(missing_r_cntr_k8_003190) > 0

detail_r_cntr_k8_003190 := "CNTR-K8-003190: check failed — every kubelet_kubeconfig file must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_003190) == 0
	not r_cntr_k8_003190
}

detail_r_cntr_k8_003190 := "CNTR-K8-003190: Not_a_Finding" if r_cntr_k8_003190

finding_r_cntr_k8_003190 := {
	"vuln_id": "V-242452",
	"stig_id": "CNTR-K8-003190",
	"severity": "CAT II",
	"rule_title": "The Kubernetes kubelet KubeConfig must have file permissions set to 644 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003190,
	"detail": detail_r_cntr_k8_003190,
}

status_r_cntr_k8_003190 := "Not_a_Finding" if r_cntr_k8_003190

status_r_cntr_k8_003190 := "Open" if not r_cntr_k8_003190

# CNTR-K8-003200 | V-242453 | CAT II | machine
missing_r_cntr_k8_003200 := [concat(".", p) | some p in [["files", "kubelet_kubeconfig"]]; not _collected(p)]

default r_cntr_k8_003200 := false

r_cntr_k8_003200 if {
	count(missing_r_cntr_k8_003200) == 0
	_files_owned(input.files["kubelet_kubeconfig"], "root", "root")
}

default detail_r_cntr_k8_003200 := ""

detail_r_cntr_k8_003200 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003200", concat(", ", missing_r_cntr_k8_003200)]) if count(missing_r_cntr_k8_003200) > 0

detail_r_cntr_k8_003200 := "CNTR-K8-003200: check failed — every kubelet_kubeconfig file must be owned by root:root" if {
	count(missing_r_cntr_k8_003200) == 0
	not r_cntr_k8_003200
}

detail_r_cntr_k8_003200 := "CNTR-K8-003200: Not_a_Finding" if r_cntr_k8_003200

finding_r_cntr_k8_003200 := {
	"vuln_id": "V-242453",
	"stig_id": "CNTR-K8-003200",
	"severity": "CAT II",
	"rule_title": "The Kubernetes kubelet KubeConfig file must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003200,
	"detail": detail_r_cntr_k8_003200,
}

status_r_cntr_k8_003200 := "Not_a_Finding" if r_cntr_k8_003200

status_r_cntr_k8_003200 := "Open" if not r_cntr_k8_003200

# CNTR-K8-003210 | V-242454 | CAT II | machine
missing_r_cntr_k8_003210 := [concat(".", p) | some p in [["files", "kubeadm_conf"]]; not _collected(p)]

default r_cntr_k8_003210 := false

r_cntr_k8_003210 if {
	count(missing_r_cntr_k8_003210) == 0
	_files_owned(input.files["kubeadm_conf"], "root", "root")
}

default detail_r_cntr_k8_003210 := ""

detail_r_cntr_k8_003210 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003210", concat(", ", missing_r_cntr_k8_003210)]) if count(missing_r_cntr_k8_003210) > 0

detail_r_cntr_k8_003210 := "CNTR-K8-003210: check failed — every kubeadm_conf file must be owned by root:root" if {
	count(missing_r_cntr_k8_003210) == 0
	not r_cntr_k8_003210
}

detail_r_cntr_k8_003210 := "CNTR-K8-003210: Not_a_Finding" if r_cntr_k8_003210

finding_r_cntr_k8_003210 := {
	"vuln_id": "V-242454",
	"stig_id": "CNTR-K8-003210",
	"severity": "CAT II",
	"rule_title": "The Kubernetes kubeadm.conf must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003210,
	"detail": detail_r_cntr_k8_003210,
}

status_r_cntr_k8_003210 := "Not_a_Finding" if r_cntr_k8_003210

status_r_cntr_k8_003210 := "Open" if not r_cntr_k8_003210

# CNTR-K8-003220 | V-242455 | CAT II | machine
missing_r_cntr_k8_003220 := [concat(".", p) | some p in [["files", "kubeadm_conf"]]; not _collected(p)]

default r_cntr_k8_003220 := false

r_cntr_k8_003220 if {
	count(missing_r_cntr_k8_003220) == 0
	_files_mode_le(input.files["kubeadm_conf"], "644")
}

default detail_r_cntr_k8_003220 := ""

detail_r_cntr_k8_003220 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003220", concat(", ", missing_r_cntr_k8_003220)]) if count(missing_r_cntr_k8_003220) > 0

detail_r_cntr_k8_003220 := "CNTR-K8-003220: check failed — every kubeadm_conf file must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_003220) == 0
	not r_cntr_k8_003220
}

detail_r_cntr_k8_003220 := "CNTR-K8-003220: Not_a_Finding" if r_cntr_k8_003220

finding_r_cntr_k8_003220 := {
	"vuln_id": "V-242455",
	"stig_id": "CNTR-K8-003220",
	"severity": "CAT II",
	"rule_title": "The Kubernetes kubeadm.conf must have file permissions set to 644 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003220,
	"detail": detail_r_cntr_k8_003220,
}

status_r_cntr_k8_003220 := "Not_a_Finding" if r_cntr_k8_003220

status_r_cntr_k8_003220 := "Open" if not r_cntr_k8_003220

# CNTR-K8-003230 | V-242456 | CAT II | machine
missing_r_cntr_k8_003230 := [concat(".", p) | some p in [["files", "kubelet_config_yaml"]]; not _collected(p)]

default r_cntr_k8_003230 := false

r_cntr_k8_003230 if {
	count(missing_r_cntr_k8_003230) == 0
	_files_mode_le(input.files["kubelet_config_yaml"], "644")
}

default detail_r_cntr_k8_003230 := ""

detail_r_cntr_k8_003230 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003230", concat(", ", missing_r_cntr_k8_003230)]) if count(missing_r_cntr_k8_003230) > 0

detail_r_cntr_k8_003230 := "CNTR-K8-003230: check failed — every kubelet_config_yaml file must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_003230) == 0
	not r_cntr_k8_003230
}

detail_r_cntr_k8_003230 := "CNTR-K8-003230: Not_a_Finding" if r_cntr_k8_003230

finding_r_cntr_k8_003230 := {
	"vuln_id": "V-242456",
	"stig_id": "CNTR-K8-003230",
	"severity": "CAT II",
	"rule_title": "The Kubernetes kubelet config must have file permissions set to 644 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003230,
	"detail": detail_r_cntr_k8_003230,
}

status_r_cntr_k8_003230 := "Not_a_Finding" if r_cntr_k8_003230

status_r_cntr_k8_003230 := "Open" if not r_cntr_k8_003230

# CNTR-K8-003240 | V-242457 | CAT II | machine
missing_r_cntr_k8_003240 := [concat(".", p) | some p in [["files", "kubelet_config_yaml"]]; not _collected(p)]

default r_cntr_k8_003240 := false

r_cntr_k8_003240 if {
	count(missing_r_cntr_k8_003240) == 0
	_files_owned(input.files["kubelet_config_yaml"], "root", "root")
}

default detail_r_cntr_k8_003240 := ""

detail_r_cntr_k8_003240 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003240", concat(", ", missing_r_cntr_k8_003240)]) if count(missing_r_cntr_k8_003240) > 0

detail_r_cntr_k8_003240 := "CNTR-K8-003240: check failed — every kubelet_config_yaml file must be owned by root:root" if {
	count(missing_r_cntr_k8_003240) == 0
	not r_cntr_k8_003240
}

detail_r_cntr_k8_003240 := "CNTR-K8-003240: Not_a_Finding" if r_cntr_k8_003240

finding_r_cntr_k8_003240 := {
	"vuln_id": "V-242457",
	"stig_id": "CNTR-K8-003240",
	"severity": "CAT II",
	"rule_title": "The Kubernetes kubelet config must be owned by root.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003240,
	"detail": detail_r_cntr_k8_003240,
}

status_r_cntr_k8_003240 := "Not_a_Finding" if r_cntr_k8_003240

status_r_cntr_k8_003240 := "Open" if not r_cntr_k8_003240

# CNTR-K8-003260 | V-242459 | CAT II | machine
missing_r_cntr_k8_003260 := [concat(".", p) | some p in [["files", "etcd_data"]]; not _collected(p)]

default r_cntr_k8_003260 := false

r_cntr_k8_003260 if {
	count(missing_r_cntr_k8_003260) == 0
	_files_mode_le(input.files["etcd_data"], "644")
}

default detail_r_cntr_k8_003260 := ""

detail_r_cntr_k8_003260 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003260", concat(", ", missing_r_cntr_k8_003260)]) if count(missing_r_cntr_k8_003260) > 0

detail_r_cntr_k8_003260 := "CNTR-K8-003260: check failed — every etcd_data file must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_003260) == 0
	not r_cntr_k8_003260
}

detail_r_cntr_k8_003260 := "CNTR-K8-003260: Not_a_Finding" if r_cntr_k8_003260

finding_r_cntr_k8_003260 := {
	"vuln_id": "V-242459",
	"stig_id": "CNTR-K8-003260",
	"severity": "CAT II",
	"rule_title": "The Kubernetes etcd must have file permissions set to 644 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003260,
	"detail": detail_r_cntr_k8_003260,
}

status_r_cntr_k8_003260 := "Not_a_Finding" if r_cntr_k8_003260

status_r_cntr_k8_003260 := "Open" if not r_cntr_k8_003260

# CNTR-K8-003270 | V-242460 | CAT II | machine
missing_r_cntr_k8_003270 := [concat(".", p) | some p in [["files", "control_plane_confs"]]; not _collected(p)]

default r_cntr_k8_003270 := false

r_cntr_k8_003270 if {
	count(missing_r_cntr_k8_003270) == 0
	_files_mode_le(input.files["control_plane_confs"], "644")
}

default detail_r_cntr_k8_003270 := ""

detail_r_cntr_k8_003270 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003270", concat(", ", missing_r_cntr_k8_003270)]) if count(missing_r_cntr_k8_003270) > 0

detail_r_cntr_k8_003270 := "CNTR-K8-003270: check failed — every control_plane_confs file must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_003270) == 0
	not r_cntr_k8_003270
}

detail_r_cntr_k8_003270 := "CNTR-K8-003270: Not_a_Finding" if r_cntr_k8_003270

finding_r_cntr_k8_003270 := {
	"vuln_id": "V-242460",
	"stig_id": "CNTR-K8-003270",
	"severity": "CAT II",
	"rule_title": "The Kubernetes admin kubeconfig must have file permissions set to 644 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003270,
	"detail": detail_r_cntr_k8_003270,
}

status_r_cntr_k8_003270 := "Not_a_Finding" if r_cntr_k8_003270

status_r_cntr_k8_003270 := "Open" if not r_cntr_k8_003270

# CNTR-K8-003280 | V-242461 | CAT II | machine
missing_r_cntr_k8_003280 := [concat(".", p) | some p in [["api_server", "flags"], ["api_server", "audit_policy"]]; not _collected(p)]

default r_cntr_k8_003280 := false

r_cntr_k8_003280 if {
	count(missing_r_cntr_k8_003280) == 0
	_nonempty(_flag(input.api_server.flags, "audit-policy-file"))
	input.api_server.audit_policy.kind == "Policy"
	count(input.api_server.audit_policy.rules) > 0
}

default detail_r_cntr_k8_003280 := ""

detail_r_cntr_k8_003280 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003280", concat(", ", missing_r_cntr_k8_003280)]) if count(missing_r_cntr_k8_003280) > 0

detail_r_cntr_k8_003280 := "CNTR-K8-003280: check failed — --audit-policy-file set with valid content" if {
	count(missing_r_cntr_k8_003280) == 0
	not r_cntr_k8_003280
}

detail_r_cntr_k8_003280 := "CNTR-K8-003280: Not_a_Finding" if r_cntr_k8_003280

finding_r_cntr_k8_003280 := {
	"vuln_id": "V-242461",
	"stig_id": "CNTR-K8-003280",
	"severity": "CAT II",
	"rule_title": "Kubernetes API Server audit logs must be enabled.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003280,
	"detail": detail_r_cntr_k8_003280,
}

status_r_cntr_k8_003280 := "Not_a_Finding" if r_cntr_k8_003280

status_r_cntr_k8_003280 := "Open" if not r_cntr_k8_003280

# CNTR-K8-003290 | V-242462 | CAT II | machine
missing_r_cntr_k8_003290 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_003290 := false

r_cntr_k8_003290 if {
	count(missing_r_cntr_k8_003290) == 0
	_nonempty(_flag(input.api_server.flags, "audit-log-maxsize"))
	to_number(_flag(input.api_server.flags, "audit-log-maxsize")) >= 100
}

default detail_r_cntr_k8_003290 := ""

detail_r_cntr_k8_003290 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003290", concat(", ", missing_r_cntr_k8_003290)]) if count(missing_r_cntr_k8_003290) > 0

detail_r_cntr_k8_003290 := "CNTR-K8-003290: check failed — api_server.flags --audit-log-maxsize must be set to at least 100" if {
	count(missing_r_cntr_k8_003290) == 0
	not r_cntr_k8_003290
}

detail_r_cntr_k8_003290 := "CNTR-K8-003290: Not_a_Finding" if r_cntr_k8_003290

finding_r_cntr_k8_003290 := {
	"vuln_id": "V-242462",
	"stig_id": "CNTR-K8-003290",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API Server must be set to audit log max size.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003290,
	"detail": detail_r_cntr_k8_003290,
}

status_r_cntr_k8_003290 := "Not_a_Finding" if r_cntr_k8_003290

status_r_cntr_k8_003290 := "Open" if not r_cntr_k8_003290

# CNTR-K8-003300 | V-242463 | CAT II | machine
missing_r_cntr_k8_003300 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_003300 := false

r_cntr_k8_003300 if {
	count(missing_r_cntr_k8_003300) == 0
	_nonempty(_flag(input.api_server.flags, "audit-log-maxbackup"))
	to_number(_flag(input.api_server.flags, "audit-log-maxbackup")) >= 10
}

default detail_r_cntr_k8_003300 := ""

detail_r_cntr_k8_003300 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003300", concat(", ", missing_r_cntr_k8_003300)]) if count(missing_r_cntr_k8_003300) > 0

detail_r_cntr_k8_003300 := "CNTR-K8-003300: check failed — api_server.flags --audit-log-maxbackup must be set to at least 10" if {
	count(missing_r_cntr_k8_003300) == 0
	not r_cntr_k8_003300
}

detail_r_cntr_k8_003300 := "CNTR-K8-003300: Not_a_Finding" if r_cntr_k8_003300

finding_r_cntr_k8_003300 := {
	"vuln_id": "V-242463",
	"stig_id": "CNTR-K8-003300",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API Server must be set to audit log maximum backup.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003300,
	"detail": detail_r_cntr_k8_003300,
}

status_r_cntr_k8_003300 := "Not_a_Finding" if r_cntr_k8_003300

status_r_cntr_k8_003300 := "Open" if not r_cntr_k8_003300

# CNTR-K8-003310 | V-242464 | CAT II | machine
missing_r_cntr_k8_003310 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_003310 := false

r_cntr_k8_003310 if {
	count(missing_r_cntr_k8_003310) == 0
	_nonempty(_flag(input.api_server.flags, "audit-log-maxage"))
	to_number(_flag(input.api_server.flags, "audit-log-maxage")) >= 30
}

default detail_r_cntr_k8_003310 := ""

detail_r_cntr_k8_003310 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003310", concat(", ", missing_r_cntr_k8_003310)]) if count(missing_r_cntr_k8_003310) > 0

detail_r_cntr_k8_003310 := "CNTR-K8-003310: check failed — api_server.flags --audit-log-maxage must be set to at least 30" if {
	count(missing_r_cntr_k8_003310) == 0
	not r_cntr_k8_003310
}

detail_r_cntr_k8_003310 := "CNTR-K8-003310: Not_a_Finding" if r_cntr_k8_003310

finding_r_cntr_k8_003310 := {
	"vuln_id": "V-242464",
	"stig_id": "CNTR-K8-003310",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API Server audit log retention must be set.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003310,
	"detail": detail_r_cntr_k8_003310,
}

status_r_cntr_k8_003310 := "Not_a_Finding" if r_cntr_k8_003310

status_r_cntr_k8_003310 := "Open" if not r_cntr_k8_003310

# CNTR-K8-003320 | V-242465 | CAT II | machine
missing_r_cntr_k8_003320 := [concat(".", p) | some p in [["api_server", "flags"]]; not _collected(p)]

default r_cntr_k8_003320 := false

r_cntr_k8_003320 if {
	count(missing_r_cntr_k8_003320) == 0
	_nonempty(_flag(input.api_server.flags, "audit-log-path"))
	startswith(_flag(input.api_server.flags, "audit-log-path"), "/")
}

default detail_r_cntr_k8_003320 := ""

detail_r_cntr_k8_003320 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003320", concat(", ", missing_r_cntr_k8_003320)]) if count(missing_r_cntr_k8_003320) > 0

detail_r_cntr_k8_003320 := "CNTR-K8-003320: check failed — api_server.flags --audit-log-path must be set to a valid path" if {
	count(missing_r_cntr_k8_003320) == 0
	not r_cntr_k8_003320
}

detail_r_cntr_k8_003320 := "CNTR-K8-003320: Not_a_Finding" if r_cntr_k8_003320

finding_r_cntr_k8_003320 := {
	"vuln_id": "V-242465",
	"stig_id": "CNTR-K8-003320",
	"severity": "CAT II",
	"rule_title": "The Kubernetes API Server audit log path must be set.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003320,
	"detail": detail_r_cntr_k8_003320,
}

status_r_cntr_k8_003320 := "Not_a_Finding" if r_cntr_k8_003320

status_r_cntr_k8_003320 := "Open" if not r_cntr_k8_003320

# CNTR-K8-003330 | V-242466 | CAT II | machine
missing_r_cntr_k8_003330 := [concat(".", p) | some p in [["files", "pki"]]; not _collected(p)]

default r_cntr_k8_003330 := false

r_cntr_k8_003330 if {
	count(missing_r_cntr_k8_003330) == 0
	_files_suffix_mode_le(input.files["pki"], ".crt", "644")
}

default detail_r_cntr_k8_003330 := ""

detail_r_cntr_k8_003330 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003330", concat(", ", missing_r_cntr_k8_003330)]) if count(missing_r_cntr_k8_003330) > 0

detail_r_cntr_k8_003330 := "CNTR-K8-003330: check failed — every .crt file under pki must have mode 644 or more restrictive" if {
	count(missing_r_cntr_k8_003330) == 0
	not r_cntr_k8_003330
}

detail_r_cntr_k8_003330 := "CNTR-K8-003330: Not_a_Finding" if r_cntr_k8_003330

finding_r_cntr_k8_003330 := {
	"vuln_id": "V-242466",
	"stig_id": "CNTR-K8-003330",
	"severity": "CAT II",
	"rule_title": "The Kubernetes PKI CRT must have file permissions set to 644 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003330,
	"detail": detail_r_cntr_k8_003330,
}

status_r_cntr_k8_003330 := "Not_a_Finding" if r_cntr_k8_003330

status_r_cntr_k8_003330 := "Open" if not r_cntr_k8_003330

# CNTR-K8-003340 | V-242467 | CAT II | machine
missing_r_cntr_k8_003340 := [concat(".", p) | some p in [["files", "pki"]]; not _collected(p)]

default r_cntr_k8_003340 := false

r_cntr_k8_003340 if {
	count(missing_r_cntr_k8_003340) == 0
	_files_suffix_mode_le(input.files["pki"], ".key", "600")
}

default detail_r_cntr_k8_003340 := ""

detail_r_cntr_k8_003340 := sprintf("%s: evidence missing — %s not collected", ["CNTR-K8-003340", concat(", ", missing_r_cntr_k8_003340)]) if count(missing_r_cntr_k8_003340) > 0

detail_r_cntr_k8_003340 := "CNTR-K8-003340: check failed — every .key file under pki must have mode 600 or more restrictive" if {
	count(missing_r_cntr_k8_003340) == 0
	not r_cntr_k8_003340
}

detail_r_cntr_k8_003340 := "CNTR-K8-003340: Not_a_Finding" if r_cntr_k8_003340

finding_r_cntr_k8_003340 := {
	"vuln_id": "V-242467",
	"stig_id": "CNTR-K8-003340",
	"severity": "CAT II",
	"rule_title": "The Kubernetes PKI keys must have file permissions set to 600 or more restrictive.",
	"check_type": "machine",
	"status": status_r_cntr_k8_003340,
	"detail": detail_r_cntr_k8_003340,
}

status_r_cntr_k8_003340 := "Not_a_Finding" if r_cntr_k8_003340

status_r_cntr_k8_003340 := "Open" if not r_cntr_k8_003340

findings := [
	finding_r_cntr_k8_000150,
	finding_r_cntr_k8_000160,
	finding_r_cntr_k8_000170,
	finding_r_cntr_k8_000180,
	finding_r_cntr_k8_000190,
	finding_r_cntr_k8_000220,
	finding_r_cntr_k8_000270,
	finding_r_cntr_k8_000290,
	finding_r_cntr_k8_000300,
	finding_r_cntr_k8_000310,
	finding_r_cntr_k8_000330,
	finding_r_cntr_k8_000350,
	finding_r_cntr_k8_000360,
	finding_r_cntr_k8_000370,
	finding_r_cntr_k8_000380,
	finding_r_cntr_k8_000400,
	finding_r_cntr_k8_000410,
	finding_r_cntr_k8_000420,
	finding_r_cntr_k8_000430,
	finding_r_cntr_k8_000440,
	finding_r_cntr_k8_000450,
	finding_r_cntr_k8_000460,
	finding_r_cntr_k8_000470,
	finding_r_cntr_k8_000610,
	finding_r_cntr_k8_000700,
	finding_r_cntr_k8_000850,
	finding_r_cntr_k8_000860,
	finding_r_cntr_k8_000880,
	finding_r_cntr_k8_000890,
	finding_r_cntr_k8_000900,
	finding_r_cntr_k8_000910,
	finding_r_cntr_k8_000920,
	finding_r_cntr_k8_000930,
	finding_r_cntr_k8_000940,
	finding_r_cntr_k8_000950,
	finding_r_cntr_k8_000960,
	finding_r_cntr_k8_001160,
	finding_r_cntr_k8_001161,
	finding_r_cntr_k8_001162,
	finding_r_cntr_k8_001163,
	finding_r_cntr_k8_001300,
	finding_r_cntr_k8_001360,
	finding_r_cntr_k8_001400,
	finding_r_cntr_k8_001410,
	finding_r_cntr_k8_001420,
	finding_r_cntr_k8_001430,
	finding_r_cntr_k8_001440,
	finding_r_cntr_k8_001450,
	finding_r_cntr_k8_001460,
	finding_r_cntr_k8_001470,
	finding_r_cntr_k8_001480,
	finding_r_cntr_k8_001490,
	finding_r_cntr_k8_001500,
	finding_r_cntr_k8_001510,
	finding_r_cntr_k8_001520,
	finding_r_cntr_k8_001530,
	finding_r_cntr_k8_001540,
	finding_r_cntr_k8_001550,
	finding_r_cntr_k8_001620,
	finding_r_cntr_k8_002000,
	finding_r_cntr_k8_002001,
	finding_r_cntr_k8_002010,
	finding_r_cntr_k8_002011,
	finding_r_cntr_k8_002600,
	finding_r_cntr_k8_002620,
	finding_r_cntr_k8_002630,
	finding_r_cntr_k8_002640,
	finding_r_cntr_k8_002700,
	finding_r_cntr_k8_002720,
	finding_r_cntr_k8_003110,
	finding_r_cntr_k8_003120,
	finding_r_cntr_k8_003130,
	finding_r_cntr_k8_003140,
	finding_r_cntr_k8_003150,
	finding_r_cntr_k8_003160,
	finding_r_cntr_k8_003170,
	finding_r_cntr_k8_003180,
	finding_r_cntr_k8_003190,
	finding_r_cntr_k8_003200,
	finding_r_cntr_k8_003210,
	finding_r_cntr_k8_003220,
	finding_r_cntr_k8_003230,
	finding_r_cntr_k8_003240,
	finding_r_cntr_k8_003260,
	finding_r_cntr_k8_003270,
	finding_r_cntr_k8_003280,
	finding_r_cntr_k8_003290,
	finding_r_cntr_k8_003300,
	finding_r_cntr_k8_003310,
	finding_r_cntr_k8_003320,
	finding_r_cntr_k8_003330,
	finding_r_cntr_k8_003340,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
