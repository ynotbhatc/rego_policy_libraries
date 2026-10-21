# METADATA
# title: "DISA STIG — Rancher Government Solutions RKE2 Security Technical Implementation Guide"
# custom:
#   class: security
#   framework: stig_rke2
#   source: disa
#   domains: [kubernetes, container]
#   coverage:
#     checks: 21
#     cited: 21
#     density: sized
#     basis: size
#     tested: true
#     entrypoint: none
#     guard: n/a
#     as_of: v2.4.2
package stig.rke2.core

# DISA STIG — Rancher Government Solutions RKE2 Security Technical Implementation Guide
# V2R7 | Release: 7 Benchmark Date: 01 Jul 2026
# 21 rules — every rule in the catalog (4 CAT I): 15 machine-checked,
# 1 machine-checked plus an attestation, 5 attestation-only (DISA's check is a
# documentation review or human judgment). IDs/severities/titles verified against the
# DISA XCCDF on 2026-10-21 (tools/stig_generators/gen_k8s.py; regenerate, don't hand-edit).
# FAIL-CLOSED: a rule whose evidence is absent is Open with detail
# "<STIG-ID>: evidence missing — <field> not collected"; attestations are Open until
# input.attest.<key> is true. Input contract: gen_k8s.py docstring, summarised here:
#   RKE2 input contract (one evaluation per RKE2 server node):
#     input.rke2.config                        : the EFFECTIVE RKE2 config: /etc/rancher/rke2/config.yaml merged with
#                                                config.yaml.d/*.yaml drop-ins in RKE2's order (same spelling rules)
#     input.rke2.args.kube_apiserver / kube_controller_manager / kube_scheduler / kubelet
#                                              : the component args RKE2 renders (ps -ef), flag -> value
#     input.rke2.audit_policy                  : parsed audit policy file {rules[{level, resources[{group, resources}]}]}
#     input.rke2.pss_defaults                  : `defaults` of the pod-security-admission-config-file
#     input.rke2.files.<group>                 : [{name, mode, owner, group}] for groups etc (/etc/rancher/rke2),
#                                                root (/var/lib/rancher/rke2), agent, bin, data, server
#     The rendered args are authoritative, and every <component>-arg entry in the effective config for a
#     checked flag must carry the same value (a stale or conflicting entry fails); files must include the
#     entries DISA names (config.yaml; agent, bin, data, server; cred, db, tls, manifests, logs, token; ...).
#     input.cluster.namespace_resources / input.cluster.images / input.collection_status : as for Kubernetes
#     input.attest.<key>                       : organizational attestations
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
# (a trailing "+" is RKE2's config.yaml.d append marker: "kube-apiserver-arg+" is the same key)
_norm(k) := replace(trim_suffix(trim_left(k, "-"), "+"), "_", "-")

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
	is_string(mode) # a number is ambiguous (644 decimal or the octal 0644 = 420?): collect modes as strings
	m := mode
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

# every required path is present in the collected list (a partial listing must not pass)
_has_paths(fs, paths) if {
	is_array(fs)
	every p in paths {
		some f in fs
		f.path == p
	}
}

_has_names(fs, names) if {
	is_array(fs)
	every n in names {
		some f in fs
		f.name == n
	}
}

# KubeletConfiguration values (and their defaults) apply only when the kubelet runs with --config;
# without a config file the kubelet's command-line defaults apply (e.g. read-only port 10255).
_kubelet_config_in_use if _nonempty(_flag(input.kubelet.flags, "config"))

# RKE2: every "<flag>=<value>" entry under <cfgkey> (or "<cfgkey>+") in the effective config must carry
# the value the running component shows. Entries are a string or a list of strings; anything else fails.
_rke2_arg_agrees(args, cfgkey, name) if {
	running := _flag(args, name)
	is_object(input.rke2.config)
	entries := [e |
		some k in object.keys(input.rke2.config)
		_norm(k) == cfgkey
		some e in _as_list(input.rke2.config[k])
	]
	every e in entries {
		is_string(e)
		_arg_ok(e, name, running)
	}
}

_as_list(x) := x if is_array(x)

_as_list(x) := [x] if not is_array(x)

# an entry for another flag is irrelevant; an entry for this flag must carry the running value
_arg_ok(e, name, _) if _norm(split(e, "=")[0]) != name

_arg_ok(e, name, running) if {
	p := split(e, "=")
	_norm(p[0]) == name
	count(p) >= 2
	concat("=", array.slice(p, 1, count(p))) == running
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

# CNTR-R2-000010 | V-254553 | CAT I | machine
missing_r_cntr_r2_000010 := [concat(".", p) | some p in [["rke2", "args", "kube_apiserver"], ["rke2", "args", "kube_controller_manager"], ["rke2", "args", "kube_scheduler"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000010 := false

r_cntr_r2_000010 if {
	count(missing_r_cntr_r2_000010) == 0
	_flag(input.rke2.args.kube_apiserver, "tls-min-version") in {"VersionTLS12", "VersionTLS13"}
	_flag(input.rke2.args.kube_controller_manager, "tls-min-version") in {"VersionTLS12", "VersionTLS13"}
	_flag(input.rke2.args.kube_scheduler, "tls-min-version") in {"VersionTLS12", "VersionTLS13"}
	_nonempty(_flag(input.rke2.args.kube_apiserver, "tls-cipher-suites"))
	_list_has_all(_flag(input.rke2.args.kube_apiserver, "tls-cipher-suites"), ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"])
	_nonempty(_flag(input.rke2.args.kube_controller_manager, "tls-cipher-suites"))
	_list_has_all(_flag(input.rke2.args.kube_controller_manager, "tls-cipher-suites"), ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"])
	_nonempty(_flag(input.rke2.args.kube_scheduler, "tls-cipher-suites"))
	_list_has_all(_flag(input.rke2.args.kube_scheduler, "tls-cipher-suites"), ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"])
	_rke2_arg_agrees(input.rke2.args.kube_apiserver, "kube-apiserver-arg", "tls-min-version")
	_rke2_arg_agrees(input.rke2.args.kube_apiserver, "kube-apiserver-arg", "tls-cipher-suites")
	_rke2_arg_agrees(input.rke2.args.kube_controller_manager, "kube-controller-manager-arg", "tls-min-version")
	_rke2_arg_agrees(input.rke2.args.kube_controller_manager, "kube-controller-manager-arg", "tls-cipher-suites")
	_rke2_arg_agrees(input.rke2.args.kube_scheduler, "kube-scheduler-arg", "tls-min-version")
	_rke2_arg_agrees(input.rke2.args.kube_scheduler, "kube-scheduler-arg", "tls-cipher-suites")
}

default detail_r_cntr_r2_000010 := ""

detail_r_cntr_r2_000010 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000010", concat(", ", missing_r_cntr_r2_000010)]) if count(missing_r_cntr_r2_000010) > 0

detail_r_cntr_r2_000010 := "CNTR-R2-000010: check failed — kube-apiserver, kube-controller-manager and kube-scheduler: --tls-min-version VersionTLS12+ and --tls-cipher-suites including TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000010) == 0
	not r_cntr_r2_000010
}

detail_r_cntr_r2_000010 := "CNTR-R2-000010: Not_a_Finding" if r_cntr_r2_000010

finding_r_cntr_r2_000010 := {
	"vuln_id": "V-254553",
	"stig_id": "CNTR-R2-000010",
	"severity": "CAT I",
	"rule_title": "Rancher RKE2 must protect authenticity of communications sessions with the use of FIPS-validated 140-2 or 140-3 security requirements for cryptographic modules.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000010,
	"detail": detail_r_cntr_r2_000010,
}

status_r_cntr_r2_000010 := "Not_a_Finding" if r_cntr_r2_000010

status_r_cntr_r2_000010 := "Open" if not r_cntr_r2_000010

# CNTR-R2-000030 | V-254554 | CAT II | machine
missing_r_cntr_r2_000030 := [concat(".", p) | some p in [["rke2", "args", "kube_controller_manager"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000030 := false

r_cntr_r2_000030 if {
	count(missing_r_cntr_r2_000030) == 0
	_flag(input.rke2.args.kube_controller_manager, "use-service-account-credentials") == "true"
	_rke2_arg_agrees(input.rke2.args.kube_controller_manager, "kube-controller-manager-arg", "use-service-account-credentials")
}

default detail_r_cntr_r2_000030 := ""

detail_r_cntr_r2_000030 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000030", concat(", ", missing_r_cntr_r2_000030)]) if count(missing_r_cntr_r2_000030) > 0

detail_r_cntr_r2_000030 := "CNTR-R2-000030: check failed — rke2.args.kube_controller_manager --use-service-account-credentials must be \"true\"; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000030) == 0
	not r_cntr_r2_000030
}

detail_r_cntr_r2_000030 := "CNTR-R2-000030: Not_a_Finding" if r_cntr_r2_000030

finding_r_cntr_r2_000030 := {
	"vuln_id": "V-254554",
	"stig_id": "CNTR-R2-000030",
	"severity": "CAT II",
	"rule_title": "RKE2 must use a centralized user management solution to support account management functions.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000030,
	"detail": detail_r_cntr_r2_000030,
}

status_r_cntr_r2_000030 := "Not_a_Finding" if r_cntr_r2_000030

status_r_cntr_r2_000030 := "Open" if not r_cntr_r2_000030

# CNTR-R2-000060 | V-254555 | CAT II | machine
missing_r_cntr_r2_000060 := [concat(".", p) | some p in [["rke2", "args", "kube_apiserver"], ["rke2", "config"], ["rke2", "audit_policy"]]; not _collected(p)]

default r_cntr_r2_000060 := false

r_cntr_r2_000060 if {
	count(missing_r_cntr_r2_000060) == 0
	_nonempty(_flag(input.rke2.args.kube_apiserver, "audit-policy-file"))
	_flag(input.rke2.args.kube_apiserver, "audit-log-mode") == "blocking-strict"
	_flag(input.rke2.config, "profile") in {"cis", "cis-1.23", "cis-1.6"}
	r1 := input.rke2.audit_policy.rules[0]
	r1.level == "Metadata"
	some g1 in r1.resources
	g1.group == ""
	"secrets" in g1.resources
	r2 := input.rke2.audit_policy.rules[1]
	r2.level == "RequestResponse"
	some g2 in r2.resources
	"*" in g2.resources
	_rke2_arg_agrees(input.rke2.args.kube_apiserver, "kube-apiserver-arg", "audit-policy-file")
	_rke2_arg_agrees(input.rke2.args.kube_apiserver, "kube-apiserver-arg", "audit-log-mode")
}

default detail_r_cntr_r2_000060 := ""

detail_r_cntr_r2_000060 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000060", concat(", ", missing_r_cntr_r2_000060)]) if count(missing_r_cntr_r2_000060) > 0

detail_r_cntr_r2_000060 := "CNTR-R2-000060: check failed — --audit-policy-file set, --audit-log-mode blocking-strict, profile cis, audit policy as DISA lists; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000060) == 0
	not r_cntr_r2_000060
}

detail_r_cntr_r2_000060 := "CNTR-R2-000060: Not_a_Finding" if r_cntr_r2_000060

finding_r_cntr_r2_000060 := {
	"vuln_id": "V-254555",
	"stig_id": "CNTR-R2-000060",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 components must be configured in accordance with the security configuration settings based on DOD security configuration or implementation guidance, including SRGs, STIGs, NSA configuration guides, CTOs, and",
	"check_type": "machine",
	"status": status_r_cntr_r2_000060,
	"detail": detail_r_cntr_r2_000060,
}

status_r_cntr_r2_000060 := "Not_a_Finding" if r_cntr_r2_000060

status_r_cntr_r2_000060 := "Open" if not r_cntr_r2_000060

# CNTR-R2-000100 | V-254556 | CAT II | machine
missing_r_cntr_r2_000100 := [concat(".", p) | some p in [["rke2", "args", "kube_controller_manager"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000100 := false

r_cntr_r2_000100 if {
	count(missing_r_cntr_r2_000100) == 0
	_flag(input.rke2.args.kube_controller_manager, "bind-address") == "127.0.0.1"
	_rke2_arg_agrees(input.rke2.args.kube_controller_manager, "kube-controller-manager-arg", "bind-address")
}

default detail_r_cntr_r2_000100 := ""

detail_r_cntr_r2_000100 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000100", concat(", ", missing_r_cntr_r2_000100)]) if count(missing_r_cntr_r2_000100) > 0

detail_r_cntr_r2_000100 := "CNTR-R2-000100: check failed — rke2.args.kube_controller_manager --bind-address must be \"127.0.0.1\"; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000100) == 0
	not r_cntr_r2_000100
}

detail_r_cntr_r2_000100 := "CNTR-R2-000100: Not_a_Finding" if r_cntr_r2_000100

finding_r_cntr_r2_000100 := {
	"vuln_id": "V-254556",
	"stig_id": "CNTR-R2-000100",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Controller Manager must have secure binding.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000100,
	"detail": detail_r_cntr_r2_000100,
}

status_r_cntr_r2_000100 := "Not_a_Finding" if r_cntr_r2_000100

status_r_cntr_r2_000100 := "Open" if not r_cntr_r2_000100

# CNTR-R2-000110 | V-254557 | CAT II | machine
missing_r_cntr_r2_000110 := [concat(".", p) | some p in [["rke2", "args", "kubelet"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000110 := false

r_cntr_r2_000110 if {
	count(missing_r_cntr_r2_000110) == 0
	_flag(input.rke2.args.kubelet, "anonymous-auth") == "false"
	_rke2_arg_agrees(input.rke2.args.kubelet, "kubelet-arg", "anonymous-auth")
}

default detail_r_cntr_r2_000110 := ""

detail_r_cntr_r2_000110 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000110", concat(", ", missing_r_cntr_r2_000110)]) if count(missing_r_cntr_r2_000110) > 0

detail_r_cntr_r2_000110 := "CNTR-R2-000110: check failed — rke2.args.kubelet --anonymous-auth must be \"false\"; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000110) == 0
	not r_cntr_r2_000110
}

detail_r_cntr_r2_000110 := "CNTR-R2-000110: Not_a_Finding" if r_cntr_r2_000110

finding_r_cntr_r2_000110 := {
	"vuln_id": "V-254557",
	"stig_id": "CNTR-R2-000110",
	"severity": "CAT II",
	"rule_title": "The Kubernetes Kubelet must have anonymous authentication disabled.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000110,
	"detail": detail_r_cntr_r2_000110,
}

status_r_cntr_r2_000110 := "Not_a_Finding" if r_cntr_r2_000110

status_r_cntr_r2_000110 := "Open" if not r_cntr_r2_000110

# CNTR-R2-000130 | V-254559 | CAT I | machine
missing_r_cntr_r2_000130 := [concat(".", p) | some p in [["rke2", "args", "kubelet"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000130 := false

r_cntr_r2_000130 if {
	count(missing_r_cntr_r2_000130) == 0
	_flag(input.rke2.args.kubelet, "read-only-port") == "0"
	_rke2_arg_agrees(input.rke2.args.kubelet, "kubelet-arg", "read-only-port")
}

default detail_r_cntr_r2_000130 := ""

detail_r_cntr_r2_000130 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000130", concat(", ", missing_r_cntr_r2_000130)]) if count(missing_r_cntr_r2_000130) > 0

detail_r_cntr_r2_000130 := "CNTR-R2-000130: check failed — rke2.args.kubelet --read-only-port must be \"0\"; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000130) == 0
	not r_cntr_r2_000130
}

detail_r_cntr_r2_000130 := "CNTR-R2-000130: Not_a_Finding" if r_cntr_r2_000130

finding_r_cntr_r2_000130 := {
	"vuln_id": "V-254559",
	"stig_id": "CNTR-R2-000130",
	"severity": "CAT I",
	"rule_title": "The Kubernetes Kubelet must have the read-only port flag disabled.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000130,
	"detail": detail_r_cntr_r2_000130,
}

status_r_cntr_r2_000130 := "Not_a_Finding" if r_cntr_r2_000130

status_r_cntr_r2_000130 := "Open" if not r_cntr_r2_000130

# CNTR-R2-000150 | V-254561 | CAT I | machine
missing_r_cntr_r2_000150 := [concat(".", p) | some p in [["rke2", "args", "kubelet"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000150 := false

r_cntr_r2_000150 if {
	count(missing_r_cntr_r2_000150) == 0
	_flag(input.rke2.args.kubelet, "authorization-mode") == "Webhook"
	_rke2_arg_agrees(input.rke2.args.kubelet, "kubelet-arg", "authorization-mode")
}

default detail_r_cntr_r2_000150 := ""

detail_r_cntr_r2_000150 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000150", concat(", ", missing_r_cntr_r2_000150)]) if count(missing_r_cntr_r2_000150) > 0

detail_r_cntr_r2_000150 := "CNTR-R2-000150: check failed — rke2.args.kubelet --authorization-mode must be \"Webhook\"; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000150) == 0
	not r_cntr_r2_000150
}

detail_r_cntr_r2_000150 := "CNTR-R2-000150: Not_a_Finding" if r_cntr_r2_000150

finding_r_cntr_r2_000150 := {
	"vuln_id": "V-254561",
	"stig_id": "CNTR-R2-000150",
	"severity": "CAT I",
	"rule_title": "The Kubernetes kubelet must enable explicit authorization.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000150,
	"detail": detail_r_cntr_r2_000150,
}

status_r_cntr_r2_000150 := "Not_a_Finding" if r_cntr_r2_000150

status_r_cntr_r2_000150 := "Open" if not r_cntr_r2_000150

# CNTR-R2-000160 | V-254562 | CAT I | machine
missing_r_cntr_r2_000160 := [concat(".", p) | some p in [["rke2", "args", "kube_apiserver"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000160 := false

r_cntr_r2_000160 if {
	count(missing_r_cntr_r2_000160) == 0
	_flag(input.rke2.args.kube_apiserver, "anonymous-auth") == "false"
	_rke2_arg_agrees(input.rke2.args.kube_apiserver, "kube-apiserver-arg", "anonymous-auth")
}

default detail_r_cntr_r2_000160 := ""

detail_r_cntr_r2_000160 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000160", concat(", ", missing_r_cntr_r2_000160)]) if count(missing_r_cntr_r2_000160) > 0

detail_r_cntr_r2_000160 := "CNTR-R2-000160: check failed — rke2.args.kube_apiserver --anonymous-auth must be \"false\"; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000160) == 0
	not r_cntr_r2_000160
}

detail_r_cntr_r2_000160 := "CNTR-R2-000160: Not_a_Finding" if r_cntr_r2_000160

finding_r_cntr_r2_000160 := {
	"vuln_id": "V-254562",
	"stig_id": "CNTR-R2-000160",
	"severity": "CAT I",
	"rule_title": "The Kubernetes API server must have anonymous authentication disabled.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000160,
	"detail": detail_r_cntr_r2_000160,
}

status_r_cntr_r2_000160 := "Not_a_Finding" if r_cntr_r2_000160

status_r_cntr_r2_000160 := "Open" if not r_cntr_r2_000160

# CNTR-R2-000320 | V-254563 | CAT II | machine
missing_r_cntr_r2_000320 := [concat(".", p) | some p in [["rke2", "args", "kube_apiserver"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000320 := false

r_cntr_r2_000320 if {
	count(missing_r_cntr_r2_000320) == 0
	_nonempty(_flag(input.rke2.args.kube_apiserver, "audit-log-maxage"))
	to_number(_flag(input.rke2.args.kube_apiserver, "audit-log-maxage")) >= 30
	_rke2_arg_agrees(input.rke2.args.kube_apiserver, "kube-apiserver-arg", "audit-log-maxage")
}

default detail_r_cntr_r2_000320 := ""

detail_r_cntr_r2_000320 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000320", concat(", ", missing_r_cntr_r2_000320)]) if count(missing_r_cntr_r2_000320) > 0

detail_r_cntr_r2_000320 := "CNTR-R2-000320: check failed — rke2.args.kube_apiserver --audit-log-maxage must be set to at least 30; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000320) == 0
	not r_cntr_r2_000320
}

detail_r_cntr_r2_000320 := "CNTR-R2-000320: Not_a_Finding" if r_cntr_r2_000320

finding_r_cntr_r2_000320 := {
	"vuln_id": "V-254563",
	"stig_id": "CNTR-R2-000320",
	"severity": "CAT II",
	"rule_title": "All audit records must identify any containers associated with the event within Rancher RKE2.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000320,
	"detail": detail_r_cntr_r2_000320,
}

status_r_cntr_r2_000320 := "Not_a_Finding" if r_cntr_r2_000320

status_r_cntr_r2_000320 := "Open" if not r_cntr_r2_000320

# CNTR-R2-000460 | V-268321 | CAT II | attestation
missing_r_cntr_r2_000460 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_r2_000460 := false

r_cntr_r2_000460 if {
	count(missing_r_cntr_r2_000460) == 0
	input.attest.rke2_images_signature_verified == true
}

default detail_r_cntr_r2_000460 := ""

detail_r_cntr_r2_000460 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000460", concat(", ", missing_r_cntr_r2_000460)]) if count(missing_r_cntr_r2_000460) > 0

detail_r_cntr_r2_000460 := "CNTR-R2-000460: not attested — input.attest.rke2_images_signature_verified must be true (every RKE2 image was obtained with Hauler and its signature verified against the RGS (Carbide) key)" if {
	count(missing_r_cntr_r2_000460) == 0
	not r_cntr_r2_000460
}

detail_r_cntr_r2_000460 := "CNTR-R2-000460: Not_a_Finding" if r_cntr_r2_000460

finding_r_cntr_r2_000460 := {
	"vuln_id": "V-268321",
	"stig_id": "CNTR-R2-000460",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 must be built from verified packages.",
	"check_type": "attestation",
	"status": status_r_cntr_r2_000460,
	"detail": detail_r_cntr_r2_000460,
}

status_r_cntr_r2_000460 := "Not_a_Finding" if r_cntr_r2_000460

status_r_cntr_r2_000460 := "Open" if not r_cntr_r2_000460

# CNTR-R2-000520 | V-254564 | CAT II | machine
missing_r_cntr_r2_000520 := [concat(".", p) | some p in [["rke2", "files"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000520 := false

r_cntr_r2_000520 if {
	count(missing_r_cntr_r2_000520) == 0
	_files_owned(input.rke2.files.etc, "root", "root")
	_files_mode_le(input.rke2.files.etc, "600")
	_files_owned(input.rke2.files.root, "root", "root")
	_named_mode_le(input.rke2.files.root, {"data"}, "750")
	_files_owned(input.rke2.files.agent, "root", "root")
	_named_mode_le(input.rke2.files.agent, {"rke2controller.kubeconfig", "kubelet.kubeconfig", "kubeproxy.kubeconfig"}, "640")
	_named_mode_le(input.rke2.files.agent, {"client-ca.crt", "client-kubelet.crt", "client-kube-proxy.crt", "client-rke2-controller.crt", "server-ca.crt", "serving-kubelet.crt"}, "600")
	_named_mode_le(input.rke2.files.agent, {"client-kubelet.key", "serving-kubelet.key", "client-rke2-controller.key", "client-kube-proxy.key"}, "600")
	_named_mode_le(input.rke2.files.agent, {"pod-manifests", "etc"}, "700")
	_files_owned(input.rke2.files.bin, "root", "root")
	_files_mode_le(input.rke2.files.bin, "750")
	_files_owned(input.rke2.files.data, "root", "root")
	_files_mode_le(input.rke2.files.data, "750")
	_files_owned(input.rke2.files.server, "root", "root")
	_named_mode_le(input.rke2.files.server, {"cred", "db", "tls"}, "700")
	_named_mode_le(input.rke2.files.server, {"manifests", "logs"}, "750")
	_named_mode_le(input.rke2.files.server, {"token"}, "600")
	_flag(input.rke2.config, "write-kubeconfig-mode") in {"0600", "600"}
	_has_names(input.rke2.files.etc, ["config.yaml"])
	_has_names(input.rke2.files.root, ["agent", "bin", "data", "server"])
	_has_names(input.rke2.files.agent, ["kubelet.kubeconfig", "client-ca.crt", "client-kubelet.key", "pod-manifests", "etc"])
	_has_names(input.rke2.files.server, ["cred", "db", "tls", "manifests", "logs", "token"])
}

default detail_r_cntr_r2_000520 := ""

detail_r_cntr_r2_000520 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000520", concat(", ", missing_r_cntr_r2_000520)]) if count(missing_r_cntr_r2_000520) > 0

detail_r_cntr_r2_000520 := "CNTR-R2-000520: check failed — RKE2 file ownership root:root and the modes DISA lists for /etc/rancher/rke2 and /var/lib/rancher/rke2; write-kubeconfig-mode 0600" if {
	count(missing_r_cntr_r2_000520) == 0
	not r_cntr_r2_000520
}

detail_r_cntr_r2_000520 := "CNTR-R2-000520: Not_a_Finding" if r_cntr_r2_000520

finding_r_cntr_r2_000520 := {
	"vuln_id": "V-254564",
	"stig_id": "CNTR-R2-000520",
	"severity": "CAT II",
	"rule_title": "Configuration and authentication files for Rancher RKE2 must be protected.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000520,
	"detail": detail_r_cntr_r2_000520,
}

status_r_cntr_r2_000520 := "Not_a_Finding" if r_cntr_r2_000520

status_r_cntr_r2_000520 := "Open" if not r_cntr_r2_000520

# CNTR-R2-000550 | V-254565 | CAT II | attestation
missing_r_cntr_r2_000550 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_r2_000550 := false

r_cntr_r2_000550 if {
	count(missing_r_cntr_r2_000550) == 0
	input.attest.rke2_only_essential_components_enabled == true
}

default detail_r_cntr_r2_000550 := ""

detail_r_cntr_r2_000550 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000550", concat(", ", missing_r_cntr_r2_000550)]) if count(missing_r_cntr_r2_000550) > 0

detail_r_cntr_r2_000550 := "CNTR-R2-000550: not attested — input.attest.rke2_only_essential_components_enabled must be true (every default RKE2 component not required (canal, coredns, ingress-nginx, kube-proxy, metrics-server) is disabled)" if {
	count(missing_r_cntr_r2_000550) == 0
	not r_cntr_r2_000550
}

detail_r_cntr_r2_000550 := "CNTR-R2-000550: Not_a_Finding" if r_cntr_r2_000550

finding_r_cntr_r2_000550 := {
	"vuln_id": "V-254565",
	"stig_id": "CNTR-R2-000550",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 must be configured with only essential configurations.",
	"check_type": "attestation",
	"status": status_r_cntr_r2_000550,
	"detail": detail_r_cntr_r2_000550,
}

status_r_cntr_r2_000550 := "Not_a_Finding" if r_cntr_r2_000550

status_r_cntr_r2_000550 := "Open" if not r_cntr_r2_000550

# CNTR-R2-000580 | V-254566 | CAT II | attestation
missing_r_cntr_r2_000580 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_r2_000580 := false

r_cntr_r2_000580 if {
	count(missing_r_cntr_r2_000580) == 0
	input.attest.rke2_pps_ppsm_cal_compliant == true
}

default detail_r_cntr_r2_000580 := ""

detail_r_cntr_r2_000580 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000580", concat(", ", missing_r_cntr_r2_000580)]) if count(missing_r_cntr_r2_000580) > 0

detail_r_cntr_r2_000580 := "CNTR-R2-000580: not attested — input.attest.rke2_pps_ppsm_cal_compliant must be true (RKE2 ports, protocols and services reviewed against the PPSM CAL or approved by the ISSO)" if {
	count(missing_r_cntr_r2_000580) == 0
	not r_cntr_r2_000580
}

detail_r_cntr_r2_000580 := "CNTR-R2-000580: Not_a_Finding" if r_cntr_r2_000580

finding_r_cntr_r2_000580 := {
	"vuln_id": "V-254566",
	"stig_id": "CNTR-R2-000580",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 runtime must enforce ports, protocols, and services that adhere to the PPSM CAL.",
	"check_type": "attestation",
	"status": status_r_cntr_r2_000580,
	"detail": detail_r_cntr_r2_000580,
}

status_r_cntr_r2_000580 := "Not_a_Finding" if r_cntr_r2_000580

status_r_cntr_r2_000580 := "Open" if not r_cntr_r2_000580

# CNTR-R2-000800 | V-254567 | CAT II | attestation
missing_r_cntr_r2_000800 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_r2_000800 := false

r_cntr_r2_000800 if {
	count(missing_r_cntr_r2_000800) == 0
	input.attest.no_sensitive_values_in_workload_env == true
}

default detail_r_cntr_r2_000800 := ""

detail_r_cntr_r2_000800 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000800", concat(", ", missing_r_cntr_r2_000800)]) if count(missing_r_cntr_r2_000800) > 0

detail_r_cntr_r2_000800 := "CNTR-R2-000800: not attested — input.attest.no_sensitive_values_in_workload_env must be true (review of pods, jobs and cronjobs found no sensitive values in environment variables)" if {
	count(missing_r_cntr_r2_000800) == 0
	not r_cntr_r2_000800
}

detail_r_cntr_r2_000800 := "CNTR-R2-000800: Not_a_Finding" if r_cntr_r2_000800

finding_r_cntr_r2_000800 := {
	"vuln_id": "V-254567",
	"stig_id": "CNTR-R2-000800",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 must store only cryptographic representations of passwords.",
	"check_type": "attestation",
	"status": status_r_cntr_r2_000800,
	"detail": detail_r_cntr_r2_000800,
}

status_r_cntr_r2_000800 := "Not_a_Finding" if r_cntr_r2_000800

status_r_cntr_r2_000800 := "Open" if not r_cntr_r2_000800

# CNTR-R2-000890 | V-254568 | CAT II | machine
missing_r_cntr_r2_000890 := [concat(".", p) | some p in [["rke2", "args", "kubelet"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000890 := false

r_cntr_r2_000890 if {
	count(missing_r_cntr_r2_000890) == 0
	_nonempty(_flag(input.rke2.args.kubelet, "streaming-connection-idle-timeout"))
	_duration_ge(_flag(input.rke2.args.kubelet, "streaming-connection-idle-timeout"), "5m")
	_rke2_arg_agrees(input.rke2.args.kubelet, "kubelet-arg", "streaming-connection-idle-timeout")
}

default detail_r_cntr_r2_000890 := ""

detail_r_cntr_r2_000890 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000890", concat(", ", missing_r_cntr_r2_000890)]) if count(missing_r_cntr_r2_000890) > 0

detail_r_cntr_r2_000890 := "CNTR-R2-000890: check failed — rke2.args.kubelet --streaming-connection-idle-timeout must be set to at least 5m; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000890) == 0
	not r_cntr_r2_000890
}

detail_r_cntr_r2_000890 := "CNTR-R2-000890: Not_a_Finding" if r_cntr_r2_000890

finding_r_cntr_r2_000890 := {
	"vuln_id": "V-254568",
	"stig_id": "CNTR-R2-000890",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated",
	"check_type": "machine",
	"status": status_r_cntr_r2_000890,
	"detail": detail_r_cntr_r2_000890,
}

status_r_cntr_r2_000890 := "Not_a_Finding" if r_cntr_r2_000890

status_r_cntr_r2_000890 := "Open" if not r_cntr_r2_000890

# CNTR-R2-000940 | V-254569 | CAT II | machine
missing_r_cntr_r2_000940 := [concat(".", p) | some p in [["rke2", "args", "kubelet"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_000940 := false

r_cntr_r2_000940 if {
	count(missing_r_cntr_r2_000940) == 0
	_flag(input.rke2.args.kubelet, "protect-kernel-defaults") == "true"
	_rke2_arg_agrees(input.rke2.args.kubelet, "kubelet-arg", "protect-kernel-defaults")
}

default detail_r_cntr_r2_000940 := ""

detail_r_cntr_r2_000940 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000940", concat(", ", missing_r_cntr_r2_000940)]) if count(missing_r_cntr_r2_000940) > 0

detail_r_cntr_r2_000940 := "CNTR-R2-000940: check failed — rke2.args.kubelet --protect-kernel-defaults must be \"true\"; config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_000940) == 0
	not r_cntr_r2_000940
}

detail_r_cntr_r2_000940 := "CNTR-R2-000940: Not_a_Finding" if r_cntr_r2_000940

finding_r_cntr_r2_000940 := {
	"vuln_id": "V-254569",
	"stig_id": "CNTR-R2-000940",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 runtime must isolate security functions from nonsecurity functions.",
	"check_type": "machine",
	"status": status_r_cntr_r2_000940,
	"detail": detail_r_cntr_r2_000940,
}

status_r_cntr_r2_000940 := "Not_a_Finding" if r_cntr_r2_000940

status_r_cntr_r2_000940 := "Open" if not r_cntr_r2_000940

# CNTR-R2-000970 | V-254570 | CAT II | machine+attestation
missing_r_cntr_r2_000970 := [concat(".", p) | some p in [["cluster", "namespace_resources"], ["collection_status", "namespace_resources"]]; not _collected(p)]

default r_cntr_r2_000970 := false

r_cntr_r2_000970 if {
	count(missing_r_cntr_r2_000970) == 0
	_only_kubernetes_service(input.cluster.namespace_resources)
	input.collection_status["namespace_resources"] == "ok"
	input.attest.kube_system_resources_approved == true
}

default detail_r_cntr_r2_000970 := ""

detail_r_cntr_r2_000970 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-000970", concat(", ", missing_r_cntr_r2_000970)]) if count(missing_r_cntr_r2_000970) > 0

detail_r_cntr_r2_000970 := "CNTR-R2-000970: check failed — default, kube-public and kube-node-lease hold nothing but service/kubernetes; input.attest.kube_system_resources_approved must be true (kube-system holds only the RKE2 system components DISA lists or ISSO-approved services)" if {
	count(missing_r_cntr_r2_000970) == 0
	not r_cntr_r2_000970
}

detail_r_cntr_r2_000970 := "CNTR-R2-000970: Not_a_Finding" if r_cntr_r2_000970

finding_r_cntr_r2_000970 := {
	"vuln_id": "V-254570",
	"stig_id": "CNTR-R2-000970",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 runtime must maintain separate execution domains for each container by assigning each container a separate address space to prevent unauthorized and unintended information transfer via shared system resource",
	"check_type": "machine+attestation",
	"status": status_r_cntr_r2_000970,
	"detail": detail_r_cntr_r2_000970,
}

status_r_cntr_r2_000970 := "Not_a_Finding" if r_cntr_r2_000970

status_r_cntr_r2_000970 := "Open" if not r_cntr_r2_000970

# CNTR-R2-001130 | V-254571 | CAT II | machine
missing_r_cntr_r2_001130 := [concat(".", p) | some p in [["rke2", "config"], ["rke2", "pss_defaults"]]; not _collected(p)]

default r_cntr_r2_001130 := false

r_cntr_r2_001130 if {
	count(missing_r_cntr_r2_001130) == 0
	_nonempty(_flag(input.rke2.config, "pod-security-admission-config-file"))
	is_object(input.rke2.pss_defaults)
	every k, v in {"audit": "restricted", "audit-version": "latest", "enforce": "restricted", "enforce-version": "latest", "warn": "restricted", "warn-version": "latest"} {
		input.rke2.pss_defaults[k] == v
	}
}

default detail_r_cntr_r2_001130 := ""

detail_r_cntr_r2_001130 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-001130", concat(", ", missing_r_cntr_r2_001130)]) if count(missing_r_cntr_r2_001130) > 0

detail_r_cntr_r2_001130 := "CNTR-R2-001130: check failed — pod-security-admission-config-file set; defaults audit/enforce/warn = restricted, versions = latest" if {
	count(missing_r_cntr_r2_001130) == 0
	not r_cntr_r2_001130
}

detail_r_cntr_r2_001130 := "CNTR-R2-001130: Not_a_Finding" if r_cntr_r2_001130

finding_r_cntr_r2_001130 := {
	"vuln_id": "V-254571",
	"stig_id": "CNTR-R2-001130",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.",
	"check_type": "machine",
	"status": status_r_cntr_r2_001130,
	"detail": detail_r_cntr_r2_001130,
}

status_r_cntr_r2_001130 := "Not_a_Finding" if r_cntr_r2_001130

status_r_cntr_r2_001130 := "Open" if not r_cntr_r2_001130

# CNTR-R2-001270 | V-254572 | CAT II | machine
missing_r_cntr_r2_001270 := [concat(".", p) | some p in [["rke2", "args", "kube_apiserver"], ["rke2", "config"]]; not _collected(p)]

default r_cntr_r2_001270 := false

r_cntr_r2_001270 if {
	count(missing_r_cntr_r2_001270) == 0
	_nonempty(_flag(input.rke2.args.kube_apiserver, "authorization-mode"))
	{trim_space(m) | some m in split(_flag(input.rke2.args.kube_apiserver, "authorization-mode"), ",")} == {"Node", "RBAC"}
	_rke2_arg_agrees(input.rke2.args.kube_apiserver, "kube-apiserver-arg", "authorization-mode")
}

default detail_r_cntr_r2_001270 := ""

detail_r_cntr_r2_001270 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-001270", concat(", ", missing_r_cntr_r2_001270)]) if count(missing_r_cntr_r2_001270) > 0

detail_r_cntr_r2_001270 := "CNTR-R2-001270: check failed — kube-apiserver --authorization-mode must be RBAC,Node (either order); config.yaml *-arg entries must match the running value" if {
	count(missing_r_cntr_r2_001270) == 0
	not r_cntr_r2_001270
}

detail_r_cntr_r2_001270 := "CNTR-R2-001270: Not_a_Finding" if r_cntr_r2_001270

finding_r_cntr_r2_001270 := {
	"vuln_id": "V-254572",
	"stig_id": "CNTR-R2-001270",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 must prohibit the installation of patches, updates, and instantiation of container images without explicit privileged status.",
	"check_type": "machine",
	"status": status_r_cntr_r2_001270,
	"detail": detail_r_cntr_r2_001270,
}

status_r_cntr_r2_001270 := "Not_a_Finding" if r_cntr_r2_001270

status_r_cntr_r2_001270 := "Open" if not r_cntr_r2_001270

# CNTR-R2-001580 | V-254574 | CAT II | machine
missing_r_cntr_r2_001580 := [concat(".", p) | some p in [["cluster", "images"], ["collection_status", "images"]]; not _collected(p)]

default r_cntr_r2_001580 := false

r_cntr_r2_001580 if {
	count(missing_r_cntr_r2_001580) == 0
	_single_version_per_image(input.cluster.images)
	input.collection_status["images"] == "ok"
}

default detail_r_cntr_r2_001580 := ""

detail_r_cntr_r2_001580 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-001580", concat(", ", missing_r_cntr_r2_001580)]) if count(missing_r_cntr_r2_001580) > 0

detail_r_cntr_r2_001580 := "CNTR-R2-001580: check failed — only one version of each image may run" if {
	count(missing_r_cntr_r2_001580) == 0
	not r_cntr_r2_001580
}

detail_r_cntr_r2_001580 := "CNTR-R2-001580: Not_a_Finding" if r_cntr_r2_001580

finding_r_cntr_r2_001580 := {
	"vuln_id": "V-254574",
	"stig_id": "CNTR-R2-001580",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 must remove old components after updated versions have been installed.",
	"check_type": "machine",
	"status": status_r_cntr_r2_001580,
	"detail": detail_r_cntr_r2_001580,
}

status_r_cntr_r2_001580 := "Not_a_Finding" if r_cntr_r2_001580

status_r_cntr_r2_001580 := "Open" if not r_cntr_r2_001580

# CNTR-R2-001620 | V-254575 | CAT II | attestation
missing_r_cntr_r2_001620 := [concat(".", p) | some p in []; not _collected(p)]

default r_cntr_r2_001620 := false

r_cntr_r2_001620 if {
	count(missing_r_cntr_r2_001620) == 0
	input.attest.rke2_supported_version_and_current_images == true
}

default detail_r_cntr_r2_001620 := ""

detail_r_cntr_r2_001620 := sprintf("%s: evidence missing — %s not collected", ["CNTR-R2-001620", concat(", ", missing_r_cntr_r2_001620)]) if count(missing_r_cntr_r2_001620) > 0

detail_r_cntr_r2_001620 := "CNTR-R2-001620: not attested — input.attest.rke2_supported_version_and_current_images must be true (every node runs a supported RKE2 release and every running image is the latest patched version)" if {
	count(missing_r_cntr_r2_001620) == 0
	not r_cntr_r2_001620
}

detail_r_cntr_r2_001620 := "CNTR-R2-001620: Not_a_Finding" if r_cntr_r2_001620

finding_r_cntr_r2_001620 := {
	"vuln_id": "V-254575",
	"stig_id": "CNTR-R2-001620",
	"severity": "CAT II",
	"rule_title": "Rancher RKE2 registry must contain the latest images with most recent updates and execute within Rancher RKE2 runtime as authorized by IAVM, CTOs, DTMs, and STIGs.",
	"check_type": "attestation",
	"status": status_r_cntr_r2_001620,
	"detail": detail_r_cntr_r2_001620,
}

status_r_cntr_r2_001620 := "Not_a_Finding" if r_cntr_r2_001620

status_r_cntr_r2_001620 := "Open" if not r_cntr_r2_001620

findings := [
	finding_r_cntr_r2_000010,
	finding_r_cntr_r2_000030,
	finding_r_cntr_r2_000060,
	finding_r_cntr_r2_000100,
	finding_r_cntr_r2_000110,
	finding_r_cntr_r2_000130,
	finding_r_cntr_r2_000150,
	finding_r_cntr_r2_000160,
	finding_r_cntr_r2_000320,
	finding_r_cntr_r2_000460,
	finding_r_cntr_r2_000520,
	finding_r_cntr_r2_000550,
	finding_r_cntr_r2_000580,
	finding_r_cntr_r2_000800,
	finding_r_cntr_r2_000890,
	finding_r_cntr_r2_000940,
	finding_r_cntr_r2_000970,
	finding_r_cntr_r2_001130,
	finding_r_cntr_r2_001270,
	finding_r_cntr_r2_001580,
	finding_r_cntr_r2_001620,
]

default compliant := false

compliant if count([f | some f in findings; f.status == "Open"]) == 0
