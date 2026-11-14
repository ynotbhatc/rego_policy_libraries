"""CIS Kubernetes Benchmark v2.1.0 -> benchmarks/cis/kubernetes/ (module, bridge, tests).

    python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> k8s.json
    python3 tools/cis_generators/gen_kubernetes.py k8s.json benchmarks/cis/kubernetes
    opa fmt -w benchmarks/cis/kubernetes

Same pattern as gen_apache.py (cis_genlib.py emitter): ids, Automated/Manual status and the profile of every
recommendation come from the workbook; the logic table below is hand-authored from each audit procedure. Aborts
when the workbook does not hold exactly the ids the table covers, when a status or profile count differs, or when
an entry's keyword is not in the workbook title of its id (logic cannot attach to a renumbered id). Titles are
written here in our own words; the workbook title is only used for that keyword check.

The input contract is the DISA Kubernetes STIG module's (benchmarks/stig/kubernetes/core.rego), so one collector
feeds both; the paths this module adds are listed in the module header.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import emit_control, emit_tests, norm_title, table  # noqa: E402
from neutralize import neutralize_title  # noqa: E402

SRC, OUT = sys.argv[1], sys.argv[2]
BENCH = "CIS Kubernetes Benchmark v2.1.0"
VERSION = "v2.1.0"
PROFILES = ["Level 1 - Master Node", "Level 2 - Master Node", "Level 1 - Worker Node", "Level 2 - Worker Node"]
EXPECT = {"total": 134, "Automated": 65, "Manual": 69,
          "profiles": {"Level 1 - Master Node": 93, "Level 2 - Master Node": 15,
                       "Level 1 - Worker Node": 25, "Level 2 - Worker Node": 1}}


def idkey(i):
    return [int(p) for p in i.split(".")]


def load(path):
    """dump_workbook.py output; this workbook lists each recommendation on exactly one profile sheet."""
    out = {}
    for e in json.load(open(path)):
        sheets = [s for s in e["sheets"] if s in PROFILES]
        if len(sheets) != 1 or len(sheets) != len(e["sheets"]):
            sys.exit(f"ABORT: {e['id']} is on sheets {e['sheets']}, expected exactly one profile sheet")
        if e["status"] not in ("Automated", "Manual"):
            sys.exit(f"ABORT: {e['id']} has status {e['status']!r}")
        out[e["id"]] = {"wb_title": norm_title(e["title"]), "assessment": e["status"],
                        "level": int(sheets[0][6]), "profiles": sheets}
    return out


WB = load(SRC)

API, CM, SCHED, ETCD, KUBELET = "api_server", "controller_manager", "scheduler", "etcd", "kubelet"
LABEL = {c: f"{c}.flags" for c in (API, CM, SCHED, ETCD)}


def add(path, value):
    return [{"op": "add", "path": path, "value": value}]


def rm(path):
    return [{"op": "remove", "path": path}]


def fact(cid, kw, title, ev, label, oks, fail, miss):
    return {"id": cid, "kw": kw, "title": title, "kind": "fact", "ev": ev, "label": label, "ok": oks,
            "fail": fail, "miss": miss}


def att(cid, kw, title, key):
    return {"id": cid, "kw": kw, "title": title, "kind": "attest", "attest": key, "attest_root": "input"}


def flag(cid, kw, title, comp, oks, fail):
    """A check on one control-plane component's flag map; fail is (flag, value) or (flag, None) to remove."""
    name, value = fail
    patch = rm(f"/{comp}/flags/{name}") if value is None else add(f"/{comp}/flags/{name}", value)
    return fact(cid, kw, title, [f'_component("{comp}")'], LABEL[comp], oks, patch, rm(f"/{comp}/flags"))


def nonempty(cid, kw, title, comp, names):
    return flag(cid, kw, title, comp, [[f'_nonempty_flag("{comp}", "{n}")' for n in names]], (names[0], None))


def fmode(cid, kw, title, group, stem, mx, idx=0):
    """Named file in a files.<group> list: mode within mx (octal bit mask)."""
    return fact(cid, kw, title, [f'_has_named("{group}", "{stem}")'], f"files.{group} entry for {stem}",
                [[f'every f in _named("{group}", "{stem}") {{ mode_within(f.mode, "{mx}") }}']],
                add(f"/files/{group}/{idx}/mode", "0644" if mx == "600" else "0777"), rm(f"/files/{group}"))


def fown(cid, kw, title, group, stem, owner="root", idx=0):
    return fact(cid, kw, title, [f'_has_named("{group}", "{stem}")'], f"files.{group} entry for {stem}",
                [[f'every f in _named("{group}", "{stem}") {{ _owned(f, "{owner}", "{owner}") }}']],
                add(f"/files/{group}/{idx}/owner", "kube"), rm(f"/files/{group}"))


def gmode(cid, kw, title, group, mx, sel="_files", label=None):
    """Every entry of a files.<group> list: mode within mx."""
    return fact(cid, kw, title, [f'count({sel}("{group}")) > 0'], label or f"files.{group}",
                [[f'every f in {sel}("{group}") {{ mode_within(f.mode, "{mx}") }}']],
                add(f"/files/{group}/0/mode", "0666"), rm(f"/files/{group}"))


def gown(cid, kw, title, group, owner="root", sel="_files", label=None):
    return fact(cid, kw, title, [f'count({sel}("{group}")) > 0'], label or f"files.{group}",
                [[f'every f in {sel}("{group}") {{ _owned(f, "{owner}", "{owner}") }}']],
                add(f"/files/{group}/0/group", "wheel"), rm(f"/files/{group}"))


M = "manifests"
CONFS = "control_plane_confs"
KL = ["_kubelet_collected"]
KL_LABEL = "kubelet.flags (and kubelet.config when --config is set)"
KL_MISS = rm("/kubelet/flags")


def kubelet(cid, kw, title, oks, fail):
    return fact(cid, kw, title, KL, KL_LABEL, oks, fail, KL_MISS)


def kflag(name, value):
    return add(f"/kubelet/flags/{name}", value)


def kcfg(path, value):
    return add(f"/kubelet/config/{path}", value)


STRONG_API = ("TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256,"
              "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
              "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,"
              "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
              "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256").split(",")
STRONG_KUBELET = ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,"
                  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
                  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384").split(",")

C = [
    # ── 1.1 control plane node configuration files ──────────────────────────────────────────────
    fmode("1.1.1", "api server", "kube-apiserver static pod manifest mode must be 600 or stricter", M, "kube-apiserver", "600", 0),
    fown("1.1.2", "api server", "kube-apiserver static pod manifest must be owned by root:root", M, "kube-apiserver", idx=0),
    fmode("1.1.3", "controller manager", "kube-controller-manager static pod manifest mode must be 600 or stricter", M, "kube-controller-manager", "600", 1),
    fown("1.1.4", "controller manager", "kube-controller-manager static pod manifest must be owned by root:root", M, "kube-controller-manager", idx=1),
    fmode("1.1.5", "scheduler", "kube-scheduler static pod manifest mode must be 600 or stricter", M, "kube-scheduler", "600", 2),
    fown("1.1.6", "scheduler", "kube-scheduler static pod manifest must be owned by root:root", M, "kube-scheduler", idx=2),
    fmode("1.1.7", "etcd", "etcd static pod manifest mode must be 600 or stricter", M, "etcd", "600", 3),
    fown("1.1.8", "etcd", "etcd static pod manifest must be owned by root:root", M, "etcd", idx=3),
    gmode("1.1.9", "container network interface", "every CNI configuration file mode must be 600 or stricter", "cni", "600"),
    gown("1.1.10", "container network interface", "every CNI configuration file must be owned by root:root", "cni"),
    fact("1.1.11", "etcd data directory", "etcd data directory mode must be 700 or stricter",
         ["count(_etcd_dir_entries) > 0"], "files.etcd_data entry for the etcd --data-dir directory",
         [['every f in _etcd_dir_entries { mode_within(f.mode, "700") }']],
         add("/files/etcd_data/0/mode", "0755"), rm("/files/etcd_data")),
    fact("1.1.12", "etcd data directory", "etcd data directory must be owned by etcd:etcd",
         ["count(_etcd_dir_entries) > 0"], "files.etcd_data entry for the etcd --data-dir directory",
         [['every f in _etcd_dir_entries { _owned(f, "etcd", "etcd") }']],
         add("/files/etcd_data/0/owner", "root"), rm("/files/etcd_data")),
    fact("1.1.13", "administrative credential", "admin.conf (and super-admin.conf when present) mode must be 600 or stricter",
         [f'_has_named("{CONFS}", "admin.conf")'], f"files.{CONFS} entry for admin.conf",
         [['every f in _admin_confs { mode_within(f.mode, "600") }']],
         add(f"/files/{CONFS}/3/mode", "0640"), rm(f"/files/{CONFS}")),
    fact("1.1.14", "administrative credential", "admin.conf (and super-admin.conf when present) must be owned by root:root",
         [f'_has_named("{CONFS}", "admin.conf")'], f"files.{CONFS} entry for admin.conf",
         [['every f in _admin_confs { _owned(f, "root", "root") }']],
         add(f"/files/{CONFS}/0/owner", "admin"), rm(f"/files/{CONFS}")),
    fmode("1.1.15", "scheduler.conf", "scheduler.conf mode must be 600 or stricter", CONFS, "scheduler.conf", "600", 1),
    fown("1.1.16", "scheduler.conf", "scheduler.conf must be owned by root:root", CONFS, "scheduler.conf", idx=1),
    fmode("1.1.17", "controller-manager.conf", "controller-manager.conf mode must be 600 or stricter", CONFS, "controller-manager.conf", "600", 2),
    fown("1.1.18", "controller-manager.conf", "controller-manager.conf must be owned by root:root", CONFS, "controller-manager.conf", idx=2),
    gown("1.1.19", "pki directory", "every file and directory under the Kubernetes PKI directory must be owned by root:root", "pki"),
    gmode("1.1.20", "pki certificate", "every Kubernetes PKI .crt file mode must be 644 or stricter", "pki", "644",
          sel="_pki_certs", label="files.pki entries ending in .crt"),
    fact("1.1.21", "pki key", "every Kubernetes PKI .key file mode must be 600 or stricter",
         ['count(_pki_keys("pki")) > 0'], "files.pki entries ending in .key",
         [['every f in _pki_keys("pki") { mode_within(f.mode, "600") }']],
         add("/files/pki/1/mode", "0640"), rm("/files/pki")),
    # ── 1.2 API server ──────────────────────────────────────────────────────────────────────────
    fact("1.2.1", "anonymous", "anonymous requests to kube-apiserver must be disabled or limited to health endpoints",
         ["_api_anonymous_collected"], "api_server.flags (and api_server.authentication_config when --authentication-config is set)",
         [[f'_flag_false("{API}", "anonymous-auth")'],
          ["_authn_anonymous.enabled == false"],
          ["_authn_anonymous.enabled == true", "count(_authn_anonymous.conditions) > 0",
           'every c in _authn_anonymous.conditions { c.path in {"/healthz", "/livez", "/readyz"} }'],
          ["_authn_anonymous.enabled == true", "count(_authn_anonymous.conditions) > 0",
           "input.attest.api_anonymous_paths_required == true"]],
         add(f"/{API}/flags/anonymous-auth", "true"), rm(f"/{API}/flags")),
    flag("1.2.2", "token-auth-file", "kube-apiserver --token-auth-file must be absent", API,
         [[f'_unset("{API}", "token-auth-file")']], ("token-auth-file", "/etc/kubernetes/tokens.csv")),
    flag("1.2.3", "denyserviceexternalips", "kube-apiserver --enable-admission-plugins must list DenyServiceExternalIPs", API,
         [[f'"DenyServiceExternalIPs" in _csv("{API}", "enable-admission-plugins")']], ("enable-admission-plugins", "NodeRestriction")),
    nonempty("1.2.4", "kubelet-client-certificate", "kube-apiserver --kubelet-client-certificate and --kubelet-client-key must both be given", API,
             ["kubelet-client-certificate", "kubelet-client-key"]),
    nonempty("1.2.5", "kubelet-certificate-authority", "kube-apiserver --kubelet-certificate-authority must be given", API,
             ["kubelet-certificate-authority"]),
    flag("1.2.6", "alwaysallow", "kube-apiserver --authorization-mode must be given and must exclude AlwaysAllow", API,
         [[f'count(_csv("{API}", "authorization-mode")) > 0', f'_csv_lacks("{API}", "authorization-mode", "AlwaysAllow")']],
         ("authorization-mode", "Node,RBAC,AlwaysAllow")),
    flag("1.2.7", "includes node", "kube-apiserver --authorization-mode must list Node", API,
         [[f'"Node" in _csv("{API}", "authorization-mode")']], ("authorization-mode", "RBAC")),
    flag("1.2.8", "includes rbac", "kube-apiserver --authorization-mode must list RBAC", API,
         [[f'"RBAC" in _csv("{API}", "authorization-mode")']], ("authorization-mode", "Node,Webhook")),
    flag("1.2.9", "eventratelimit", "kube-apiserver --enable-admission-plugins must list EventRateLimit", API,
         [[f'"EventRateLimit" in _csv("{API}", "enable-admission-plugins")']], ("enable-admission-plugins", "NodeRestriction")),
    flag("1.2.10", "alwaysadmit", "kube-apiserver --enable-admission-plugins must exclude AlwaysAdmit", API,
         [[f'_csv_lacks("{API}", "enable-admission-plugins", "AlwaysAdmit")']],
         ("enable-admission-plugins", "NodeRestriction,AlwaysAdmit")),
    flag("1.2.11", "alwayspullimages", "kube-apiserver --enable-admission-plugins must list AlwaysPullImages", API,
         [[f'"AlwaysPullImages" in _csv("{API}", "enable-admission-plugins")']], ("enable-admission-plugins", "NodeRestriction")),
    flag("1.2.12", "plugin serviceaccount", "kube-apiserver --disable-admission-plugins must exclude ServiceAccount", API,
         [[f'_csv_lacks("{API}", "disable-admission-plugins", "ServiceAccount")']], ("disable-admission-plugins", "ServiceAccount")),
    flag("1.2.13", "namespacelifecycle", "kube-apiserver --disable-admission-plugins must exclude NamespaceLifecycle", API,
         [[f'_csv_lacks("{API}", "disable-admission-plugins", "NamespaceLifecycle")']],
         ("disable-admission-plugins", "PodSecurity,NamespaceLifecycle")),
    flag("1.2.14", "noderestriction", "kube-apiserver --enable-admission-plugins must list NodeRestriction", API,
         [[f'"NodeRestriction" in _csv("{API}", "enable-admission-plugins")']], ("enable-admission-plugins", "EventRateLimit")),
    flag("1.2.15", "profiling", "kube-apiserver --profiling must be false", API,
         [[f'_flag_false("{API}", "profiling")']], ("profiling", None)),
    nonempty("1.2.16", "audit-log-path", "kube-apiserver --audit-log-path must be given", API, ["audit-log-path"]),
    flag("1.2.17", "audit-log-maxage", "kube-apiserver --audit-log-maxage must be 30 or more", API,
         [[f'_num_flag("{API}", "audit-log-maxage") >= 30']], ("audit-log-maxage", "7")),
    flag("1.2.18", "audit-log-maxbackup", "kube-apiserver --audit-log-maxbackup must be 10 or more", API,
         [[f'_num_flag("{API}", "audit-log-maxbackup") >= 10']], ("audit-log-maxbackup", "0")),
    flag("1.2.19", "audit-log-maxsize", "kube-apiserver --audit-log-maxsize must be 100 or more", API,
         [[f'_num_flag("{API}", "audit-log-maxsize") >= 100']], ("audit-log-maxsize", "10")),
    flag("1.2.20", "request-timeout", "kube-apiserver --request-timeout must be absent, or a positive duration attested as suitable (attest.api_request_timeout_appropriate)", API,
         [[f'_unset("{API}", "request-timeout")'],
          [f'time.parse_duration_ns(_fl("{API}", "request-timeout")) > 0', "input.attest.api_request_timeout_appropriate == true"]],
         ("request-timeout", "0s")),
    flag("1.2.21", "service-account-lookup", "kube-apiserver --service-account-lookup must be true when given", API,
         [[f'_flag_not_false("{API}", "service-account-lookup")']], ("service-account-lookup", "false")),
    nonempty("1.2.22", "service-account-key-file", "kube-apiserver --service-account-key-file must be given", API, ["service-account-key-file"]),
    nonempty("1.2.23", "etcd-certfile", "kube-apiserver --etcd-certfile and --etcd-keyfile must both be given", API, ["etcd-certfile", "etcd-keyfile"]),
    nonempty("1.2.24", "tls-cert-file", "kube-apiserver --tls-cert-file and --tls-private-key-file must both be given", API,
             ["tls-cert-file", "tls-private-key-file"]),
    nonempty("1.2.25", "client-ca-file", "kube-apiserver --client-ca-file must be given", API, ["client-ca-file"]),
    nonempty("1.2.26", "etcd-cafile", "kube-apiserver --etcd-cafile must be given", API, ["etcd-cafile"]),
    fact("1.2.27", "encryption-provider-config", "kube-apiserver --encryption-provider-config must be given and the file must cover secrets",
         ["_encryption_collected"], "api_server.flags (and api_server.encryption_config when --encryption-provider-config is set)",
         [[f'_nonempty_flag("{API}", "encryption-provider-config")', "count(_encryption_secret_entries) > 0"]],
         add(f"/{API}/encryption_config/resources/0/resources", ["configmaps"]), rm(f"/{API}/flags")),
    fact("1.2.28", "encryption providers", "every EncryptionConfiguration resource entry must write with aescbc, kms or secretbox",
         ["_encryption_collected"], "api_server.flags (and api_server.encryption_config when --encryption-provider-config is set)",
         [[f'_nonempty_flag("{API}", "encryption-provider-config")', "count(input.api_server.encryption_config.resources) > 0",
           'every r in input.api_server.encryption_config.resources { r.providers[0] in {"aescbc", "kms", "secretbox"} }']],
         add(f"/{API}/encryption_config/resources/0/providers", ["identity", "aescbc"]), rm(f"/{API}/flags")),
    flag("1.2.29", "ciphers", "kube-apiserver --tls-cipher-suites must be given and hold only the strong suites", API,
         [[f'count(_csv("{API}", "tls-cipher-suites")) > 0', f'count(_csv("{API}", "tls-cipher-suites") - _strong_api_ciphers) == 0']],
         ("tls-cipher-suites", "TLS_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA")),
    flag("1.2.30", "service-account-extend-token-expiration", "kube-apiserver --service-account-extend-token-expiration must be false", API,
         [[f'_flag_false("{API}", "service-account-extend-token-expiration")']], ("service-account-extend-token-expiration", None)),
    # ── 1.3 controller manager, 1.4 scheduler ───────────────────────────────────────────────────
    flag("1.3.1", "terminated-pod-gc-threshold", "kube-controller-manager --terminated-pod-gc-threshold must be given as a positive number", CM,
         [[f'_num_flag("{CM}", "terminated-pod-gc-threshold") > 0']], ("terminated-pod-gc-threshold", "0")),
    flag("1.3.2", "profiling", "kube-controller-manager --profiling must be false", CM,
         [[f'_flag_false("{CM}", "profiling")']], ("profiling", "true")),
    flag("1.3.3", "use-service-account-credentials", "kube-controller-manager --use-service-account-credentials must be true", CM,
         [[f'_flag_true("{CM}", "use-service-account-credentials")']], ("use-service-account-credentials", None)),
    nonempty("1.3.4", "service-account-private-key-file", "kube-controller-manager --service-account-private-key-file must be given", CM,
             ["service-account-private-key-file"]),
    nonempty("1.3.5", "root-ca-file", "kube-controller-manager --root-ca-file must be given", CM, ["root-ca-file"]),
    flag("1.3.6", "rotatekubeletservercertificate", "kube-controller-manager feature gate RotateKubeletServerCertificate must not be switched off", CM,
         [[f'_gate_never_false("{CM}", "RotateKubeletServerCertificate")']],
         ("feature-gates", "RotateKubeletServerCertificate=false")),
    flag("1.3.7", "bind-address", "kube-controller-manager --bind-address must be a loopback address", CM,
         [[f'_loopback(_fl("{CM}", "bind-address"))']], ("bind-address", "0.0.0.0")),
    flag("1.4.1", "profiling", "kube-scheduler --profiling must be false", SCHED,
         [[f'_flag_false("{SCHED}", "profiling")']], ("profiling", None)),
    flag("1.4.2", "bind-address", "kube-scheduler --bind-address must be a loopback address", SCHED,
         [[f'_loopback(_fl("{SCHED}", "bind-address"))']], ("bind-address", None)),
    # ── 2 etcd ──────────────────────────────────────────────────────────────────────────────────
    nonempty("2.1", "--cert-file", "etcd --cert-file and --key-file must both be given", ETCD, ["cert-file", "key-file"]),
    flag("2.2", "--client-cert-auth", "etcd --client-cert-auth must be true", ETCD,
         [[f'_flag_true("{ETCD}", "client-cert-auth")']], ("client-cert-auth", None)),
    flag("2.3", "--auto-tls", "etcd --auto-tls must not be true", ETCD,
         [[f'_flag_not_true("{ETCD}", "auto-tls")']], ("auto-tls", "true")),
    flag("2.4", "--peer-cert-file", "etcd --peer-cert-file and --peer-key-file must both be given (single-member etcd excepted)", ETCD,
         [[f'_nonempty_flag("{ETCD}", "peer-cert-file")', f'_nonempty_flag("{ETCD}", "peer-key-file")'],
          ["input.etcd.member_count == 1"]], ("peer-key-file", None)),
    flag("2.5", "--peer-client-cert-auth", "etcd --peer-client-cert-auth must be true (single-member etcd excepted)", ETCD,
         [[f'_flag_true("{ETCD}", "peer-client-cert-auth")'], ["input.etcd.member_count == 1"]], ("peer-client-cert-auth", "false")),
    flag("2.6", "--peer-auto-tls", "etcd --peer-auto-tls must not be true", ETCD,
         [[f'_flag_not_true("{ETCD}", "peer-auto-tls")']], ("peer-auto-tls", "true")),
    fact("2.7", "unique certificate authority", "etcd --trusted-ca-file must be given and must differ from kube-apiserver --client-ca-file",
         [f'_component("{ETCD}")', f'_component("{API}")'], "etcd.flags / api_server.flags",
         [[f'_nonempty_flag("{ETCD}", "trusted-ca-file")', f'_nonempty_flag("{API}", "client-ca-file")',
           f'trim_space(_fl("{ETCD}", "trusted-ca-file")) != trim_space(_fl("{API}", "client-ca-file"))']],
         add(f"/{ETCD}/flags/trusted-ca-file", "/etc/kubernetes/pki/ca.crt"), rm(f"/{ETCD}/flags")),
    # ── 3 control plane configuration ───────────────────────────────────────────────────────────
    att("3.1.1", "client certificate", "users must not sign in with client certificates", "users_no_client_certificate_auth"),
    att("3.1.2", "service account token", "users must not sign in with service account tokens", "users_no_service_account_token_auth"),
    att("3.1.3", "bootstrap token", "users must not sign in with bootstrap tokens", "users_no_bootstrap_token_auth"),
    fact("3.2.1", "minimal audit policy", "kube-apiserver --audit-policy-file must be given and the file must hold a Policy with rules",
         ["_audit_policy_collected"], "api_server.flags (and api_server.audit_policy when --audit-policy-file is set)",
         [[f'_nonempty_flag("{API}", "audit-policy-file")', 'input.api_server.audit_policy.kind == "Policy"',
           "is_array(input.api_server.audit_policy.rules)", "count(input.api_server.audit_policy.rules) > 0"]],
         add(f"/{API}/audit_policy/rules", []), rm(f"/{API}/flags")),
    att("3.2.2", "audit policy covers", "the audit policy must be reviewed against the security events it has to record", "audit_policy_coverage_reviewed"),
    # ── 4.1 worker node configuration files ─────────────────────────────────────────────────────
    gmode("4.1.1", "kubelet service file permissions", "every kubelet service unit and drop-in file mode must be 600 or stricter", "kubelet_service", "600"),
    gown("4.1.2", "kubelet service file ownership", "every kubelet service unit and drop-in file must be owned by root:root", "kubelet_service"),
    fact("4.1.3", "proxy kubeconfig", "kube-proxy kubeconfig mode must be 600 or stricter while kube-proxy runs",
         ["_kube_proxy_files_collected"], "kube_proxy.running (and files.kube_proxy_kubeconfig when it runs)",
         [["input.kube_proxy.running == false"],
          ["input.kube_proxy.running == true", 'every f in _files("kube_proxy_kubeconfig") { mode_within(f.mode, "600") }']],
         add("/files/kube_proxy_kubeconfig/0/mode", "0644"), rm("/kube_proxy/running")),
    fact("4.1.4", "proxy kubeconfig", "kube-proxy kubeconfig must be owned by root:root while kube-proxy runs",
         ["_kube_proxy_files_collected"], "kube_proxy.running (and files.kube_proxy_kubeconfig when it runs)",
         [["input.kube_proxy.running == false"],
          ["input.kube_proxy.running == true", 'every f in _files("kube_proxy_kubeconfig") { _owned(f, "root", "root") }']],
         add("/files/kube_proxy_kubeconfig/0/owner", "kube-proxy"), rm("/files/kube_proxy_kubeconfig")),
    gmode("4.1.5", "kubelet.conf file permissions", "kubelet kubeconfig mode must be 600 or stricter", "kubelet_kubeconfig", "600"),
    gown("4.1.6", "kubelet.conf file ownership", "kubelet kubeconfig must be owned by root:root", "kubelet_kubeconfig"),
    gmode("4.1.7", "certificate authorities file permissions", "kubelet client CA file mode must be 644 or stricter", "kubelet_client_ca", "644"),
    gown("4.1.8", "certificate authorities file ownership", "kubelet client CA file must be owned by root:root", "kubelet_client_ca"),
    fact("4.1.9", "config.yaml", "kubelet configuration file mode must be 600 or stricter when --config is used",
         ["_kubelet_yaml_collected"], "kubelet.flags (and files.kubelet_config_yaml when --config is set)",
         [[f'_unset("{KUBELET}", "config")'], ['every f in _files("kubelet_config_yaml") { mode_within(f.mode, "600") }']],
         add("/files/kubelet_config_yaml/0/mode", "0644"), rm("/files/kubelet_config_yaml")),
    fact("4.1.10", "config.yaml", "kubelet configuration file must be owned by root:root when --config is used",
         ["_kubelet_yaml_collected"], "kubelet.flags (and files.kubelet_config_yaml when --config is set)",
         [[f'_unset("{KUBELET}", "config")'], ['every f in _files("kubelet_config_yaml") { _owned(f, "root", "root") }']],
         add("/files/kubelet_config_yaml/0/owner", "kube"), rm("/files/kubelet_config_yaml")),
    fact("4.1.11", "drop-in configuration directory", "kubelet --config-dir directory must be root:root 755 or stricter and its .conf files root:root 644 or stricter",
         ["_kubelet_dropin_collected"], "kubelet.flags (and files.kubelet_config_dir with the --config-dir directory when it is set)",
         [[f'_unset("{KUBELET}", "config-dir")'],
          ["count(_dropin_dirs) > 0", 'every f in _dropin_dirs { mode_within(f.mode, "755"); _owned(f, "root", "root") }',
           'every f in _dropin_confs { mode_within(f.mode, "644"); _owned(f, "root", "root") }']],
         add("/files/kubelet_config_dir/1/mode", "0664"), rm("/files/kubelet_config_dir")),
    # ── 4.2 kubelet ─────────────────────────────────────────────────────────────────────────────
    kubelet("4.2.1", "--anonymous-auth", "kubelet anonymous authentication must be off (--anonymous-auth or authentication.anonymous.enabled)",
            [[f'_flag_false("{KUBELET}", "anonymous-auth")'],
             [f'_unset("{KUBELET}", "anonymous-auth")', '_kcv(["authentication", "anonymous", "enabled"]) == false']],
            kcfg("authentication/anonymous/enabled", True)),
    kubelet("4.2.2", "alwaysallow", "kubelet authorization mode must be given and must not be AlwaysAllow (--authorization-mode or authorization.mode)",
            [[f'_nonempty_flag("{KUBELET}", "authorization-mode")', f'_fl("{KUBELET}", "authorization-mode") != "AlwaysAllow"'],
             [f'_unset("{KUBELET}", "authorization-mode")', '_nonempty(_kcv(["authorization", "mode"]))',
              '_kcv(["authorization", "mode"]) != "AlwaysAllow"']],
            kflag("authorization-mode", "AlwaysAllow")),
    kubelet("4.2.3", "--client-ca-file", "kubelet client CA file must be given (--client-ca-file or authentication.x509.clientCAFile)",
            [[f'_nonempty_flag("{KUBELET}", "client-ca-file")'],
             [f'_unset("{KUBELET}", "client-ca-file")', '_nonempty(_kcv(["authentication", "x509", "clientCAFile"]))']],
            kcfg("authentication/x509/clientCAFile", "")),
    kubelet("4.2.4", "readonlyport", "kubelet read-only port must be 0 (--read-only-port, or readOnlyPort in the configuration file)",
            [[f'_num_flag("{KUBELET}", "read-only-port") == 0'],
             [f'_unset("{KUBELET}", "read-only-port")', "_kubelet_config_in_use", 'object.get(_kc, "readOnlyPort", 0) == 0']],
            kcfg("readOnlyPort", 10255)),
    kubelet("4.2.5", "--streaming-connection-idle-timeout", "kubelet streaming connection idle timeout must not be 0",
            [[f'time.parse_duration_ns(_fl("{KUBELET}", "streaming-connection-idle-timeout")) != 0'],
             [f'_unset("{KUBELET}", "streaming-connection-idle-timeout")', '_kcv(["streamingConnectionIdleTimeout"]) == null'],
             [f'_unset("{KUBELET}", "streaming-connection-idle-timeout")',
              'time.parse_duration_ns(_kcv(["streamingConnectionIdleTimeout"])) != 0']],
            kcfg("streamingConnectionIdleTimeout", "0s")),
    kubelet("4.2.6", "--make-iptables-util-chains", "kubelet iptables utility chains must stay on (--make-iptables-util-chains, makeIPTablesUtilChains)",
            [[f'_flag_true("{KUBELET}", "make-iptables-util-chains")'],
             [f'_unset("{KUBELET}", "make-iptables-util-chains")', '_kcv(["makeIPTablesUtilChains"]) in {null, true}']],
            kcfg("makeIPTablesUtilChains", False)),
    kubelet("4.2.7", "--hostname-override", "kubelet --hostname-override must be absent",
            [[f'_unset("{KUBELET}", "hostname-override")']], kflag("hostname-override", "node-a")),
    att("4.2.8", "eventrecordqps", "kubelet eventRecordQPS must be reviewed as suited to the cluster's event volume", "kubelet_event_record_qps_reviewed"),
    kubelet("4.2.9", "--tls-cert-file", "kubelet serving certificate and key must be given (--tls-cert-file/--tls-private-key-file or tlsCertFile/tlsPrivateKeyFile)",
            [[f'_nonempty_flag("{KUBELET}", "tls-cert-file")', f'_nonempty_flag("{KUBELET}", "tls-private-key-file")'],
             [f'_unset("{KUBELET}", "tls-cert-file")', f'_unset("{KUBELET}", "tls-private-key-file")',
              '_nonempty(_kcv(["tlsCertFile"]))', '_nonempty(_kcv(["tlsPrivateKeyFile"]))']],
            rm("/kubelet/config/tlsPrivateKeyFile")),
    kubelet("4.2.10", "--rotate-certificates", "kubelet client certificate rotation must not be switched off (--rotate-certificates, rotateCertificates)",
            [[f'_flag_true("{KUBELET}", "rotate-certificates")'],
             [f'_unset("{KUBELET}", "rotate-certificates")', '_kcv(["rotateCertificates"]) in {null, true}']],
            kflag("rotate-certificates", "false")),
    kubelet("4.2.11", "rotatekubeletservercertificate", "kubelet serving certificate rotation must be on (serverTLSBootstrap, --rotate-server-certificates or the RotateKubeletServerCertificate gate)",
            [['_kcv(["serverTLSBootstrap"]) == true'],
             [f'_flag_true("{KUBELET}", "rotate-server-certificates")'],
             [f'_gate_all_true("{KUBELET}", "RotateKubeletServerCertificate")'],
             [f'count(_gate_vals("{KUBELET}", "RotateKubeletServerCertificate")) == 0',
              '_kcv(["featureGates", "RotateKubeletServerCertificate"]) == true']],
            rm("/kubelet/config/serverTLSBootstrap")),
    kubelet("4.2.12", "ciphers", "kubelet TLS cipher suites must be given and hold only the strong suites (--tls-cipher-suites or tlsCipherSuites)",
            [[f'count(_csv("{KUBELET}", "tls-cipher-suites")) > 0', f'count(_csv("{KUBELET}", "tls-cipher-suites") - _strong_kubelet_ciphers) == 0',
              f'not _unset("{KUBELET}", "tls-cipher-suites")'],
             [f'_unset("{KUBELET}", "tls-cipher-suites")', 'is_array(_kcv(["tlsCipherSuites"]))', 'count(_kcv(["tlsCipherSuites"])) > 0',
              'every s in _kcv(["tlsCipherSuites"]) { s in _strong_kubelet_ciphers }']],
            kcfg("tlsCipherSuites/-", "TLS_RSA_WITH_AES_256_GCM_SHA384")),
    kubelet("4.2.13", "pids", "kubelet pod PID limit must be a positive number (--pod-max-pids or podPidsLimit)",
            [[f'_num_flag("{KUBELET}", "pod-max-pids") > 0'],
             [f'_unset("{KUBELET}", "pod-max-pids")', 'is_number(_kcv(["podPidsLimit"]))', '_kcv(["podPidsLimit"]) > 0']],
            kcfg("podPidsLimit", -1)),
    kubelet("4.2.14", "--seccomp-default", "kubelet default seccomp profile must be on (--seccomp-default or seccompDefault)",
            [[f'_flag_true("{KUBELET}", "seccomp-default")'],
             [f'_unset("{KUBELET}", "seccomp-default")', '_kcv(["seccompDefault"]) == true']],
            rm("/kubelet/config/seccompDefault")),
    fact("4.3.1", "kube-proxy metrics", "kube-proxy metrics endpoint must bind to loopback only (--metrics-bind-address, metricsBindAddress)",
         ["_kube_proxy_collected"], "kube_proxy.running (and kube_proxy.flags, plus kube_proxy.config when --config is set, when it runs)",
         [["input.kube_proxy.running == false"],
          ["input.kube_proxy.running == true", "_kube_proxy_flag_metrics_ok", "_kube_proxy_config_metrics_ok"]],
         add("/kube_proxy/config/metricsBindAddress", "0.0.0.0:10249"), rm("/kube_proxy/flags")),
    # ── 5 policies ──────────────────────────────────────────────────────────────────────────────
    att("5.1.1", "cluster-admin", "every cluster-admin binding must be reviewed as needed", "cluster_admin_bindings_reviewed"),
    att("5.1.2", "secrets", "get, list and watch rights on Secrets must be reviewed and kept small", "secret_access_reviewed"),
    att("5.1.3", "wildcard", "wildcards in Role and ClusterRole rules must be reviewed and kept small", "rbac_wildcards_reviewed"),
    att("5.1.4", "create pods", "the right to create Pods must be reviewed and kept small", "pod_create_access_reviewed"),
    fact("5.1.5", "default service accounts", "every namespace's default ServiceAccount must have token automount off and no added role bindings",
         ["is_array(input.service_accounts.default)", "count(input.service_accounts.default) > 0",
          'input.collection_status.default_service_accounts == "ok"'],
         "service_accounts.default / collection_status.default_service_accounts",
         [["every sa in input.service_accounts.default { sa.automount_token == false; is_array(sa.role_bindings); count(sa.role_bindings) == 0 }"]],
         add("/service_accounts/default/0/automount_token", True), rm("/service_accounts")),
    att("5.1.6", "tokens are only mounted", "Pods and ServiceAccounts that mount an API token must be reviewed as needing it", "service_account_token_mounts_reviewed"),
    att("5.1.7", "system:masters", "credentials in the system:masters group must not be in use", "system_masters_not_used"),
    att("5.1.8", "impersonate", "bind, impersonate and escalate rights must be reviewed and kept small", "bind_impersonate_escalate_reviewed"),
    att("5.1.9", "persistent volumes", "the right to create PersistentVolumes must be reviewed and kept small", "persistent_volume_create_access_reviewed"),
    att("5.1.10", "proxy sub-resource", "rights on nodes/proxy must be reviewed and kept small", "node_proxy_access_reviewed"),
    att("5.1.11", "approval sub-resource", "rights on certificatesigningrequests/approval must be reviewed and kept small", "csr_approval_access_reviewed"),
    att("5.1.12", "webhook configuration", "rights on validating and mutating webhook configurations must be reviewed and kept small", "webhook_config_access_reviewed"),
    att("5.1.13", "token creation", "the right to create serviceaccounts/token must be reviewed and kept small", "service_account_token_create_access_reviewed"),
    att("5.1.14", "fine-grained subresources", "principals bound to nodes/proxy must be reviewed for a move to the fine-grained kubelet subresources", "kubelet_fine_grained_access_reviewed"),
    att("5.2.1", "policy control mechanism", "a pod admission policy mechanism must be active in the cluster", "policy_control_mechanism_active"),
    att("5.2.2", "privileged containers", "admission policy must keep privileged containers out except where approved", "admission_privileged_restricted"),
    att("5.2.3", "host process id", "admission policy must keep hostPID pods out except where approved", "admission_host_pid_restricted"),
    att("5.2.4", "host ipc", "admission policy must keep hostIPC pods out except where approved", "admission_host_ipc_restricted"),
    att("5.2.5", "host network", "admission policy must keep hostNetwork pods out except where approved", "admission_host_network_restricted"),
    att("5.2.6", "allowprivilegeescalation", "admission policy must keep allowPrivilegeEscalation containers out except where approved", "admission_privilege_escalation_restricted"),
    att("5.2.7", "root containers", "admission policy must keep containers running as UID 0 out except where approved", "admission_root_containers_restricted"),
    att("5.2.8", "net_raw", "admission policy must keep the NET_RAW capability out except where approved", "admission_net_raw_restricted"),
    att("5.2.9", "capabilities assigned", "admission policy must require containers to drop capabilities except where approved", "admission_capabilities_restricted"),
    att("5.2.10", "hostprocess", "admission policy must keep Windows hostProcess containers out except where approved", "admission_windows_host_process_restricted"),
    att("5.2.11", "hostpath", "admission policy must keep hostPath volumes out except where approved", "admission_host_path_restricted"),
    att("5.2.12", "hostports", "admission policy must keep hostPort use out except where approved", "admission_host_ports_restricted"),
    att("5.2.13", "procmounts", "admission policy must keep unmasked procMount containers out except where approved", "admission_proc_mount_restricted"),
    att("5.3.1", "cni", "the CNI plugin in use must enforce ingress and egress NetworkPolicy", "cni_enforces_network_policies"),
    fact("5.3.2", "namespaces have network policies", "every namespace must have at least one NetworkPolicy",
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
    att("5.5.1", "image provenance", "image provenance admission control must be in place and reviewed", "image_provenance_configured"),
    att("5.6.1", "administrative boundaries", "namespaces must be reviewed as the administrative boundaries in use", "namespace_boundaries_reviewed"),
    att("5.6.2", "seccomp", "pod definitions must be reviewed for the RuntimeDefault seccomp profile", "pod_seccomp_profiles_reviewed"),
    att("5.6.3", "security context", "pod and container security contexts must be reviewed", "pod_security_contexts_reviewed"),
    fact("5.6.4", "default namespace", "the default namespace must hold nothing but the kubernetes Service",
         ['is_array(input.cluster.namespace_resources["default"])', 'input.collection_status.namespace_resources == "ok"'],
         "cluster.namespace_resources.default / collection_status.namespace_resources",
         [['every r in input.cluster.namespace_resources["default"] { r == "service/kubernetes" }']],
         add("/cluster/namespace_resources/default/-", "pod/debug"), rm("/collection_status")),
]

# ── workbook cross-check: abort on any id, count, status, profile or keyword mismatch ─────────────────
ids = [c["id"] for c in C]
if len(ids) != len(set(ids)):
    sys.exit("ABORT: duplicate id in the logic table")
if set(ids) != set(WB):
    sys.exit(f"ABORT: workbook and logic table differ: only in workbook {sorted(set(WB) - set(ids), key=idkey)}, "
             f"only in table {sorted(set(ids) - set(WB), key=idkey)}")
if ids != sorted(ids, key=idkey):
    sys.exit("ABORT: logic table is not in id order")
got = {"total": len(WB), "Automated": sum(w["assessment"] == "Automated" for w in WB.values()),
       "Manual": sum(w["assessment"] == "Manual" for w in WB.values()),
       "profiles": {p: sum(w["profiles"] == [p] for w in WB.values()) for p in PROFILES}}
if got != EXPECT:
    sys.exit(f"ABORT: workbook counts {got} differ from the expected {EXPECT}")
for c in C:
    w = WB[c["id"]]
    if c["kw"] not in w["wb_title"].lower():
        sys.exit(f"ABORT: {c['id']} keyword {c['kw']!r} is not in the workbook title; the id may have been renumbered")
    if w["assessment"] == "Automated" and c["kind"] != "fact":
        sys.exit(f"ABORT: {c['id']} is Automated in the workbook but attested here")
    if neutralize_title(c["title"]) != c["title"]:
        sys.exit(f"ABORT: {c['id']} title is not stable under neutralize_title")
    w["title"] = c["title"]  # our wording; the workbook title is never written out
for w in WB.values():
    del w["wb_title"]

SECTIONS = {"1": ("control_plane", "Control plane components"), "2": ("etcd", "etcd"),
            "3": ("control_plane_config", "Control plane configuration"), "4": ("worker_nodes", "Worker nodes"),
            "5": ("policies", "Policies")}


def section(cid):
    return SECTIONS[cid.split(".")[0]][0]


def f(path, mode, owner="root"):
    return {"path": path, "mode": mode, "owner": owner, "group": owner}


PKI = "/etc/kubernetes/pki"
GREEN = {
    "api_server": {
        "flags": {
            "anonymous-auth": "false", "kubelet-client-certificate": f"{PKI}/apiserver-kubelet-client.crt",
            "kubelet-client-key": f"{PKI}/apiserver-kubelet-client.key", "kubelet-certificate-authority": f"{PKI}/ca.crt",
            "authorization-mode": "Node,RBAC",
            "enable-admission-plugins": "NodeRestriction,EventRateLimit,AlwaysPullImages,DenyServiceExternalIPs",
            "profiling": "false", "audit-log-path": "/var/log/kubernetes/audit.log", "audit-log-maxage": "30",
            "audit-log-maxbackup": "10", "audit-log-maxsize": "100", "audit-policy-file": "/etc/kubernetes/audit-policy.yaml",
            "service-account-lookup": "true", "service-account-key-file": f"{PKI}/sa.pub",
            "etcd-certfile": f"{PKI}/apiserver-etcd-client.crt", "etcd-keyfile": f"{PKI}/apiserver-etcd-client.key",
            "etcd-cafile": f"{PKI}/etcd/ca.crt", "tls-cert-file": f"{PKI}/apiserver.crt",
            "tls-private-key-file": f"{PKI}/apiserver.key", "client-ca-file": f"{PKI}/ca.crt",
            "encryption-provider-config": "/etc/kubernetes/enc/config.yaml",
            "tls-cipher-suites": "TLS_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "service-account-extend-token-expiration": "false",
        },
        "audit_policy": {"apiVersion": "audit.k8s.io/v1", "kind": "Policy", "rules": [{"level": "Metadata"}]},
        "encryption_config": {"resources": [{"resources": ["secrets"], "providers": ["aescbc", "identity"]}]},
    },
    "controller_manager": {"flags": {
        "terminated-pod-gc-threshold": "1000", "profiling": "false", "use-service-account-credentials": "true",
        "service-account-private-key-file": f"{PKI}/sa.key", "root-ca-file": f"{PKI}/ca.crt", "bind-address": "127.0.0.1"}},
    "scheduler": {"flags": {"profiling": "false", "bind-address": "127.0.0.1"}},
    "etcd": {"flags": {
        "cert-file": f"{PKI}/etcd/server.crt", "key-file": f"{PKI}/etcd/server.key", "client-cert-auth": "true",
        "peer-cert-file": f"{PKI}/etcd/peer.crt", "peer-key-file": f"{PKI}/etcd/peer.key", "peer-client-cert-auth": "true",
        "trusted-ca-file": f"{PKI}/etcd/ca.crt", "data-dir": "/var/lib/etcd"}},
    "kubelet": {
        "flags": {"config": "/var/lib/kubelet/config.yaml", "kubeconfig": "/etc/kubernetes/kubelet.conf",
                  "config-dir": "/etc/kubernetes/kubelet.conf.d"},
        "config": {
            "authentication": {"anonymous": {"enabled": False}, "x509": {"clientCAFile": f"{PKI}/ca.crt"}},
            "authorization": {"mode": "Webhook"}, "readOnlyPort": 0, "streamingConnectionIdleTimeout": "4h0m0s",
            "makeIPTablesUtilChains": True, "tlsCertFile": "/var/lib/kubelet/pki/kubelet.crt",
            "tlsPrivateKeyFile": "/var/lib/kubelet/pki/kubelet.key", "rotateCertificates": True, "serverTLSBootstrap": True,
            "tlsCipherSuites": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"], "podPidsLimit": 4096, "seccompDefault": True,
        },
    },
    "kube_proxy": {"running": True, "flags": {"config": "/var/lib/kube-proxy/config.conf"},
                   "config": {"metricsBindAddress": "127.0.0.1:10249"}},
    "files": {
        "manifests": [f("/etc/kubernetes/manifests/kube-apiserver.yaml", "0600"),
                      f("/etc/kubernetes/manifests/kube-controller-manager.yaml", "0600"),
                      f("/etc/kubernetes/manifests/kube-scheduler.yaml", "0600"), f("/etc/kubernetes/manifests/etcd.yaml", "0600")],
        "cni": [f("/etc/cni/net.d/10-calico.conflist", "0600")],
        "etcd_data": [f("/var/lib/etcd", "0700", "etcd"), f("/var/lib/etcd/member", "0700", "etcd")],
        "control_plane_confs": [f("/etc/kubernetes/admin.conf", "0600"), f("/etc/kubernetes/scheduler.conf", "0600"),
                                f("/etc/kubernetes/controller-manager.conf", "0600"), f("/etc/kubernetes/super-admin.conf", "0600")],
        "pki": [f(f"{PKI}/ca.crt", "0644"), f(f"{PKI}/ca.key", "0600"), f(PKI, "0755"),
                f(f"{PKI}/apiserver.crt", "0644"), f(f"{PKI}/apiserver.key", "0600")],
        "kubelet_service": [f("/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf", "0600")],
        "kube_proxy_kubeconfig": [f("/var/lib/kube-proxy/kubeconfig.conf", "0600")],
        "kubelet_kubeconfig": [f("/etc/kubernetes/kubelet.conf", "0600")],
        "kubelet_client_ca": [f(f"{PKI}/ca.crt", "0644")],
        "kubelet_config_yaml": [f("/var/lib/kubelet/config.yaml", "0600")],
        "kubelet_config_dir": [f("/etc/kubernetes/kubelet.conf.d", "0755"), f("/etc/kubernetes/kubelet.conf.d/10-limits.conf", "0644")],
    },
    "service_accounts": {"default": [{"namespace": "default", "automount_token": False, "role_bindings": []},
                                     {"namespace": "kube-system", "automount_token": False, "role_bindings": []}]},
    "network_policies": {"namespaces_without_policy": []},
    "secrets": {"env_var_usage_count": 0},
    "cluster": {"namespace_resources": {"default": ["service/kubernetes"]}},
    "collection_status": {"default_service_accounts": "ok", "network_policies": "ok", "secret_env_scan": "ok",
                          "namespace_resources": "ok"},
    "attest": {c["attest"]: True for c in C if c["kind"] == "attest"},
}

fact_manual = [c["id"] for c in C if c["kind"] == "fact" and WB[c["id"]]["assessment"] == "Manual"]
attest_ids = [c["id"] for c in C if c["kind"] == "attest"]
N = len(C)
NP = EXPECT["profiles"]


def meta(title, density, basis):
    return f'''# METADATA
# title: "{title}"
# custom:
#   class: security
#   framework: cis_kubernetes
#   source: cis
#   domains: [kubernetes, container]
#   coverage:
#     checks: 0
#     cited: 0
#     density: {density}
#     basis: {basis}
#     tested: true
#     entrypoint: compliance_report
#     guard: self
#     as_of: v2.4.2
'''


def wrap(idlist, width=112):
    out, line = [], "#   "
    for i in idlist:
        if len(line) + len(i) + 2 > width:
            out.append(line.rstrip())
            line = "#   "
        line += i + ", "
    out.append(line.rstrip().rstrip(","))
    return "\n".join(out)


HEADER = meta(BENCH, "sized", "size") + f'''package cis_kubernetes

# {BENCH}. Generated by tools/cis_generators/gen_kubernetes.py from the CIS workbook: do not edit by hand,
# regenerate. Replaces the v1.10.0-labelled module that lived in this directory.
#
# {N} recommendations, every one in the benchmark ({EXPECT["Automated"]} Automated, {EXPECT["Manual"]} Manual); ids, status and profile
# are read from the workbook. `recommendations` lists each id with its level, status and profile.
# - {len(C) - len(attest_ids)} are decided from collected facts and fail closed: facts not collected =>
#   "<id>: evidence missing — <field> not collected".
# - {len(fact_manual)} of those are Manual in the workbook but their audit is a flag, file or object comparison, so they
#   are checked like Automated ones:
{wrap(fact_manual)}
# - {len(attest_ids)} need a human judgement and read an attestation boolean under input.attest (not attested => violation):
{wrap(attest_ids)}
# - 1.2.1 with custom anonymous paths and 1.2.20 with a request timeout set also need an attestation
#   (attest.api_anonymous_paths_required, attest.api_request_timeout_appropriate).
#
# Profiles: Level 1 / Level 2 for Master Node and Worker Node ({NP["Level 1 - Master Node"]} + {NP["Level 2 - Master Node"]} master, {NP["Level 1 - Worker Node"]} + {NP["Level 2 - Worker Node"]} worker; the workbook
# puts every recommendation in exactly one). input.cis_profile selects the recommendations in scope:
#   level: 1 | 2 (default 2; Level 2 includes Level 1)
#   role:  "master" (also "control_plane") | "worker"; absent or unknown => both roles (strictest, all {N})
# A recommendation outside the selection raises nothing and is not counted in total_controls.
#
# Input contract. It is the DISA Kubernetes STIG module's (benchmarks/stig/kubernetes/core.rego), so one collector
# feeds both; "NEW" marks the paths this module adds.
#   api_server.flags / controller_manager.flags / scheduler.flags / etcd.flags : flag name -> string value, as the
#       component was started. Names are normalised ("--a_b" == "a-b"); a flag present under two spellings or with
#       a non-string value is ambiguous and fails its check. An empty map counts as not collected.
#   api_server.audit_policy          : parsed --audit-policy-file {{apiVersion, kind, rules[]}}
#   api_server.encryption_config     : parsed --encryption-provider-config {{resources: [{{resources[], providers[]}}]}}
#                                      (providers = provider names in file order; the first one writes)
#   api_server.authentication_config : NEW parsed --authentication-config (anonymous.enabled, anonymous.conditions[].path)
#   etcd.member_count                : NEW optional; 1 exempts a single-member etcd from 2.4 and 2.5
#   kubelet.flags                    : kubelet command-line flags ({{}} if none)
#   kubelet.config                   : the effective KubeletConfiguration as parsed YAML; read only when
#                                      kubelet.flags has --config
#   kube_proxy.running               : bool; false passes 4.1.3, 4.1.4 and 4.3.1
#   kube_proxy.flags / kube_proxy.config : NEW kube-proxy flags and its parsed --config file (metricsBindAddress)
#   files.<group>[]                  : {{path, mode, owner, group}}; mode is an octal STRING ("0600" or "600"), compared
#                                      with bit masks. Groups: manifests (kube-apiserver, kube-controller-manager,
#                                      kube-scheduler, etcd), etcd_data (must include the --data-dir directory itself),
#                                      control_plane_confs (admin.conf, scheduler.conf, controller-manager.conf and
#                                      super-admin.conf when it exists), pki (the directory tree), kubelet_kubeconfig,
#                                      kubelet_client_ca, kubelet_config_yaml, kube_proxy_kubeconfig, and NEW: cni,
#                                      kubelet_service, kubelet_config_dir (the --config-dir directory and its files)
#   service_accounts.default[]       : NEW {{namespace, automount_token, role_bindings[]}} for every namespace's default
#                                      ServiceAccount (role_bindings = bindings beyond the built-in ones)
#   network_policies.namespaces_without_policy[] : NEW namespaces holding no NetworkPolicy
#   secrets.env_var_usage_count      : number of secretKeyRef environment variables in workloads
#   cluster.namespace_resources.default : names of the objects in the default namespace ("service/kubernetes")
#   collection_status.<query>        : "ok" when the cluster query ran to completion: secret_env_scan,
#                                      namespace_resources, and NEW default_service_accounts, network_policies
#   attest.<key>                     : attestation booleans

import rego.v1

default compliant := false

compliant if {{
	count(in_scope) > 0
	count(violations) == 0
}}

violations := sort([m | some m in _all_violations])

'''

HELPERS = r'''# ── profile ──────────────────────────────────────────────────────────────────
default _cis_profile := {}

_cis_profile := p if {
	p := input.cis_profile
	is_object(p)
}

default level := 2

level := 1 if _cis_profile.level == 1

_role_alias := {"master": "master", "control_plane": "master", "control-plane": "master", "worker": "worker"}

default node_roles := {"master", "worker"}

node_roles := {r} if {
	is_string(_cis_profile.role)
	r := _role_alias[lower(_cis_profile.role)]
}

_role_label := {"master": "Master", "worker": "Worker"}

_selected_profiles := {sprintf("Level %d - %s Node", [l, _role_label[r]]) |
	some l in numbers.range(1, level)
	some r in node_roles
}

in_scope contains id if {
	some id, r in recommendations
	some p in r.profiles
	p in _selected_profiles
}

_applies(id) if id in in_scope

# ── flags ────────────────────────────────────────────────────────────────────
# Components normalise flag names ("--a_b", "a-b" and "a_b" are one flag). A flag is read only when exactly one
# key normalises to its name and its value is a string; anything else is ambiguous: neither set nor unset.
_norm(k) := replace(trim_suffix(trim_left(k, "-"), "+"), "_", "-")

_flags(c) := fl if {
	fl := object.get(input, [c, "flags"], null)
	is_object(fl)
}

_keys(c, name) := [k | some k, _ in _flags(c); _norm(k) == name]

# the component's flags were collected (a control-plane component always has some)
_component(c) if count(_flags(c)) > 0

_unset(c, name) if count(_keys(c, name)) == 0

_fl(c, name) := v if {
	ks := _keys(c, name)
	count(ks) == 1
	v := _flags(c)[ks[0]]
	is_string(v)
}

_nonempty(s) if {
	is_string(s)
	trim_space(s) != ""
}

_nonempty_flag(c, name) if _nonempty(_fl(c, name))

_fl_or_empty(c, name) := "" if _unset(c, name)

_fl_or_empty(c, name) := v if v := _fl(c, name)

# comma-separated flag as a set of trimmed entries (empty when unset; undefined when ambiguous)
_csv(c, name) := s if {
	v := _fl_or_empty(c, name)
	s := {trim_space(x) | some x in split(v, ","); trim_space(x) != ""}
}

# the comma-separated flag is readable and does not list <x> (an ambiguous flag fails)
_csv_lacks(c, name, x) if {
	s := _csv(c, name)
	not x in s
}

# boolean flag values, parsed the way the components do
_bool(v) := "true" if lower(trim_space(v)) in {"1", "t", "true"}

_bool(v) := "false" if lower(trim_space(v)) in {"0", "f", "false"}

_flag_true(c, name) if _bool(_fl(c, name)) == "true"

_flag_false(c, name) if _bool(_fl(c, name)) == "false"

_flag_not_true(c, name) if _unset(c, name)

_flag_not_true(c, name) if _flag_false(c, name)

_flag_not_false(c, name) if _unset(c, name)

_flag_not_false(c, name) if _flag_true(c, name)

_num_flag(c, name) := to_number(v) if {
	v := trim_space(_fl(c, name))
	regex.match(`^-?[0-9]+$`, v)
}

# --feature-gates "A=true,B=false": every entry for one gate; an entry that does not parse is "invalid"
_gate_vals(c, name) := vals if {
	fg := _fl_or_empty(c, "feature-gates")
	vals := [_gate_val(p) |
		some kv in split(fg, ",")
	p := split(trim_space(kv), "=")
		trim_space(p[0]) == name
	]
}

_gate_val(p) := b if {
	count(p) == 2
	b := _bool(p[1])
}

_gate_val(p) := "invalid" if count(p) != 2

_gate_val(p) := "invalid" if {
	count(p) == 2
	not _bool(p[1])
}

# never switched off (and never unparseable): an unset gate keeps its default
_gate_never_false(c, name) if {
	vals := _gate_vals(c, name)
	every v in vals { v == "true" }
}

_gate_all_true(c, name) if {
	vals := _gate_vals(c, name)
	count(vals) > 0
	every v in vals { v == "true" }
}

# loopback is 127.0.0.0/8 or ::1; 0.0.0.0 and :: are wildcards
_loopback_host(h) if regex.match(`^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`, h)

_loopback_host(h) if h == "::1"

_loopback(v) if _loopback_host(trim_space(v))

_loopback_hostport(v) if _loopback(v)

_loopback_hostport(v) if {
	m := regex.find_all_string_submatch_n(`^\[?([^\]]+?)\]?:[0-9]+$`, trim_space(v), 1)
	_loopback_host(m[0][1])
}

_strong_api_ciphers := __API_CIPHERS__

_strong_kubelet_ciphers := __KUBELET_CIPHERS__

# ── API server files read through flags ──────────────────────────────────────
default _api_anonymous_collected := false

_api_anonymous_collected if {
	_component("api_server")
	_unset("api_server", "authentication-config")
}

_api_anonymous_collected if {
	_component("api_server")
	is_object(input.api_server.authentication_config)
}

_authn_anonymous := a if {
	_nonempty_flag("api_server", "authentication-config")
	a := input.api_server.authentication_config.anonymous
	is_object(a)
}

default _encryption_collected := false

_encryption_collected if {
	_component("api_server")
	_unset("api_server", "encryption-provider-config")
}

_encryption_collected if {
	_component("api_server")
	is_object(input.api_server.encryption_config)
}

# resource entries that cover Secrets (by name or by wildcard)
_encryption_secret_entries := [r |
	some r in input.api_server.encryption_config.resources
	count({n | some n in r.resources; n in {"secrets", "secrets.", "*.", "*.*"}}) > 0
]

default _audit_policy_collected := false

_audit_policy_collected if {
	_component("api_server")
	_unset("api_server", "audit-policy-file")
}

_audit_policy_collected if {
	_component("api_server")
	is_object(input.api_server.audit_policy)
}

# ── kubelet ──────────────────────────────────────────────────────────────────
# The configuration file counts only when the kubelet was started with --config; a flag overrides the file.
_kubelet_config_in_use if _nonempty_flag("kubelet", "config")

default _kubelet_collected := false

_kubelet_collected if {
	is_object(input.kubelet.flags)
	_unset("kubelet", "config")
}

_kubelet_collected if {
	_kubelet_config_in_use
	is_object(input.kubelet.config)
}

default _kc := {}

_kc := input.kubelet.config if {
	_kubelet_config_in_use
	is_object(input.kubelet.config)
}

# a configuration file value, null when the file does not set it
_kcv(path) := object.get(_kc, path, null)

_dropin_dir := d if {
	d := trim_right(trim_space(_fl("kubelet", "config-dir")), "/")
	d != ""
}

_dropin_dirs := [x | some x in _files("kubelet_config_dir"); is_string(x.path); trim_right(x.path, "/") == _dropin_dir]

_dropin_confs := [x | some x in _files("kubelet_config_dir"); is_string(x.path); endswith(x.path, ".conf")]

default _kubelet_yaml_collected := false

_kubelet_yaml_collected if {
	is_object(input.kubelet.flags)
	_unset("kubelet", "config")
}

_kubelet_yaml_collected if {
	_kubelet_config_in_use
	count(_files("kubelet_config_yaml")) > 0
}

default _kubelet_dropin_collected := false

_kubelet_dropin_collected if {
	is_object(input.kubelet.flags)
	_unset("kubelet", "config-dir")
}

_kubelet_dropin_collected if count(_dropin_dirs) > 0

# ── kube-proxy ───────────────────────────────────────────────────────────────
default _kube_proxy_files_collected := false

_kube_proxy_files_collected if input.kube_proxy.running == false

_kube_proxy_files_collected if {
	input.kube_proxy.running == true
	count(_files("kube_proxy_kubeconfig")) > 0
}

default _kube_proxy_collected := false

_kube_proxy_collected if input.kube_proxy.running == false

_kube_proxy_collected if {
	input.kube_proxy.running == true
	is_object(input.kube_proxy.flags)
	_unset("kube_proxy", "config")
}

_kube_proxy_collected if {
	input.kube_proxy.running == true
	_nonempty_flag("kube_proxy", "config")
	is_object(input.kube_proxy.config)
}

_kube_proxy_flag_metrics_ok if _unset("kube_proxy", "metrics-bind-address")

_kube_proxy_flag_metrics_ok if _loopback_hostport(_fl("kube_proxy", "metrics-bind-address"))

_kube_proxy_config_metrics_ok if _unset("kube_proxy", "config")

_kube_proxy_config_metrics_ok if object.get(input.kube_proxy.config, "metricsBindAddress", "") == ""

_kube_proxy_config_metrics_ok if _loopback_hostport(input.kube_proxy.config.metricsBindAddress)

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

_admin_confs := [x | some x in _files("control_plane_confs"); is_string(x.path); _base(x.path) in {"admin.conf", "super-admin.conf"}]

_pki_certs(g) := [x | some x in _files(g); is_string(x.path); endswith(x.path, ".crt")]

_pki_keys(g) := [x | some x in _files(g); is_string(x.path); endswith(x.path, ".key")]

default _etcd_data_dir := "/var/lib/etcd"

_etcd_data_dir := d if {
	d := trim_right(trim_space(_fl("etcd", "data-dir")), "/")
	d != ""
}

_etcd_dir_entries := [x | some x in _files("etcd_data"); is_string(x.path); trim_right(x.path, "/") == _etcd_data_dir]

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

'''.replace("__API_CIPHERS__", json.dumps(sorted(STRONG_API)).replace("[", "{").replace("]", "}")) \
   .replace("__KUBELET_CIPHERS__", json.dumps(sorted(STRONG_KUBELET)).replace("[", "{").replace("]", "}"))

parts = [HEADER]
for num, (name, label) in SECTIONS.items():
    parts.append(f"# Section {num}: {label}\n{name}_violations := sort([m | some m in _v_{name}])\n\n"
                 f"_all_violations contains m if some m in _v_{name}\n")
parts.append(HELPERS)
for c in C:
    c2 = dict(c)
    if c["kind"] == "fact" and len(c["ok"]) == 0:
        sys.exit(f"ABORT: {c['id']} has no pass predicate")
    parts.append(emit_control(c2, WB, f"_v_{section(c['id'])}", applies=True))

parts.append("# Every recommendation in the benchmark: our description, level, assessment status, CIS profile, section.\n"
             "recommendations := " + table(C, WB, lambda c, w: {"section": int(c["id"].split(".")[0])}) + "\n")
sect_obj = ",\n".join(
    f'\t"{name}": {{"name": "{label}", "total": count(_section_ids({num})), "failed": count(_section_ids({num}) & _failed_ids), '
    f'"violations": {name}_violations}}' for num, (name, label) in SECTIONS.items())
parts.append(f'''
_failed_ids := {{id | some v in violations; id := split(v, ":")[0]}}

_level_ids(l) := {{id | some id in in_scope; recommendations[id].level == l}}

_section_ids(s) := {{id | some id in in_scope; recommendations[id].section == s}}

section_results := {{
{sect_obj},
}}

default _pct := 0

_pct := round(((count(in_scope) - count(_failed_ids)) * 100000) / count(in_scope)) / 1000 if count(in_scope) > 0

compliance_report := {{
	"framework": "cis_kubernetes",
	"benchmark": "{BENCH}",
	"version": "{VERSION}",
	"profile": {{"level": level, "roles": sort([r | some r in node_roles])}},
	"total_controls": count(in_scope),
	"benchmark_total_controls": count(recommendations),
	"standard_total": {N},
	"standard_total_source": "{BENCH}, recommendations counted from the CIS workbook",
	"failed_controls": count(_failed_ids),
	"passed_controls": count(in_scope) - count(_failed_ids),
	"compliance_percentage": _pct,
	"level_1": {{"total": count(_level_ids(1)), "failed": count(_level_ids(1) & _failed_ids)}},
	"level_2": {{"total": count(_level_ids(2)), "failed": count(_level_ids(2) & _failed_ids)}},
	"section_results": section_results,
	"compliant": compliant,
	"violation_count": count(violations),
	"violations": violations,
}}
''')
os.makedirs(f"{OUT}/tests", exist_ok=True)
open(f"{OUT}/cis_kubernetes.rego", "w").write("\n".join(parts))

MAIN = meta(f"{BENCH} - compliance_report entrypoint", "orchestrator", "role") + f'''package cis_kubernetes.main

# OPA query path: /v1/data/cis_kubernetes/main/compliance_report (the framework key's entrypoint).
# Thin alias of data.cis_kubernetes, which already fails closed per recommendation: every check whose facts were
# not collected is a violation, so empty input fails every recommendation in scope. Generated by
# tools/cis_generators/gen_kubernetes.py.

import data.cis_kubernetes as bench
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

compliant := bench.compliant

violations := _report_violations

# With no facts at all the report says so explicitly, so an empty assessment can never read as a result. The
# notice is a finding, not a control: total_controls and failed_controls count recommendations only.
_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["cis_kubernetes"],
)

_report_violations := array.concat(bench.violations, [_no_facts_msg]) if not _facts_supplied

_report_violations := bench.violations if _facts_supplied

compliance_report := object.union(bench.compliance_report, {{
	"facts_supplied": _facts_supplied,
	"violation_count": count(_report_violations),
	"violations": _report_violations,
}})
'''
open(f"{OUT}/cis_kubernetes_main.rego", "w").write(MAIN)

M1, M2, W1, W2 = (NP[p] for p in PROFILES)
TESTS = f'''package cis_kubernetes_test

import rego.v1

import data.cis_kubernetes as b
import data.cis_kubernetes.main as bridge

# Generated per-recommendation tests for {BENCH}: every recommendation has a pass test (green input) and a
# fail test; fact-based checks also have an evidence-missing test; attestations fail when false or absent.
# Profile, report-contract and helper tests come first.

green := {json.dumps(GREEN, indent=chr(9), ensure_ascii=False)}

_has_id(vs, id) if {{
	some v in vs
	startswith(v, concat("", [id, ":"]))
}}

_patched(ops) := json.patch(green, ops)

test_green_input_is_compliant if {{
	vs := b.violations with input as green
	count(vs) == 0
	b.compliant with input as green
	r := bridge.compliance_report with input as green
	r.compliant == true
	r.failed_controls == 0
	r.passed_controls == {N}
	r.compliance_percentage == 100
}}

test_recommendation_count_matches_workbook if {{
	count(b.recommendations) == {N}
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == {EXPECT["Automated"]}
	count([id | some id, r in b.recommendations; r.assessment == "Manual"]) == {EXPECT["Manual"]}
	count([id | some id, r in b.recommendations; r.profiles == ["Level 1 - Master Node"]]) == {M1}
	count([id | some id, r in b.recommendations; r.profiles == ["Level 2 - Master Node"]]) == {M2}
	count([id | some id, r in b.recommendations; r.profiles == ["Level 1 - Worker Node"]]) == {W1}
	count([id | some id, r in b.recommendations; r.profiles == ["Level 2 - Worker Node"]]) == {W2}
	count([id | some id, r in b.recommendations; r.check == "attestation"]) == {len(attest_ids)}
}}

test_report_contract_on_empty_input if {{
	r := bridge.compliance_report with input as {{}}
	r.compliant == false
	r.total_controls == {N}
	r.failed_controls == {N}
	r.passed_controls == 0
	r.compliance_percentage == 0
	r.facts_supplied == false
	is_array(r.violations)
	r.violation_count == count(r.violations)
	r.level_1.total == {M1 + W1}
	r.level_2.total == {M2 + W2}
	r.version == "{VERSION}"
}}

_profile_total(p) := r.total_controls if r := bridge.compliance_report with input as {{"cis_profile": p}}

_profile_failed(p) := r.failed_controls if r := bridge.compliance_report with input as {{"cis_profile": p}}

test_profile_totals if {{
	_profile_total({{"level": 1}}) == {M1 + W1}
	_profile_total({{"level": 2}}) == {N}
	_profile_total({{"level": 1, "role": "master"}}) == {M1}
	_profile_total({{"level": 2, "role": "master"}}) == {M1 + M2}
	_profile_total({{"role": "control_plane"}}) == {M1 + M2}
	_profile_total({{"level": 1, "role": "worker"}}) == {W1}
	_profile_total({{"level": 2, "role": "Worker"}}) == {W1 + W2}
	_profile_total({{"level": 3, "role": "edge"}}) == {N}
}}

test_profile_fails_only_what_is_in_scope if {{
	_profile_failed({{"level": 1, "role": "master"}}) == {M1}
	_profile_failed({{"level": 2, "role": "master"}}) == {M1 + M2}
	_profile_failed({{"level": 1, "role": "worker"}}) == {W1}
	_profile_failed({{"level": 2, "role": "worker"}}) == {W1 + W2}
}}

test_worker_role_does_not_count_master_recommendations if {{
	inp := {{"cis_profile": {{"role": "worker", "level": 1}}}}
	vs := b.violations with input as inp
	not _has_id(vs, "1.1.1")
	not _has_id(vs, "4.1.1")
	not _has_id(vs, "4.2.8")
	_has_id(vs, "4.1.2")
	_has_id(vs, "5.1.3")
}}

test_master_role_does_not_count_worker_recommendations if {{
	inp := {{"cis_profile": {{"role": "master", "level": 1}}}}
	vs := b.violations with input as inp
	_has_id(vs, "1.1.1")
	_has_id(vs, "4.1.1")
	not _has_id(vs, "4.1.2")
	not _has_id(vs, "1.2.12")
	not _has_id(vs, "5.1.3")
}}

test_worker_only_facts_are_compliant_for_the_worker_profile if {{
	inp := object.union(object.remove(green, ["api_server", "controller_manager", "scheduler", "etcd"]), {{"cis_profile": {{"role": "worker"}}}})
	b.compliant with input as inp
	not b.compliant with input as object.remove(inp, ["cis_profile"])
}}

test_section_results_partition_the_scope if {{
	r := b.compliance_report with input as {{}}
	sum([s.total | some _, s in r.section_results]) == r.total_controls
	sum([s.failed | some _, s in r.section_results]) == r.failed_controls
}}

# file modes are octal bit masks: 0460 is numerically below 0600 but grants group access
test_mode_is_a_bit_mask if {{
	b.mode_within("0600", "600")
	b.mode_within("400", "600")
	b.mode_within("0o640", "644")
	not b.mode_within("0460", "600")
	not b.mode_within("0601", "600")
	not b.mode_within("4600", "600")
	not b.mode_within("1755", "755")
	not b.mode_within(600, "600")
	not b.mode_within("rw-------", "600")
	not b.mode_within("", "600")
}}

test_1_1_1_group_readable_manifest_fails if {{
	_has_id(b.violations, "1.1.1") with input as _patched([{{"op": "add", "path": "/files/manifests/0/mode", "value": "0460"}}])
	_has_id(b.violations, "1.1.1") with input as _patched([{{"op": "add", "path": "/files/manifests/0/mode", "value": 600}}])
	not _has_id(b.violations, "1.1.1") with input as _patched([{{"op": "add", "path": "/files/manifests/0/mode", "value": "400"}}])
}}

test_1_1_11_follows_the_etcd_data_dir_flag if {{
	ops := [{{"op": "add", "path": "/etcd/flags/data-dir", "value": "/data/etcd/"}}]
	vs := b.violations with input as _patched(ops)
	"1.1.11: evidence missing — files.etcd_data entry for the etcd --data-dir directory not collected" in vs
	ok := array.concat(ops, [{{"op": "add", "path": "/files/etcd_data/-", "value": {{"path": "/data/etcd", "mode": "700", "owner": "etcd", "group": "etcd"}}}}])
	not _has_id(b.violations, "1.1.11") with input as _patched(ok)
}}

test_flag_spellings_and_ambiguity if {{
	ops := [{{"op": "remove", "path": "/api_server/flags/profiling"}}, {{"op": "add", "path": "/api_server/flags/--profiling", "value": "False"}}]
	not _has_id(b.violations, "1.2.15") with input as _patched(ops)
	both := [{{"op": "add", "path": "/api_server/flags/--profiling", "value": "false"}}]
	_has_id(b.violations, "1.2.15") with input as _patched(both)
	listed := [{{"op": "add", "path": "/api_server/flags/token_auth_file", "value": ["/a", "/b"]}}]
	_has_id(b.violations, "1.2.2") with input as _patched(listed)
}}

test_1_2_1_structured_authentication if {{
	base := [{{"op": "remove", "path": "/api_server/flags/anonymous-auth"}}, {{"op": "add", "path": "/api_server/flags/authentication-config", "value": "/etc/kubernetes/authn.yaml"}}]
	"1.2.1: evidence missing — api_server.flags (and api_server.authentication_config when --authentication-config is set) not collected" in b.violations with input as _patched(base)
	off := array.concat(base, [{{"op": "add", "path": "/api_server/authentication_config", "value": {{"anonymous": {{"enabled": false}}}}}}])
	not _has_id(b.violations, "1.2.1") with input as _patched(off)
	health := array.concat(base, [{{"op": "add", "path": "/api_server/authentication_config", "value": {{"anonymous": {{"enabled": true, "conditions": [{{"path": "/healthz"}}, {{"path": "/livez"}}]}}}}}}])
	not _has_id(b.violations, "1.2.1") with input as _patched(health)
	open := array.concat(base, [{{"op": "add", "path": "/api_server/authentication_config", "value": {{"anonymous": {{"enabled": true}}}}}}])
	_has_id(b.violations, "1.2.1") with input as _patched(open)
	none := array.concat(base, [{{"op": "add", "path": "/api_server/authentication_config", "value": {{"jwt": []}}}}])
	_has_id(b.violations, "1.2.1") with input as _patched(none)
	other := array.concat(base, [{{"op": "add", "path": "/api_server/authentication_config", "value": {{"anonymous": {{"enabled": true, "conditions": [{{"path": "/metrics"}}]}}}}}}])
	_has_id(b.violations, "1.2.1") with input as _patched(other)
	attested := array.concat(other, [{{"op": "add", "path": "/attest/api_anonymous_paths_required", "value": true}}])
	not _has_id(b.violations, "1.2.1") with input as _patched(attested)
	unset := [{{"op": "remove", "path": "/api_server/flags/anonymous-auth"}}]
	_has_id(b.violations, "1.2.1") with input as _patched(unset)
}}

test_1_2_20_request_timeout if {{
	set := [{{"op": "add", "path": "/api_server/flags/request-timeout", "value": "5m"}}]
	_has_id(b.violations, "1.2.20") with input as _patched(set)
	ok := array.concat(set, [{{"op": "add", "path": "/attest/api_request_timeout_appropriate", "value": true}}])
	not _has_id(b.violations, "1.2.20") with input as _patched(ok)
	zero := array.concat(ok, [{{"op": "add", "path": "/api_server/flags/request-timeout", "value": "0"}}])
	_has_id(b.violations, "1.2.20") with input as _patched(zero)
}}

test_unset_defaults if {{
	# 1.2.10, 1.2.12, 1.2.13, 1.2.21, 1.3.6, 2.3, 2.6 pass when the flag is absent (green carries none of them)
	vs := b.violations with input as _patched([{{"op": "remove", "path": "/api_server/flags/service-account-lookup"}}])
	count(vs) == 0
	# 1.3.7 and 1.4.2 do not: the default bind address is the wildcard
	_has_id(b.violations, "1.3.7") with input as _patched([{{"op": "remove", "path": "/controller_manager/flags/bind-address"}}])
	_has_id(b.violations, "1.4.2") with input as _patched([{{"op": "add", "path": "/scheduler/flags/bind-address", "value": "::"}}])
	not _has_id(b.violations, "1.4.2") with input as _patched([{{"op": "add", "path": "/scheduler/flags/bind-address", "value": "::1"}}])
}}

test_ambiguous_flags_fail_negative_checks if {{
	listed := [{{"op": "add", "path": "/api_server/flags/enable-admission-plugins", "value": ["NodeRestriction", "AlwaysAdmit"]}}]
	_has_id(b.violations, "1.2.10") with input as _patched(listed)
	twice := [{{"op": "add", "path": "/api_server/flags/disable_admission_plugins", "value": "ServiceAccount"}}, {{"op": "add", "path": "/api_server/flags/disable-admission-plugins", "value": ""}}]
	vs := b.violations with input as _patched(twice)
	_has_id(vs, "1.2.12")
	_has_id(vs, "1.2.13")
	gates := [{{"op": "add", "path": "/controller_manager/flags/feature-gates", "value": "RotateKubeletServerCertificate=true"}}, {{"op": "add", "path": "/controller_manager/flags/feature_gates", "value": "RotateKubeletServerCertificate=false"}}]
	_has_id(b.violations, "1.3.6") with input as _patched(gates)
	kgates := [{{"op": "remove", "path": "/kubelet/config/serverTLSBootstrap"}}, {{"op": "add", "path": "/kubelet/config/featureGates", "value": {{"RotateKubeletServerCertificate": true}}}}]
	not _has_id(b.violations, "4.2.11") with input as _patched(kgates)
	kamb := array.concat(kgates, [{{"op": "add", "path": "/kubelet/flags/feature-gates", "value": ["RotateKubeletServerCertificate=false"]}}])
	_has_id(b.violations, "4.2.11") with input as _patched(kamb)
}}

test_4_1_9_only_applies_with_a_config_file if {{
	noconf := [{{"op": "add", "path": "/kubelet", "value": {{"flags": {{}}}}}}, {{"op": "remove", "path": "/files/kubelet_config_yaml"}}]
	vs := b.violations with input as _patched(noconf)
	not _has_id(vs, "4.1.9")
	not _has_id(vs, "4.1.10")
}}

test_1_3_6_feature_gate if {{
	not _has_id(b.violations, "1.3.6") with input as _patched([{{"op": "add", "path": "/controller_manager/flags/feature-gates", "value": "A=false,RotateKubeletServerCertificate=true"}}])
	_has_id(b.violations, "1.3.6") with input as _patched([{{"op": "add", "path": "/controller_manager/flags/feature-gates", "value": "RotateKubeletServerCertificate=maybe"}}])
}}

test_single_member_etcd_is_exempt_from_peer_tls if {{
	ops := [{{"op": "remove", "path": "/etcd/flags/peer-cert-file"}}, {{"op": "remove", "path": "/etcd/flags/peer-client-cert-auth"}}]
	vs := b.violations with input as _patched(ops)
	_has_id(vs, "2.4")
	_has_id(vs, "2.5")
	vs1 := b.violations with input as _patched(array.concat(ops, [{{"op": "add", "path": "/etcd/member_count", "value": 1}}]))
	not _has_id(vs1, "2.4")
	not _has_id(vs1, "2.5")
}}

test_kubelet_flags_override_the_config_file if {{
	_has_id(b.violations, "4.2.1") with input as _patched([{{"op": "add", "path": "/kubelet/flags/anonymous-auth", "value": "true"}}])
	_has_id(b.violations, "4.2.4") with input as _patched([{{"op": "add", "path": "/kubelet/flags/read-only-port", "value": "10255"}}])
	not _has_id(b.violations, "4.2.4") with input as _patched([{{"op": "remove", "path": "/kubelet/config/readOnlyPort"}}])
	_has_id(b.violations, "4.2.5") with input as _patched([{{"op": "add", "path": "/kubelet/flags/streaming-connection-idle-timeout", "value": "0"}}])
	not _has_id(b.violations, "4.2.5") with input as _patched([{{"op": "remove", "path": "/kubelet/config/streamingConnectionIdleTimeout"}}])
	_has_id(b.violations, "4.2.13") with input as _patched([{{"op": "add", "path": "/kubelet/flags/pod-max-pids", "value": "0"}}])
}}

test_kubelet_without_a_config_file if {{
	flags := {{"anonymous-auth": "false", "authorization-mode": "Webhook", "client-ca-file": "/etc/kubernetes/pki/ca.crt", "read-only-port": "0", "tls-cert-file": "/k.crt", "tls-private-key-file": "/k.key", "rotate-server-certificates": "true", "tls-cipher-suites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "pod-max-pids": "1024", "seccomp-default": "true"}}
	inp := json.patch(green, [{{"op": "add", "path": "/kubelet", "value": {{"flags": flags}}}}])
	vs := b.violations with input as inp
	count(vs) == 0
	# the file's values do not count when --config is not given
	stale := json.patch(green, [{{"op": "remove", "path": "/kubelet/flags/config"}}])
	vs2 := b.violations with input as stale
	_has_id(vs2, "4.2.1")
	_has_id(vs2, "4.2.4")
	# --config given but the file was not collected
	gone := json.patch(green, [{{"op": "remove", "path": "/kubelet/config"}}])
	"4.2.1: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in b.violations with input as gone
}}

test_4_1_11_only_applies_with_a_drop_in_directory if {{
	ops := [{{"op": "remove", "path": "/kubelet/flags/config-dir"}}, {{"op": "remove", "path": "/files/kubelet_config_dir"}}]
	not _has_id(b.violations, "4.1.11") with input as _patched(ops)
	_has_id(b.violations, "4.1.11") with input as _patched([{{"op": "add", "path": "/files/kubelet_config_dir/0/mode", "value": "0775"}}])
	_has_id(b.violations, "4.1.11") with input as _patched([{{"op": "add", "path": "/files/kubelet_config_dir/1/owner", "value": "kube"}}])
}}

test_kube_proxy_not_running_or_bound_elsewhere if {{
	off := json.patch(green, [{{"op": "add", "path": "/kube_proxy", "value": {{"running": false}}}}, {{"op": "remove", "path": "/files/kube_proxy_kubeconfig"}}])
	vs := b.violations with input as off
	count(vs) == 0
	_has_id(b.violations, "4.3.1") with input as _patched([{{"op": "add", "path": "/kube_proxy/flags/metrics-bind-address", "value": "0.0.0.0:10249"}}])
	not _has_id(b.violations, "4.3.1") with input as _patched([{{"op": "add", "path": "/kube_proxy/flags/metrics-bind-address", "value": "[::1]:10249"}}])
	not _has_id(b.violations, "4.3.1") with input as _patched([{{"op": "remove", "path": "/kube_proxy/config/metricsBindAddress"}}])
}}

test_violation_messages_start_with_an_in_scope_id if {{
	vs := b.violations with input as {{}}
	every v in vs {{ split(v, ":")[0] in object.keys(b.recommendations) }}
}}

{emit_tests("cis_kubernetes", C, WB, GREEN, "/attest")}'''
open(f"{OUT}/tests/test_cis_kubernetes_controls.rego", "w").write(TESTS)

print("ok", N, "automated", EXPECT["Automated"], "manual", EXPECT["Manual"], "fact", N - len(attest_ids),
      "fact-manual", len(fact_manual), "attest", len(attest_ids), "profiles", NP)
