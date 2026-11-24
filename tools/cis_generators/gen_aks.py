"""CIS AKS benchmarks -> benchmarks/cis/aks (v2.1.0) and benchmarks/cis/aks_automatic (Automatic v1.0.0).

    /usr/bin/python3 tools/cis_generators/dump_workbook.py <workbook.xlsx> wb.json
    /usr/bin/python3 tools/cis_generators/gen_aks.py aks wb.json benchmarks/cis/aks
    /usr/bin/python3 tools/cis_generators/gen_aks.py automatic wb.json benchmarks/cis/aks_automatic
    opa fmt -w <module dir>

One logic table serves both benchmarks. Each check has a canonical key; a per-benchmark id map says which
recommendation id carries it (the two workbooks number a few checks differently: HTTPS is 5.4.5 on AKS and 5.4.4
on Automatic, Entra authorization is 5.5.2 and 5.5.1). Ids, Automated/Manual status and the Level 1 / Level 2
profile come from the workbook; the run aborts on any count, id, status, profile or title-keyword mismatch.
Titles are our own wording (neutralize_title); the workbook title is only used for the keyword check.

Node facts reuse the Kubernetes module's contract (kubelet.flags, kubelet.config, files.<group>), cluster facts
are the `az aks show` object under input.aks.cluster, and the cluster queries reuse the Kubernetes module's
service_accounts / network_policies / secrets / cluster.namespace_resources / collection_status paths.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cis_genlib import emit_control, emit_tests, load_workbook_json, table  # noqa: E402
from neutralize import neutralize_title  # noqa: E402

VARIANT, SRC, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
CFG = {
    "aks": {"key": "cis_aks", "bench": "CIS Azure Kubernetes Service (AKS) Benchmark v2.1.0", "version": "v2.1.0",
            "nodes": True, "expect": {"total": 50, "Automated": 25, "Manual": 25, "Level 1": 38, "Level 2": 12}},
    "automatic": {"key": "cis_aks_automatic",
                  "bench": "CIS Azure Kubernetes Service Automatic (AKS Automatic) Benchmark v1.0.0", "version": "v1.0.0",
                  "nodes": False, "expect": {"total": 33, "Automated": 12, "Manual": 21, "Level 1": 25, "Level 2": 8}},
}[VARIANT]
KEY, BENCH, VERSION, NODES, EXPECT = CFG["key"], CFG["bench"], CFG["version"], CFG["nodes"], CFG["expect"]

# canonical check key -> id, per benchmark
IDS_AKS = {
    "diag_logs": "2.1.1", "kc_mode": "3.1.1", "kc_owner": "3.1.2", "az_mode": "3.1.3", "az_owner": "3.1.4",
    "anon": "3.2.1", "authz": "3.2.2", "clientca": "3.2.3", "ro_port": "3.2.4", "iptables": "3.2.5",
    "eventqps": "3.2.6", "rotate_cert": "3.2.7", "rotate_server": "3.2.8",
    "cluster_admin": "4.1.1", "secrets_rbac": "4.1.2", "wildcards": "4.1.3", "create_pods": "4.1.4",
    "default_sa": "4.1.5", "token_mounts": "4.1.6", "bind_impersonate": "4.1.7", "create_pv": "4.1.8",
    "node_proxy": "4.1.9", "csr_approval": "4.1.10", "webhooks": "4.1.11", "sa_token_create": "4.1.12",
    "psa_priv": "4.2.1", "psa_pid": "4.2.2", "psa_ipc": "4.2.3", "psa_net": "4.2.4", "psa_ape": "4.2.5",
    "overlay": "4.3.1", "netpol_ns": "4.3.2", "secret_env": "4.4.1", "ext_secrets": "4.4.2",
    "ns_boundaries": "4.5.1", "sec_context": "4.5.2", "default_ns": "4.5.3",
    "scan": "5.1.1", "acr_scope": "5.1.2", "acr_pull": "5.1.3", "registries": "5.1.4", "sa_dedicated": "5.2.1",
    "kms": "5.3.1", "endpoint": "5.4.1", "private_cluster": "5.4.2", "private_nodes": "5.4.3",
    "netpolicy": "5.4.4", "https": "5.4.5", "entra_rbac": "5.5.1", "entra_authz": "5.5.2",
}
IDS_AUTO = {k: v for k, v in IDS_AKS.items() if k in {
    "cluster_admin", "secrets_rbac", "wildcards", "create_pods", "default_sa", "token_mounts", "bind_impersonate",
    "create_pv", "node_proxy", "csr_approval", "webhooks", "sa_token_create", "psa_priv", "psa_pid", "psa_ipc",
    "psa_net", "psa_ape", "secret_env", "ext_secrets", "ns_boundaries", "sec_context", "default_ns", "scan",
    "acr_scope", "acr_pull", "registries", "sa_dedicated", "kms", "endpoint", "private_cluster", "private_nodes"}}
IDS_AUTO.update({"https": "5.4.4", "entra_authz": "5.5.1"})
IDS = IDS_AKS if VARIANT == "aks" else IDS_AUTO


def idkey(i):
    return [int(p) for p in i.split(".")]


WB = load_workbook_json(SRC)
for rid, w in WB.items():
    w["wb_title"] = w["title"].lower()
    if w["assessment"] not in ("Automated", "Manual"):
        sys.exit(f"ABORT: {rid} has status {w['assessment']!r}")
    if w["profiles"] not in (["Level 1"], ["Level 2"]):
        sys.exit(f"ABORT: {rid} is on profiles {w['profiles']}, expected exactly Level 1 or Level 2")


def add(path, value):
    return [{"op": "add", "path": path, "value": value}]


def rm(path):
    return [{"op": "remove", "path": path}]


def fact(key, kw, title, ev, label, oks, fail, miss):
    return {"key": key, "kw": kw, "title": title, "kind": "fact", "ev": ev, "label": label, "ok": oks,
            "fail": fail, "miss": miss}


def att(key, kw, title, attest):
    return {"key": key, "kw": kw, "title": title, "kind": "attest", "attest": attest, "attest_root": "input"}


def gmode(key, kw, title, group, mx):
    return fact(key, kw, title, [f'count(_files("{group}")) > 0'], f"files.{group}",
                [[f'every f in _files("{group}") {{ mode_within(f.mode, "{mx}") }}']],
                add(f"/files/{group}/0/mode", "0666"), rm(f"/files/{group}"))


def gown(key, kw, title, group):
    return fact(key, kw, title, [f'count(_files("{group}")) > 0'], f"files.{group}",
                [[f'every f in _files("{group}") {{ _owned(f, "root", "root") }}']],
                add(f"/files/{group}/0/group", "wheel"), rm(f"/files/{group}"))


KL_LABEL = "kubelet.flags (and kubelet.config when --config is set)"


def kubelet(key, kw, title, oks, fail):
    return fact(key, kw, title, ["_kubelet_collected"], KL_LABEL, oks, fail, rm("/kubelet/flags"))


def kflag(name, value):
    return add(f"/kubelet/flags/{name}", value)


def kcfg(path, value):
    return add(f"/kubelet/config/{path}", value)


CL = "aks.cluster"


def cluster(key, kw, title, ev, label, oks, fail, miss):
    return fact(key, kw, title, ev, label, oks, fail, miss)


def psa(key, kw, title, lst, item):
    return fact(key, kw, title,
                [f"is_array(input.pod_security.{lst})", "is_array(input.pod_security.namespaces_without_enforcement)",
                 'input.collection_status.pod_security == "ok"'],
                f"pod_security.{lst} / pod_security.namespaces_without_enforcement / collection_status.pod_security",
                [[f"count(input.pod_security.{lst}) == 0", "count(input.pod_security.namespaces_without_enforcement) == 0"]],
                add(f"/pod_security/{lst}/-", item), rm("/collection_status/pod_security"))


API_EV = ['_cluster_has("apiServerAccessProfile")']
API_LABEL = "aks.cluster.apiServerAccessProfile"
NET_EV = ["is_object(_cluster.networkProfile)"]
NET_LABEL = "aks.cluster.networkProfile"
POLICY_ENGINES = '{"azure", "calico", "cilium"}'

C = [
    att("diag_logs", "diagnostic", "control plane resource logs must be routed to a destination and reviewed against monitoring needs", "control_plane_logs_routed"),
]
if NODES:
    C += [
        gmode("kc_mode", "kubeconfig file permissions", "kubelet kubeconfig mode must be 644 or stricter", "kubelet_kubeconfig", "644"),
        gown("kc_owner", "kubelet kubeconfig file ownership", "kubelet kubeconfig must be owned by root:root", "kubelet_kubeconfig"),
        gmode("az_mode", "azure.json file has permissions", "azure.json mode must be 644 or stricter", "azure_json", "644"),
        gown("az_owner", "azure.json file ownership", "azure.json must be owned by root:root", "azure_json"),
        kubelet("anon", "--anonymous-auth", "kubelet anonymous authentication must be off (--anonymous-auth or authentication.anonymous.enabled)",
                [['_flag_false("kubelet", "anonymous-auth")'],
                 ['_unset("kubelet", "anonymous-auth")', '_kcv(["authentication", "anonymous", "enabled"]) == false']],
                kcfg("authentication/anonymous/enabled", True)),
        kubelet("authz", "alwaysallow", "kubelet authorization mode must be given and must not be AlwaysAllow (--authorization-mode or authorization.mode)",
                [['_nonempty_flag("kubelet", "authorization-mode")', '_fl("kubelet", "authorization-mode") != "AlwaysAllow"'],
                 ['_unset("kubelet", "authorization-mode")', '_nonempty(_kcv(["authorization", "mode"]))',
                  '_kcv(["authorization", "mode"]) != "AlwaysAllow"']],
                kflag("authorization-mode", "AlwaysAllow")),
        kubelet("clientca", "--client-ca-file", "kubelet client CA file must be given (--client-ca-file or authentication.x509.clientCAFile)",
                [['_nonempty_flag("kubelet", "client-ca-file")'],
                 ['_unset("kubelet", "client-ca-file")', '_nonempty(_kcv(["authentication", "x509", "clientCAFile"]))']],
                kcfg("authentication/x509/clientCAFile", "")),
        kubelet("ro_port", "--read-only-port", "kubelet read-only port must be 0 (--read-only-port, or readOnlyPort in the configuration file)",
                [['_num_flag("kubelet", "read-only-port") == 0'],
                 ['_unset("kubelet", "read-only-port")', "_kubelet_config_in_use", 'object.get(_kc, "readOnlyPort", 0) == 0']],
                kcfg("readOnlyPort", 10255)),
        kubelet("iptables", "--make-iptables-util-chains", "kubelet iptables utility chains must stay on (--make-iptables-util-chains, makeIPTablesUtilChains)",
                [['_flag_true("kubelet", "make-iptables-util-chains")'],
                 ['_unset("kubelet", "make-iptables-util-chains")', '_kcv(["makeIPTablesUtilChains"]) in {null, true}']],
                kcfg("makeIPTablesUtilChains", False)),
        kubelet("eventqps", "eventrecordqps", "kubelet event record rate must be set to a non-negative number (--event-qps or eventRecordQPS)",
                [['_num_flag("kubelet", "event-qps") >= 0'],
                 ['_unset("kubelet", "event-qps")', 'is_number(_kcv(["eventRecordQPS"]))', '_kcv(["eventRecordQPS"]) >= 0']],
                kcfg("eventRecordQPS", -1)),
        kubelet("rotate_cert", "rotatecertificates", "kubelet client certificate rotation must not be switched off (--rotate-certificates, rotateCertificates)",
                [['_flag_true("kubelet", "rotate-certificates")'],
                 ['_unset("kubelet", "rotate-certificates")', '_kcv(["rotateCertificates"]) in {null, true}']],
                kflag("rotate-certificates", "false")),
        kubelet("rotate_server", "rotatekubeletservercertificate", "kubelet serving certificate rotation must be on (serverTLSBootstrap, --rotate-server-certificates or the RotateKubeletServerCertificate gate)",
                [['_kcv(["serverTLSBootstrap"]) == true'],
                 ['_flag_true("kubelet", "rotate-server-certificates")'],
                 ['_gate_all_true("kubelet", "RotateKubeletServerCertificate")'],
                 ['count(_gate_vals("kubelet", "RotateKubeletServerCertificate")) == 0',
                  '_kcv(["featureGates", "RotateKubeletServerCertificate"]) == true']],
                rm("/kubelet/config/serverTLSBootstrap")),
    ]
C += [
    att("cluster_admin", "cluster-admin", "every cluster-admin binding must be reviewed as needed", "cluster_admin_bindings_reviewed"),
    att("secrets_rbac", "secrets", "get, list and watch rights on Secrets must be reviewed and kept small", "secret_access_reviewed"),
    att("wildcards", "wildcard", "wildcards in Role and ClusterRole rules must be reviewed and kept small", "rbac_wildcards_reviewed"),
    att("create_pods", "create pods", "the right to create Pods must be reviewed and kept small", "pod_create_access_reviewed"),
    fact("default_sa", "default service accounts", "every namespace's default ServiceAccount must have token automount off and no added role bindings",
         ["is_array(input.service_accounts.default)", "count(input.service_accounts.default) > 0",
          'input.collection_status.default_service_accounts == "ok"'],
         "service_accounts.default / collection_status.default_service_accounts",
         [["every sa in input.service_accounts.default { sa.automount_token == false; is_array(sa.role_bindings); count(sa.role_bindings) == 0 }"]],
         add("/service_accounts/default/0/automount_token", True), rm("/service_accounts")),
    fact("token_mounts", "service account tokens", "Pods must not mount a ServiceAccount token without a need for API access or workload identity",
         ["is_array(input.service_accounts.unneeded_token_mounts)", 'input.collection_status.service_account_token_mounts == "ok"'],
         "service_accounts.unneeded_token_mounts / collection_status.service_account_token_mounts",
         [["count(input.service_accounts.unneeded_token_mounts) == 0"]],
         add("/service_accounts/unneeded_token_mounts/-", "payments/web-0"), rm("/collection_status/service_account_token_mounts")),
    att("bind_impersonate", "impersonate", "bind, impersonate and escalate rights must be reviewed and kept small", "bind_impersonate_escalate_reviewed"),
    att("create_pv", "persistent storage", "rights to create PersistentVolumes, claims and StorageClasses must be reviewed and kept small", "persistent_volume_create_access_reviewed"),
    att("node_proxy", "nodes/proxy", "rights on nodes/proxy must be reviewed and kept small", "node_proxy_access_reviewed"),
    att("csr_approval", "approval subresource", "rights on certificatesigningrequests/approval must be reviewed and kept small", "csr_approval_access_reviewed"),
    att("webhooks", "webhook", "rights on validating and mutating webhook configurations must be reviewed and kept small", "webhook_config_access_reviewed"),
    att("sa_token_create", "token creation", "the right to create serviceaccounts/token must be reviewed and kept small", "service_account_token_create_access_reviewed"),
    psa("psa_priv", "privileged", "admission must keep privileged containers out of customer workloads and every namespace must be covered", "privileged_containers", "payments/web-0/app"),
    psa("psa_pid", "process id", "admission must keep hostPID Pods out of customer workloads and every namespace must be covered", "host_pid_pods", "payments/web-0"),
    psa("psa_ipc", "ipc", "admission must keep hostIPC Pods out of customer workloads and every namespace must be covered", "host_ipc_pods", "payments/web-0"),
    psa("psa_net", "network namespace", "admission must keep hostNetwork Pods out of customer workloads and every namespace must be covered", "host_network_pods", "payments/web-0"),
    psa("psa_ape", "allowprivilegeescalation", "admission must keep allowPrivilegeEscalation containers out of customer workloads and every namespace must be covered", "privilege_escalation_containers", "payments/web-0/app"),
]
if NODES:
    C += [
        cluster("overlay", "cni overlay", "the cluster network plugin must be azure in overlay mode", NET_EV, NET_LABEL,
                [['_cluster.networkProfile.networkPlugin == "azure"', '_cluster.networkProfile.networkPluginMode == "overlay"']],
                add("/aks/cluster/networkProfile/networkPluginMode", ""), rm("/aks/cluster/networkProfile")),
        fact("netpol_ns", "networkpolicy", "every namespace must hold a NetworkPolicy and the cluster must run a network policy engine",
             ["is_array(input.network_policies.namespaces_without_policy)", 'input.collection_status.network_policies == "ok"'] + NET_EV,
             "network_policies.namespaces_without_policy / collection_status.network_policies / aks.cluster.networkProfile",
             [["count(input.network_policies.namespaces_without_policy) == 0",
               f"_cluster.networkProfile.networkPolicy in {POLICY_ENGINES}"]],
             add("/network_policies/namespaces_without_policy/-", "payments"), rm("/collection_status/network_policies")),
    ]
C += [
    fact("secret_env", "environment variables", "workloads must not read Secrets through environment variables",
         ["is_number(input.secrets.env_var_usage_count)", 'input.collection_status.secret_env_scan == "ok"'],
         "secrets.env_var_usage_count / collection_status.secret_env_scan",
         [["input.secrets.env_var_usage_count == 0"]], add("/secrets/env_var_usage_count", 3), rm("/secrets")),
    att("ext_secrets", "external secret", "an external secret store must be in use for sensitive values and the decision recorded", "external_secret_storage_reviewed"),
    att("ns_boundaries", "namespaces", "namespaces must be reviewed as the administrative boundaries in use", "namespace_boundaries_reviewed"),
    att("sec_context", "security context", "pod and container security contexts must be reviewed", "pod_security_contexts_reviewed"),
    fact("default_ns", "default namespace", "the default namespace must hold only the built-in kubernetes Service, default ServiceAccount and root CA ConfigMap",
         ['is_array(input.cluster.namespace_resources["default"])', 'input.collection_status.namespace_resources == "ok"'],
         "cluster.namespace_resources.default / collection_status.namespace_resources",
         [['every r in input.cluster.namespace_resources["default"] { r in _default_ns_builtin }']],
         add("/cluster/namespace_resources/default/-", "pod/debug"), rm("/collection_status/namespace_resources")),
    att("scan", "vulnerability scanning", "container image vulnerability scanning must be active and its findings reviewed", "image_vulnerability_scanning_active"),
    att("acr_scope", "minimize and scope access", "access to Azure Container Registry must be identity based and least privilege", "acr_access_scoped"),
    att("acr_pull", "pull images", "the cluster must hold only image pull rights on Azure Container Registry", "acr_cluster_pull_only"),
    att("registries", "approved container registries", "workloads must be limited to approved container registries by policy", "approved_registries_enforced"),
    att("sa_dedicated", "dedicated kubernetes service accounts", "workloads must use dedicated, least-privilege ServiceAccounts", "dedicated_workload_service_accounts"),
    cluster("kms", "kms", "Kubernetes Secrets must be encrypted at rest with AKS KMS (infrastructure encryption or Key Vault KMS)",
            ['_cluster_has("securityProfile")'], "aks.cluster.securityProfile",
            [['_cv(["securityProfile", "kubernetesResourceObjectEncryptionProfile", "infrastructureEncryption"]) == "Enabled"',
              'not _cv_not_boolean(["securityProfile", "azureKeyVaultKms", "enabled"])'],
             ['_cv(["securityProfile", "azureKeyVaultKms", "enabled"]) == true']],
            add("/aks/cluster/securityProfile", {"azureKeyVaultKms": {"enabled": False}}), rm("/aks/cluster/securityProfile")),
    cluster("endpoint", "control plane endpoint", "the API server must be private, or public with a non-wildcard authorized IP range list", API_EV, API_LABEL,
            [['_api_profile.enablePrivateCluster == true'],
             ['object.get(_api_profile, "enablePrivateCluster", false) != true', "count(_authorized_ranges) > 0",
              'not "0.0.0.0/0" in _authorized_ranges']],
            add("/aks/cluster/apiServerAccessProfile", {"enablePrivateCluster": False, "authorizedIpRanges": []}),
            rm("/aks/cluster/apiServerAccessProfile")),
    cluster("private_cluster", "private aks clusters", "the API server must be a private cluster with the public FQDN disabled", API_EV, API_LABEL,
            [['_api_profile.enablePrivateCluster == true', '_api_profile.enablePublicFqdn == false']],
            add("/aks/cluster/apiServerAccessProfile/enablePublicFqdn", True), rm("/aks/cluster/apiServerAccessProfile")),
    cluster("private_nodes", "private nodes", "node pools must not give their nodes public IP addresses",
            ["is_array(_cluster.agentPoolProfiles)", "count(_cluster.agentPoolProfiles) > 0"], "aks.cluster.agentPoolProfiles",
            [['every p in _cluster.agentPoolProfiles { is_object(p); object.get(p, "enableNodePublicIP", null) in {false, null} }']],
            add("/aks/cluster/agentPoolProfiles/0/enableNodePublicIP", True), rm("/aks/cluster/agentPoolProfiles")),
]
if NODES:
    C += [cluster("netpolicy", "network policy", "a network policy engine (azure, calico or cilium) must be enabled", NET_EV, NET_LABEL,
                  [[f"_cluster.networkProfile.networkPolicy in {POLICY_ENGINES}"]],
                  add("/aks/cluster/networkProfile/networkPolicy", "none"), rm("/aks/cluster/networkProfile"))]
C += [att("https", "https", "externally exposed workloads must serve HTTPS with valid certificates", "external_workloads_use_https")]
if NODES:
    C += [cluster("entra_rbac", "kubernetes rbac",
                  "Entra ID managed integration with Kubernetes RBAC must be on and local accounts disabled",
                  ['_cluster_has("aadProfile")', '_cluster_has("enableRbac")'], "aks.cluster.aadProfile / aks.cluster.enableRbac",
                  [['_cv(["aadProfile", "managed"]) == true', '_cv(["enableRbac"]) == true',
                    '_cv(["disableLocalAccounts"]) == true']],
                  add("/aks/cluster/disableLocalAccounts", False), rm("/aks/cluster/aadProfile"))]
C += [cluster("entra_authz", "authorization for the kubernetes api",
              "Entra ID managed integration with Azure RBAC for Kubernetes authorization must be on in the subscription's tenant, with local accounts disabled",
              ['_cluster_has("aadProfile")', "is_string(input.aks.subscription_tenant_id)"],
              "aks.cluster.aadProfile / aks.subscription_tenant_id",
              [['_cv(["aadProfile", "managed"]) == true', '_cv(["aadProfile", "enableAzureRbac"]) == true',
                '_cv(["disableLocalAccounts"]) == true', "_same_tenant"]],
              add("/aks/cluster/aadProfile/enableAzureRbac", False), rm("/aks/cluster/aadProfile"))]

# ── assign ids, cross-check against the workbook ─────────────────────────────────────────────────────
C = [c for c in C if c["key"] in IDS]
if {c["key"] for c in C} != set(IDS):
    sys.exit(f"ABORT: id map keys without logic: {sorted(set(IDS) - {c['key'] for c in C})}")
for c in C:
    c["id"] = IDS[c["key"]]
C.sort(key=lambda c: idkey(c["id"]))
ids = [c["id"] for c in C]
if len(ids) != len(set(ids)):
    sys.exit("ABORT: duplicate id in the logic table")
if set(ids) != set(WB):
    sys.exit(f"ABORT: workbook and logic table differ: only in workbook {sorted(set(WB) - set(ids), key=idkey)}, "
             f"only in table {sorted(set(ids) - set(WB), key=idkey)}")
got = {"total": len(WB), "Automated": sum(w["assessment"] == "Automated" for w in WB.values()),
       "Manual": sum(w["assessment"] == "Manual" for w in WB.values()),
       "Level 1": sum(w["profiles"] == ["Level 1"] for w in WB.values()),
       "Level 2": sum(w["profiles"] == ["Level 2"] for w in WB.values())}
if got != EXPECT:
    sys.exit(f"ABORT: workbook counts {got} differ from the expected {EXPECT}")
BAD_TITLES = []
for c in C:
    w = WB[c["id"]]
    if c["kw"] not in w["wb_title"]:
        sys.exit(f"ABORT: {c['id']} keyword {c['kw']!r} is not in the workbook title; the id may have been renumbered")
    if w["assessment"] == "Automated" and c["kind"] != "fact":
        sys.exit(f"ABORT: {c['id']} is Automated in the workbook but attested here")
    if neutralize_title(c["title"]) != c["title"]:
        BAD_TITLES.append(f"{c['id']}: {neutralize_title(c['title'])!r}")
    w["title"] = c["title"]
if BAD_TITLES:
    sys.exit("ABORT: titles not stable under neutralize_title:\n" + "\n".join(BAD_TITLES))
for w in WB.values():
    del w["wb_title"]

SECTIONS = {"2": ("logging", "Logging and monitoring"), "3": ("worker_nodes", "Worker nodes"),
            "4": ("policies", "Policies"), "5": ("managed_service", "Managed service configuration")}
SECTIONS = {n: v for n, v in SECTIONS.items() if any(i.startswith(n + ".") for i in ids)}


def section(cid):
    return SECTIONS[cid.split(".")[0]][0]


def f(path, mode, owner="root"):
    return {"path": path, "mode": mode, "owner": owner, "group": owner}


GREEN = {}
if NODES:
    GREEN["kubelet"] = {
        "flags": {"config": "/etc/default/kubeletconfig.json", "kubeconfig": "/var/lib/kubelet/kubeconfig"},
        "config": {"authentication": {"anonymous": {"enabled": False}, "x509": {"clientCAFile": "/etc/kubernetes/certs/ca.crt"}},
                   "authorization": {"mode": "Webhook"}, "readOnlyPort": 0, "makeIPTablesUtilChains": True,
                   "eventRecordQPS": 50, "rotateCertificates": True, "serverTLSBootstrap": True}}
    GREEN["files"] = {"kubelet_kubeconfig": [f("/var/lib/kubelet/kubeconfig", "0600")],
                      "azure_json": [f("/etc/kubernetes/azure.json", "0644")]}
cluster_green = {
    "name": "aks-prod", "enableRbac": True,
    "apiServerAccessProfile": {"enablePrivateCluster": True, "enablePublicFqdn": False, "authorizedIpRanges": None},
    "agentPoolProfiles": [{"name": "system", "mode": "System", "enableNodePublicIP": False},
                          {"name": "user", "mode": "User", "enableNodePublicIP": None}],
    "securityProfile": {"kubernetesResourceObjectEncryptionProfile": {"infrastructureEncryption": "Enabled"},
                        "azureKeyVaultKms": {"enabled": True}},
    "aadProfile": {"managed": True, "enableAzureRbac": True, "tenantId": "11111111-2222-3333-4444-555555555555"},
    "disableLocalAccounts": True,
    "networkProfile": {"networkPlugin": "azure", "networkPluginMode": "overlay", "networkPolicy": "cilium", "networkDataplane": "cilium"},
}
GREEN["aks"] = {"cluster": cluster_green, "subscription_tenant_id": "11111111-2222-3333-4444-555555555555"}
GREEN["pod_security"] = {"privileged_containers": [], "host_pid_pods": [], "host_ipc_pods": [], "host_network_pods": [],
                         "privilege_escalation_containers": [], "namespaces_without_enforcement": []}
GREEN["service_accounts"] = {"default": [{"namespace": "default", "automount_token": False, "role_bindings": []},
                                         {"namespace": "kube-system", "automount_token": False, "role_bindings": []}],
                             "unneeded_token_mounts": []}
if NODES:
    GREEN["network_policies"] = {"namespaces_without_policy": []}
GREEN["secrets"] = {"env_var_usage_count": 0}
GREEN["cluster"] = {"namespace_resources": {"default": ["service/kubernetes", "serviceaccount/default", "configmap/kube-root-ca.crt"]}}
GREEN["collection_status"] = {"default_service_accounts": "ok", "service_account_token_mounts": "ok", "secret_env_scan": "ok",
                              "namespace_resources": "ok", "pod_security": "ok"}
if NODES:
    GREEN["collection_status"]["network_policies"] = "ok"
GREEN["attest"] = {c["attest"]: True for c in C if c["kind"] == "attest"}

fact_manual = [c["id"] for c in C if c["kind"] == "fact" and WB[c["id"]]["assessment"] == "Manual"]
attest_ids = [c["id"] for c in C if c["kind"] == "attest"]
N = len(C)
L1, L2 = EXPECT["Level 1"], EXPECT["Level 2"]


def wrap(idlist, width=112):
    out, line = [], "#   "
    for i in idlist:
        if len(line) + len(i) + 2 > width:
            out.append(line.rstrip())
            line = "#   "
        line += i + ", "
    out.append(line.rstrip().rstrip(","))
    return "\n".join(out)


def meta(title, density, basis):
    return f'''# METADATA
# title: "{title}"
# custom:
#   class: security
#   framework: {KEY}
#   source: cis
#   domains: [kubernetes, cloud, azure]
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


NODE_FACTS = '''#   kubelet.flags / kubelet.config   : the Kubernetes module's contract (benchmarks/cis/kubernetes): kubelet command-line
#                                      flags, and the effective KubeletConfiguration (configz) read only when the flags
#                                      hold --config; a flag overrides the file. Collected per node.
#   files.kubelet_kubeconfig[]       : {path, mode, owner, group}; mode is an octal STRING compared with bit masks
#   files.azure_json[]               : NEW the node's azure.json entry, same shape
''' if NODES else ""
NODE_ATT = ""
HEADER = meta(BENCH, "sized", "size") + f'''package {KEY}

# {BENCH}. Generated by tools/cis_generators/gen_aks.py from the CIS workbook: do not edit by hand, regenerate.
{"# Replaces the v1.8.0-labelled module that lived in this directory." if VARIANT == "aks" else ""}
# {N} recommendations, every one in the benchmark ({EXPECT["Automated"]} Automated, {EXPECT["Manual"]} Manual); ids, status and profile
# are read from the workbook. `recommendations` lists each id with its level, status and profile.
# - {N - len(attest_ids)} are decided from collected facts and fail closed: facts not collected =>
#   "<id>: evidence missing — <field> not collected".
# - {len(fact_manual)} of those are Manual in the workbook but their audit is a configuration comparison, so they are
#   checked like Automated ones:
{wrap(fact_manual)}
# - {len(attest_ids)} need a human judgement and read an attestation boolean under input.attest (not attested => violation):
{wrap(attest_ids)}
#
# Profiles: Level 1 ({L1}) and Level 2 ({L2}); input.cis_profile.level selects (1 | 2, default 2; Level 2 includes
# Level 1). A recommendation outside the selection raises nothing and is not counted in total_controls.
#
# Input contract (NEW marks the paths this module introduces):
#   aks.cluster                      : NEW the `az aks show` object, ARM field names (apiServerAccessProfile, agentPoolProfiles,
#                                      networkProfile, securityProfile, aadProfile{', enableRbac' if NODES else ''}, disableLocalAccounts)
#   aks.subscription_tenant_id       : NEW the Entra tenant of the subscription holding the cluster
{NODE_FACTS}#   pod_security.<list>[]            : NEW customer workload offenders, "namespace/pod[/container]" strings, AKS-managed system
#                                      namespaces excluded: privileged_containers, host_pid_pods, host_ipc_pods,
#                                      host_network_pods, privilege_escalation_containers
#   pod_security.namespaces_without_enforcement[] : NEW namespaces with no enforcing Pod Security Admission label, Azure
#                                      Policy or Deployment Safeguards control
#   service_accounts.default[]       : {{namespace, automount_token, role_bindings[]}} per namespace default ServiceAccount
#   service_accounts.unneeded_token_mounts[] : NEW "namespace/pod" entries mounting a token without API or workload-identity need
{"#   network_policies.namespaces_without_policy[] : namespaces holding no NetworkPolicy" if NODES else ""}
#   secrets.env_var_usage_count      : secretKeyRef and envFrom.secretRef uses in workloads
#   cluster.namespace_resources.default : names of the objects in the default namespace ("service/kubernetes")
#   collection_status.<query>        : "ok" when the query ran to completion: default_service_accounts, secret_env_scan,
#                                      namespace_resources{", network_policies" if NODES else ""}, and NEW service_account_token_mounts, pod_security
#   attest.<key>                     : attestation booleans

import rego.v1

default compliant := false

compliant if {{
	count(in_scope) > 0
	count(violations) == 0
}}

violations := sort([m | some m in _all_violations])

'''

HELPERS = '''# ── profile ──────────────────────────────────────────────────────────────────
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

# ── cluster (az aks show) ────────────────────────────────────────────────────
_cluster := c if {
	c := object.get(input, ["aks", "cluster"], null)
	is_object(c)
	count(c) > 0
}

_cluster_has(k) if k in object.keys(_cluster)

# a cluster value, null when absent
_cv(path) := object.get(_cluster, path, null)

# A boolean cluster setting sent as a string or a number is a collection error: the recommendation that reads it
# is not met, whatever else holds. An unset (null or absent) setting is not this error.
_cv_not_boolean(path) if {
	v := _cv(path)
	not is_null(v)
	not is_boolean(v)
}

# an unset (null) apiServerAccessProfile is a public cluster with no restriction
_api_profile := p if {
	p := object.get(_cluster, "apiServerAccessProfile", null)
	is_object(p)
}

_api_profile := {} if {
	_cluster_has("apiServerAccessProfile")
	object.get(_cluster, "apiServerAccessProfile", null) == null
}

default _authorized_ranges := set()

_authorized_ranges := {trim_space(r) | some r in _api_profile.authorizedIpRanges; is_string(r)} if is_array(_api_profile.authorizedIpRanges)

_same_tenant if {
	a := _cv(["aadProfile", "tenantId"])
	b := input.aks.subscription_tenant_id
	is_string(a)
	is_string(b)
	trim_space(b) != ""
	lower(trim_space(a)) == lower(trim_space(b))
}

_default_ns_builtin := {"service/kubernetes", "serviceaccount/default", "configmap/kube-root-ca.crt"}

# a collected, non-empty file list (an empty list proves nothing)
_files(g) := fs if {
	fs := object.get(input, ["files", g], null)
	is_array(fs)
	count(fs) > 0
}

_owned(x, owner, group) if {
	x.owner == owner
	x.group == group
}

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

'''

KUBELET_HELPERS = '''# ── kubelet (the Kubernetes module's helpers) ────────────────────────────────
# Flag names are normalised ("--a_b", "a-b" and "a_b" are one flag). A flag is read only when exactly one key
# normalises to its name and its value is a string; anything else is ambiguous: neither set nor unset.
_norm(k) := replace(trim_suffix(trim_left(k, "-"), "+"), "_", "-")

_flags(c) := fl if {
	fl := object.get(input, [c, "flags"], null)
	is_object(fl)
}

_keys(c, name) := [k | some k, _ in _flags(c); _norm(k) == name]

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

_bool(v) := "true" if lower(trim_space(v)) in {"1", "t", "true"}

_bool(v) := "false" if lower(trim_space(v)) in {"0", "f", "false"}

_flag_true(c, name) if _bool(_fl(c, name)) == "true"

_flag_false(c, name) if _bool(_fl(c, name)) == "false"

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

_gate_all_true(c, name) if {
	vals := _gate_vals(c, name)
	count(vals) > 0
	every v in vals { v == "true" }
}

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

'''

parts = [HEADER]
for num, (name, label) in SECTIONS.items():
    parts.append(f"# Section {num}: {label}\n{name}_violations := sort([m | some m in _v_{name}])\n\n"
                 f"_all_violations contains m if some m in _v_{name}\n")
parts.append(HELPERS)
if NODES:
    parts.append(KUBELET_HELPERS)
for c in C:
    if c["kind"] == "fact" and not c["ok"]:
        sys.exit(f"ABORT: {c['id']} has no pass predicate")
    parts.append(emit_control(dict(c), WB, f"_v_{section(c['id'])}", applies=True))

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
	"framework": "{KEY}",
	"benchmark": "{BENCH}",
	"version": "{VERSION}",
	"profile": {{"level": level}},
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
GEN_MARK = "Generated by tools/cis_generators/gen_aks.py"
open(f"{OUT}/{KEY}.rego", "w").write("\n".join(parts))

MAIN = meta(f"{BENCH} - compliance_report entrypoint", "orchestrator", "role") + f'''package {KEY}.main

# OPA query path: /v1/data/{KEY.replace("_", "_")}/main/compliance_report (the framework key's entrypoint).
# Thin alias of data.{KEY}, which already fails closed per recommendation: every check whose facts were
# not collected is a violation, so empty input fails every recommendation in scope. {GEN_MARK}.

import data.{KEY} as bench
import rego.v1

default _facts_supplied := false

_facts_supplied if count(object.keys(input)) > 0

compliant := bench.compliant

violations := _report_violations

# With no facts at all the report says so explicitly, so an empty assessment can never read as a result. The
# notice is a finding, not a control: total_controls and failed_controls count recommendations only.
_no_facts_msg := sprintf(
	"FAIL-CLOSED: no facts supplied for %s — the assessment could not be evaluated. This is NOT a passing result; check that fact collection ran and produced input.",
	["{KEY}"],
)

_report_violations := array.concat(bench.violations, [_no_facts_msg]) if not _facts_supplied

_report_violations := bench.violations if _facts_supplied

compliance_report := object.union(bench.compliance_report, {{
	"facts_supplied": _facts_supplied,
	"violation_count": count(_report_violations),
	"violations": _report_violations,
}})
'''
open(f"{OUT}/{KEY}_main.rego", "w").write(MAIN)


def idof(key):
    return IDS.get(key)


T_HEAD = '''package __KEY___test

import rego.v1

import data.__KEY__ as b
import data.__KEY__.main as bridge

# Generated per-recommendation tests for __BENCH__: every recommendation has a pass test (green input) and a
# fail test; fact-based checks also have an evidence-missing test; attestations fail when false or absent.
# Profile, report-contract and check-specific tests come first. __GEN__.

green := __GREEN__

_has_id(vs, id) if {
	some v in vs
	startswith(v, concat("", [id, ":"]))
}

_patched(ops) := json.patch(green, ops)

test_green_input_is_compliant if {
	vs := b.violations with input as green
	count(vs) == 0
	b.compliant with input as green
	r := bridge.compliance_report with input as green
	r.compliant == true
	r.failed_controls == 0
	r.passed_controls == __N__
	r.compliance_percentage == 100
}

test_recommendation_count_matches_workbook if {
	count(b.recommendations) == __N__
	count([id | some id, r in b.recommendations; r.assessment == "Automated"]) == __AUTO__
	count([id | some id, r in b.recommendations; r.assessment == "Manual"]) == __MAN__
	count([id | some id, r in b.recommendations; r.profiles == ["Level 1"]]) == __L1__
	count([id | some id, r in b.recommendations; r.profiles == ["Level 2"]]) == __L2__
	count([id | some id, r in b.recommendations; r.check == "attestation"]) == __NATT__
}

test_report_contract_on_empty_input if {
	r := bridge.compliance_report with input as {}
	r.compliant == false
	r.total_controls == __N__
	r.failed_controls == __N__
	r.passed_controls == 0
	r.compliance_percentage == 0
	r.facts_supplied == false
	is_array(r.violations)
	r.violation_count == count(r.violations)
	r.level_1.total == __L1__
	r.level_2.total == __L2__
	r.version == "__VERSION__"
}

# One test per profile, each with a literal input: a helper that evaluates the report `with input as` its own
# parameter cannot be compiled by `opa build -t wasm`.

test_profile_total_l1 if {
	r := bridge.compliance_report with input as {"cis_profile": {"level": 1}}
	r.total_controls == __L1__
	r.failed_controls == __L1__
}

test_profile_total_l2 if {
	r := bridge.compliance_report with input as {"cis_profile": {"level": 2}}
	r.total_controls == __N__
}

test_profile_total_unknown_level if {
	r := bridge.compliance_report with input as {"cis_profile": {"level": 3}}
	r.total_controls == __N__
}

test_level_1_scope_leaves_level_2_alone if {
	inp := {"cis_profile": {"level": 1}}
	vs := b.violations with input as inp
	l2_ids := {id | some id, r in b.recommendations; r.level == 2}
	every id in l2_ids { not _has_id(vs, id) }
}

test_section_results_partition_the_scope if {
	r := b.compliance_report with input as {}
	sum([s.total | some _, s in r.section_results]) == r.total_controls
	sum([s.failed | some _, s in r.section_results]) == r.failed_controls
}

test_violation_messages_start_with_an_in_scope_id if {
	vs := b.violations with input as {}
	every v in vs { split(v, ":")[0] in object.keys(b.recommendations) }
}

# file modes are octal bit masks: 0464 is numerically below 0644 but grants group write
test_mode_is_a_bit_mask if {
	b.mode_within("0644", "644")
	b.mode_within("400", "644")
	b.mode_within("0o640", "644")
	not b.mode_within("0664", "644")
	not b.mode_within("0645", "644")
	not b.mode_within("4644", "644")
	not b.mode_within(644, "644")
	not b.mode_within("rw-r--r--", "644")
	not b.mode_within("", "644")
}

'''

T_SHARED = '''# 5.4.1 / private cluster
test_endpointpublic_cluster_needs_authorized_ranges if {
	pub := [{"op": "add", "path": "/aks/cluster/apiServerAccessProfile", "value": {"enablePrivateCluster": false}}]
	_has_id(b.violations, "__ID_ENDPOINT__") with input as _patched(pub)
	ranges := [{"op": "add", "path": "/aks/cluster/apiServerAccessProfile", "value": {"enablePrivateCluster": false, "authorizedIpRanges": ["203.0.113.0/24"]}}]
	not _has_id(b.violations, "__ID_ENDPOINT__") with input as _patched(ranges)
	wide := [{"op": "add", "path": "/aks/cluster/apiServerAccessProfile", "value": {"enablePrivateCluster": false, "authorizedIpRanges": ["203.0.113.0/24", "0.0.0.0/0"]}}]
	_has_id(b.violations, "__ID_ENDPOINT__") with input as _patched(wide)
	unset := [{"op": "add", "path": "/aks/cluster/apiServerAccessProfile", "value": null}]
	_has_id(b.violations, "__ID_ENDPOINT__") with input as _patched(unset)
	not "__ID_ENDPOINT__: evidence missing — aks.cluster.apiServerAccessProfile not collected" in b.violations with input as _patched(unset)
}

test_privateprivate_cluster_needs_the_public_fqdn_off if {
	fqdn := [{"op": "add", "path": "/aks/cluster/apiServerAccessProfile/enablePublicFqdn", "value": true}]
	_has_id(b.violations, "__ID_PRIVATE__") with input as _patched(fqdn)
	absent := [{"op": "remove", "path": "/aks/cluster/apiServerAccessProfile/enablePublicFqdn"}]
	_has_id(b.violations, "__ID_PRIVATE__") with input as _patched(absent)
	public := [{"op": "add", "path": "/aks/cluster/apiServerAccessProfile", "value": {"enablePrivateCluster": false, "enablePublicFqdn": false}}]
	_has_id(b.violations, "__ID_PRIVATE__") with input as _patched(public)
}

test_nodesabsent_public_ip_setting_is_private if {
	absent := [{"op": "remove", "path": "/aks/cluster/agentPoolProfiles/0/enableNodePublicIP"}]
	not _has_id(b.violations, "__ID_NODES__") with input as _patched(absent)
	late := [{"op": "add", "path": "/aks/cluster/agentPoolProfiles/1/enableNodePublicIP", "value": true}]
	_has_id(b.violations, "__ID_NODES__") with input as _patched(late)
	empty := [{"op": "add", "path": "/aks/cluster/agentPoolProfiles", "value": []}]
	_has_id(b.violations, "__ID_NODES__") with input as _patched(empty)
}

test_kmskms_either_experience if {
	legacy := [{"op": "add", "path": "/aks/cluster/securityProfile", "value": {"azureKeyVaultKms": {"enabled": true}}}]
	not _has_id(b.violations, "__ID_KMS__") with input as _patched(legacy)
	current := [{"op": "add", "path": "/aks/cluster/securityProfile", "value": {"kubernetesResourceObjectEncryptionProfile": {"infrastructureEncryption": "Enabled"}}}]
	not _has_id(b.violations, "__ID_KMS__") with input as _patched(current)
	off := [{"op": "add", "path": "/aks/cluster/securityProfile", "value": null}]
	_has_id(b.violations, "__ID_KMS__") with input as _patched(off)
}

test_authzentra_authorization if {
	_has_id(b.violations, "__ID_AUTHZ__") with input as _patched([{"op": "add", "path": "/aks/cluster/disableLocalAccounts", "value": false}])
	_has_id(b.violations, "__ID_AUTHZ__") with input as _patched([{"op": "add", "path": "/aks/cluster/aadProfile/managed", "value": false}])
	_has_id(b.violations, "__ID_AUTHZ__") with input as _patched([{"op": "add", "path": "/aks/subscription_tenant_id", "value": "99999999-2222-3333-4444-555555555555"}])
	not _has_id(b.violations, "__ID_AUTHZ__") with input as _patched([{"op": "add", "path": "/aks/subscription_tenant_id", "value": " 11111111-2222-3333-4444-555555555555 "}])
	_has_id(b.violations, "__ID_AUTHZ__") with input as _patched([{"op": "add", "path": "/aks/cluster/aadProfile", "value": null}])
}

test_admission_checks_need_namespace_coverage if {
	ops := [{"op": "add", "path": "/pod_security/namespaces_without_enforcement", "value": ["payments"]}]
	vs := b.violations with input as _patched(ops)
	every id in {"__ID_P1__", "__ID_P2__", "__ID_P3__", "__ID_P4__", "__ID_P5__"} { _has_id(vs, id) }
}

test_default_namespace_builtins_pass_other_objects_fail if {
	ok := [{"op": "add", "path": "/cluster/namespace_resources/default", "value": ["service/kubernetes"]}]
	not _has_id(b.violations, "__ID_DNS__") with input as _patched(ok)
	bad := [{"op": "add", "path": "/cluster/namespace_resources/default/-", "value": "secret/db"}]
	_has_id(b.violations, "__ID_DNS__") with input as _patched(bad)
}

'''
T_NODES = '''test_network_policy_engine_values if {
	none := [{"op": "add", "path": "/aks/cluster/networkProfile/networkPolicy", "value": "none"}]
	vs := b.violations with input as _patched(none)
	_has_id(vs, "__ID_NP__")
	_has_id(vs, "__ID_NPNS__")
	unset := [{"op": "add", "path": "/aks/cluster/networkProfile/networkPolicy", "value": null}]
	_has_id(b.violations, "__ID_NP__") with input as _patched(unset)
	azure := [{"op": "add", "path": "/aks/cluster/networkProfile/networkPolicy", "value": "azure"}]
	not _has_id(b.violations, "__ID_NP__") with input as _patched(azure)
}

test_overlay_needs_azure_plugin_in_overlay_mode if {
	kubenet := [{"op": "add", "path": "/aks/cluster/networkProfile/networkPlugin", "value": "kubenet"}]
	_has_id(b.violations, "__ID_OV__") with input as _patched(kubenet)
}

test_entra_rbac_model_checks if {
	not _has_id(b.violations, "__ID_ER__") with input as _patched([{"op": "add", "path": "/aks/cluster/aadProfile/enableAzureRbac", "value": false}])
	_has_id(b.violations, "__ID_ER__") with input as _patched([{"op": "add", "path": "/aks/cluster/aadProfile/managed", "value": false}])
	_has_id(b.violations, "__ID_ER__") with input as _patched([{"op": "add", "path": "/aks/cluster/enableRbac", "value": false}])
}

test_kubelet_flags_override_the_config_file if {
	_has_id(b.violations, "__ID_ANON__") with input as _patched([{"op": "add", "path": "/kubelet/flags/anonymous-auth", "value": "true"}])
	_has_id(b.violations, "__ID_RO__") with input as _patched([{"op": "add", "path": "/kubelet/flags/read-only-port", "value": "10255"}])
	not _has_id(b.violations, "__ID_RO__") with input as _patched([{"op": "remove", "path": "/kubelet/config/readOnlyPort"}])
	_has_id(b.violations, "__ID_QPS__") with input as _patched([{"op": "add", "path": "/kubelet/flags/event-qps", "value": "-1"}])
	not _has_id(b.violations, "__ID_QPS__") with input as _patched([{"op": "add", "path": "/kubelet/flags/event-qps", "value": "0"}])
	_has_id(b.violations, "__ID_QPS__") with input as _patched([{"op": "remove", "path": "/kubelet/config/eventRecordQPS"}])
}

test_kubelet_without_a_config_file if {
	flags := {"anonymous-auth": "false", "authorization-mode": "Webhook", "client-ca-file": "/etc/kubernetes/certs/ca.crt", "read-only-port": "0", "event-qps": "0", "rotate-server-certificates": "true"}
	inp := json.patch(green, [{"op": "add", "path": "/kubelet", "value": {"flags": flags}}])
	vs := b.violations with input as inp
	count(vs) == 0
	# the file's values do not count when --config is not given
	stale := json.patch(green, [{"op": "remove", "path": "/kubelet/flags/config"}])
	_has_id(b.violations, "__ID_ANON__") with input as stale
	# --config given but the file was not collected
	gone := json.patch(green, [{"op": "remove", "path": "/kubelet/config"}])
	"__ID_ANON__: evidence missing — kubelet.flags (and kubelet.config when --config is set) not collected" in b.violations with input as gone
}

test_server_certificate_rotation_spellings if {
	gate := [{"op": "remove", "path": "/kubelet/config/serverTLSBootstrap"}, {"op": "add", "path": "/kubelet/flags/feature-gates", "value": "RotateKubeletServerCertificate=true"}]
	not _has_id(b.violations, "__ID_RS__") with input as _patched(gate)
	off := [{"op": "remove", "path": "/kubelet/config/serverTLSBootstrap"}, {"op": "add", "path": "/kubelet/flags/feature-gates", "value": "RotateKubeletServerCertificate=false"}]
	_has_id(b.violations, "__ID_RS__") with input as _patched(off)
}

'''

SUBS = {"ENDPOINT": "endpoint", "PRIVATE": "private_cluster", "NODES": "private_nodes", "KMS": "kms",
        "AUTHZ": "entra_authz", "P1": "psa_priv", "P2": "psa_pid", "P3": "psa_ipc", "P4": "psa_net", "P5": "psa_ape",
        "DNS": "default_ns", "NP": "netpolicy", "NPNS": "netpol_ns", "OV": "overlay", "ER": "entra_rbac",
        "ANON": "anon", "RO": "ro_port", "QPS": "eventqps", "RS": "rotate_server"}


def subst(t):
    for k, key in SUBS.items():
        if key in IDS:
            t = t.replace(f"__ID_{k}__", IDS[key])
    return t


body = T_HEAD + T_SHARED + (T_NODES if NODES else "")
body = subst(body)
for k, v in {"__KEY__": KEY, "__BENCH__": BENCH, "__VERSION__": VERSION, "__GEN__": GEN_MARK,
             "__GREEN__": json.dumps(GREEN, indent="\t", ensure_ascii=False), "__N__": str(N),
             "__AUTO__": str(EXPECT["Automated"]), "__MAN__": str(EXPECT["Manual"]), "__L1__": str(L1), "__L2__": str(L2),
             "__NATT__": str(len(attest_ids))}.items():
    body = body.replace(k, v)
if "__ID_" in body:
    sys.exit("ABORT: unresolved test placeholder")
open(f"{OUT}/tests/test_{KEY}_controls.rego", "w").write(body + "\n" + emit_tests(KEY, C, WB, GREEN, "/attest"))
print("ok", VARIANT, N, "automated", EXPECT["Automated"], "manual", EXPECT["Manual"], "fact", N - len(attest_ids),
      "fact-manual", len(fact_manual), "attest", len(attest_ids), "L1", L1, "L2", L2)
