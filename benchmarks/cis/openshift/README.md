# CIS Red Hat OpenShift Container Platform Benchmark v2.0.0

**Version:** v1.0 · generated 2026-11-17 by `tools/cis_generators/gen_openshift.py` from the CIS workbook

Every one of the 115 recommendations (13 Automated, 102 Manual). 101 are decided from collected facts, 88 of them
Manual in the workbook because their audit is still an `oc` query, a file stat or an object comparison; 3 of those
also need an attestation for the part of the audit that is a judgement (3.2.1, 5.1.1, 5.5.1). The other 14 need a
person's judgement (RBAC reviews, garbage collection, secrets management, namespaces) and are reported as not
attested until `input.attest.<key>` is true. A check whose facts were not collected reports `<id>: evidence missing —
<field> not collected`. It never passes. Messages are our own wording; no CIS text is reproduced.

Replaces the earlier hand-written module (156 declared controls on an abstract `input.openshift` contract). The
package `cis_openshift_4` and the framework key entrypoint stay the same.

Query: `POST /v1/data/cis_openshift/main/compliance_report`

## Sections

| Section | Recommendations |
|---|---|
| 1 Control plane components (files, API server, controller manager, scheduler) | 58 |
| 2 etcd | 7 |
| 3 Control plane configuration (authentication, audit) | 3 |
| 4 Worker nodes (files, kubelet) | 22 |
| 5 Policies (RBAC, SCCs, network, secrets, image provenance, namespaces) | 25 |

`cis_openshift_4.rego` holds every recommendation, the `recommendations` table and the report.
`cis_openshift_main.rego` is the entrypoint the framework key reads.

## Profile

`input.cis_profile.level` selects `1` or `2` (Level 2 includes Level 1; default `2`). `total_controls` is the number
in scope: 99 at Level 1, 115 at Level 2 (`benchmark_total_controls` is always 115).

## Facts

The audits run per node, per pod or per etcd member, so most facts are lists and every entry must pass; an empty
list counts as not collected. Shapes follow `benchmarks/cis/kubernetes` (`files.<group>` with octal string modes,
KubeletConfiguration field names, `collection_status`) and the DISA OpenShift STIG module
(`api_server.audit_profile`, `oauth.identity_providers`, `cluster.kubeadmin_user_exists`) where the fact is the
same. The module header lists every path. These are the paths this module adds:

- `etcd.members[] {name, flags}`, `kubelet.nodes[] {name, config}` (configz `.kubeletconfig`)
- `openshift.kube_apiserver_config`, `openshift.openshift_apiserver_config`, `openshift.kube_controller_manager_config`
  (parsed `config.yaml` of each `config` configmap; arguments are lists of strings)
- `openshift.kube_controller_manager_pod`, `openshift.kube_scheduler_pod` (parsed `pod.yaml` configmaps)
- `openshift.kubeapiserver`, `openshift.openshiftapiserver`, `openshift.apiserver`, `openshift.ingresscontroller_default`,
  `openshift.authentication_cliconfig`, `openshift.image_config`, `openshift.openshift_apiserver_serving_cert`
- `openshift.kube_apiserver_endpoint_ports[]`, `openshift.openshift_apiserver_endpoint_ports[]`,
  `openshift.kube_apiserver_container_ports[]`, `openshift.metrics_probes.<component>`, `openshift.audit_logs`
- `openshift.unauthenticated_cluster_role_bindings[]`, `openshift.cluster_admin_bindings[]`,
  `openshift.pods_without_seccomp_profile[]`, `scc.items[]`
- `files.ovs`, `files.node_kubeconfig`, `files.scheduler_kubeconfig`, `files.controller_manager_kubeconfig`
- `collection_status.scc`, `.cluster_admin_bindings`, `.unauthenticated_bindings`, `.pod_seccomp`

File modes are compared as permission bit masks, so `0460` fails a `600` limit even though it is numerically smaller.

## Regenerate

```
/usr/bin/python3 tools/cis_generators/dump_workbook.py <CIS_Red_Hat_OpenShift_Container_Platform_Benchmark_v2.0.0.xlsx> ocp.json
/usr/bin/python3 tools/cis_generators/gen_openshift.py ocp.json benchmarks/cis/openshift
```
