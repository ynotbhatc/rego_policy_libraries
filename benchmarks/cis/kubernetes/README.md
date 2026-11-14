# CIS Kubernetes Benchmark v2.1.0

**Version:** v1.0 · generated 2026-11-14 by `tools/cis_generators/gen_kubernetes.py` from the CIS workbook

Every one of the 134 recommendations (65 Automated, 69 Manual). 97 are decided from collected facts, 32 of them
Manual in the workbook because their audit is still a flag, file or object comparison. The other 37 need a person's
judgement (RBAC reviews, admission policy, secrets management) and are reported as not attested until
`input.attest.<key>` is true. A check whose facts were not collected reports `<id>: evidence missing — <field> not
collected`. It never passes. Messages are our own wording; no CIS text is reproduced.

Query: `POST /v1/data/cis_kubernetes/main/compliance_report`

## Sections

| Section | Recommendations |
|---|---|
| 1 Control plane components (files, API server, controller manager, scheduler) | 60 |
| 2 etcd | 7 |
| 3 Control plane configuration (authentication, audit policy) | 5 |
| 4 Worker nodes (files, kubelet, kube-proxy) | 26 |
| 5 Policies (RBAC, admission, network, secrets, namespaces) | 36 |

`cis_kubernetes.rego` holds every recommendation, the `recommendations` table and the report.
`cis_kubernetes_main.rego` is the entrypoint the framework key reads.

## Profile

`input.cis_profile` selects the recommendations in scope. Recommendations outside the selection raise nothing and
are not counted.

| Field | Values | When absent |
|---|---|---|
| `level` | `1`, `2` (Level 2 includes Level 1) | `2` |
| `role` | `master` (or `control_plane`), `worker` | both roles |

`total_controls` is the number in scope: 93 master Level 1, 108 master Level 2, 25 worker Level 1, 26 worker Level 2,
134 with no selection (`benchmark_total_controls` is always 134). The workbook puts each recommendation in one
profile only, so 4.1.1 counts on the master profile and 4.1.2 on the worker profile. That is how CIS publishes them.

## Facts

The input contract is the DISA Kubernetes STIG module's (`benchmarks/stig/kubernetes/`), so one collector feeds
both: component flag maps, the kubelet configuration file, `files.<group>` lists with octal string modes, and
cluster query results with `collection_status`. The module header lists every path. These are the paths this
module adds:

- `api_server.authentication_config`, `etcd.member_count`, `kube_proxy.flags`, `kube_proxy.config`
- `files.cni`, `files.kubelet_service`, `files.kubelet_config_dir`
- `service_accounts.default[]`, `network_policies.namespaces_without_policy[]`
- `collection_status.default_service_accounts`, `collection_status.network_policies`

File modes are compared as permission bit masks, so `0460` fails a `600` limit even though it is numerically smaller.

## Regenerate

```
/usr/bin/python3 tools/cis_generators/dump_workbook.py <CIS_Kubernetes_Benchmark_v2.1.0.xlsx> k8s.json
/usr/bin/python3 tools/cis_generators/gen_kubernetes.py k8s.json benchmarks/cis/kubernetes
opa fmt -w benchmarks/cis/kubernetes
```
