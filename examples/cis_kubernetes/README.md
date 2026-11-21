# A sample Kubernetes cluster

`facts.json` is the input for one fictional kubeadm cluster, in the shape the CIS Kubernetes Benchmark v2.1.0
module in this library reads: the kube-apiserver, controller-manager, etcd and kube-proxy flags, the kubelet flags
and configuration file, file owners and modes on the control plane and nodes (modes as octal strings, for example
`"0600"`), cluster query results (namespaces, default service accounts, network policies, secrets read through
environment variables) with a `collection_status` per query, and the sign-offs for the manual recommendations
(`attest`). Nothing in it comes from a real cluster.

The cluster is mostly hardened and has a handful of ordinary gaps, so the result is mixed.

## Run it

From the repository root:

```bash
opa eval -d benchmarks/cis/kubernetes -i examples/cis_kubernetes/facts.json -f pretty 'data.cis_kubernetes.main.compliance_report'
```

## What the output means

- `compliant` is `false`: at least one recommendation failed.
- `total_controls` is 134, every recommendation in v2.1.0, because the file sets
  `"cis_profile": {"level": 2, "roles": ["master", "worker"]}`. Remove `cis_profile` and you get the same default.
  `level_1` (118) and `level_2` (16) split the count by profile level.
- `failed_controls` is 7 and `passed_controls` is 127: 5 Level 1 and 2 Level 2 recommendations fail.
- Two of the seven are "evidence missing": their facts were not collected, which is a finding, not a pass.
- `violations` has one line per failing recommendation, starting with its id. `section_results` gives the same
  picture per section.

To see only the failures:

```bash
opa eval -d benchmarks/cis/kubernetes -i examples/cis_kubernetes/facts.json -f json 'data.cis_kubernetes.main.compliance_report' \
  | jq -r '.result[0].expressions[0].value.violations[]'
```

## What is wrong with this cluster

- **1.1.13**: `/etc/kubernetes/admin.conf` is mode 0644, so any local user can read the cluster-admin credentials
- **1.2.15**: the API server runs with profiling turned on
- **1.4.1, 1.4.2**: evidence missing: the scheduler's flags (`scheduler.flags`) were not collected, so the module
  cannot tell how the scheduler is configured. Both fail instead of passing
- **4.2.4**: the kubelet's unauthenticated read-only port is open (`readOnlyPort: 10255`)
- **5.3.2**: the `payments` namespace has no NetworkPolicy, so every pod can reach its workloads
- **5.4.1**: the collector found three places where workloads read Secrets through environment variables instead of
  mounted files (`secrets.env_var_usage_count: 3`)

Fix one in the file and run the command again: set `api_server.flags.profiling` to `"false"` and
`failed_controls` drops to 6. Set a `collection_status` entry to anything but `"ok"` and the result of that query
no longer counts: an empty list passes only when the collector says the query ran (for example, `network_policies`
set to anything but `"ok"` turns 5.3.2 into evidence missing).

## Where facts come from

This library evaluates facts; it does not collect them. The input contract is shared with the DISA Kubernetes
STIG module (`benchmarks/stig/kubernetes/`), so one collector feeds both; every path is listed in the header of
[`benchmarks/cis/kubernetes/cis_kubernetes.rego`](../../benchmarks/cis/kubernetes/cis_kubernetes.rego) and in
[`benchmarks/cis/kubernetes/README.md`](../../benchmarks/cis/kubernetes/README.md). The collectors in the companion
product, [Ansible Automated Compliance](https://github.com/Ansible-Automated-Compliance/aac), produce this document;
any tool that writes the same JSON works equally well.

## Keeping it true

`bash examples/cis_kubernetes/check.sh` evaluates the file and fails if the result is no longer the one described
here (134 recommendations, these 7 failing, 2 of them evidence missing).
