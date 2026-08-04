# Rocky Linux 9 — DERIVED policy set

**These controls are not authored against the Rocky Linux 9 CIS Benchmark.**

Every rule in this directory is a copy of `benchmarks/cis/rocky_linux_8/`, with only the
package name and display strings changed. Verified by diff — the control logic is
byte-identical:

```bash
diff <(cat benchmarks/cis/rocky_linux_8/*.rego) <(cat benchmarks/cis/rocky_linux_9/*.rego) \
  | grep '^[<>]' | grep -vE '^[<>] *(package |#|import )'
# only package/import renames and display strings differ
```

## What this means

| | |
|---|---|
| Control logic actually implemented | **CIS Rocky Linux 8 Benchmark v3.0.0** |
| Platform it is applied to | Rocky Linux 9 |
| A Rocky Linux 9-specific CIS benchmark | **not implemented** |

The previous headers claimed a Rocky Linux 9 benchmark version that no rule in this
directory implements. That claim has been removed rather than left to imply
coverage we cannot substantiate.

## Before relying on this for Rocky Linux 9

The source and target platforms genuinely diverge — RHEL 8 to 9 changed crypto
policies and default services; Ubuntu LTS releases move defaults between
versions. Treat results as an approximate baseline, not a Rocky Linux 9 CIS
attestation.

Authoring real controls requires the published CIS Rocky Linux 9 Benchmark, which is
gated behind CIS SecureSuite membership.
