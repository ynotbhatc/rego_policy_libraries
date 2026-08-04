# Debian 11 — DERIVED policy set

**These controls are not authored against the Debian 11 CIS Benchmark.**

Every rule in this directory is a copy of `benchmarks/cis/ubuntu_20_04/`, with only the
package name and display strings changed. Verified by diff — the control logic is
byte-identical:

```bash
diff <(cat benchmarks/cis/ubuntu_20_04/*.rego) <(cat benchmarks/cis/debian_11/*.rego) \
  | grep '^[<>]' | grep -vE '^[<>] *(package |#|import )'
# only package/import renames and display strings differ
```

## What this means

| | |
|---|---|
| Control logic actually implemented | **CIS Ubuntu Linux 20.04 LTS Benchmark v3.0.0** |
| Platform it is applied to | Debian 11 |
| A Debian 11-specific CIS benchmark | **not implemented** |

The previous headers claimed a Debian 11 benchmark version that no rule in this
directory implements. That claim has been removed rather than left to imply
coverage we cannot substantiate.

## Before relying on this for Debian 11

The source and target platforms genuinely diverge — RHEL 8 to 9 changed crypto
policies and default services; Ubuntu LTS releases move defaults between
versions. Treat results as an approximate baseline, not a Debian 11 CIS
attestation.

Authoring real controls requires the published CIS Debian 11 Benchmark, which is
gated behind CIS SecureSuite membership.
