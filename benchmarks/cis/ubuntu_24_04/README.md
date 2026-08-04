# Ubuntu 24.04 LTS — DERIVED policy set

**These controls are not authored against the Ubuntu 24.04 LTS CIS Benchmark.**

Every rule in this directory is a copy of `benchmarks/cis/ubuntu_22_04/`, with only the
package name and display strings changed. Verified by diff — the control logic is
byte-identical:

```bash
diff <(cat benchmarks/cis/ubuntu_22_04/*.rego) <(cat benchmarks/cis/ubuntu_24_04/*.rego) \
  | grep '^[<>]' | grep -vE '^[<>] *(package |#|import )'
# only package/import renames and display strings differ
```

## What this means

| | |
|---|---|
| Control logic actually implemented | **CIS Ubuntu Linux 22.04 LTS Benchmark v3.0.0** |
| Platform it is applied to | Ubuntu 24.04 LTS |
| A Ubuntu 24.04 LTS-specific CIS benchmark | **not implemented** |

The previous headers claimed a Ubuntu 24.04 LTS benchmark version that no rule in this
directory implements. That claim has been removed rather than left to imply
coverage we cannot substantiate.

## Before relying on this for Ubuntu 24.04 LTS

The source and target platforms genuinely diverge — RHEL 8 to 9 changed crypto
policies and default services; Ubuntu LTS releases move defaults between
versions. Treat results as an approximate baseline, not a Ubuntu 24.04 LTS CIS
attestation.

Authoring real controls requires the published CIS Ubuntu 24.04 LTS Benchmark, which is
gated behind CIS SecureSuite membership.
