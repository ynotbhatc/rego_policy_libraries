# Debian 11 — DERIVED policy set

**These controls are not authored against the Debian 11 CIS Benchmark.**

The controls here are the controls of `benchmarks/cis/ubuntu_20_04/`: the same control ids, the same
declared total (163), the same input contract. The two trees began as copies and have since been
repaired separately, so the Rego is **not** byte-identical and is not claimed to be. What holds, and
how it was measured on 2026-11-24:

- **Same input contract.** The all-pass fixture is the same object in both trees
  (`tests/test_all_pass_fixture.rego`; `diff` of the two `fixture_compliant` objects is empty) and
  both entrypoints report it compliant, 163 of 163.
- **Same verdict on changed facts, with one exception.** Each leaf of that fixture was changed one at
  a time (booleans flipped, sent as strings and removed; numbers sent as strings, removed and pushed
  out of range; strings removed and replaced with garbage): 637 inputs. The two trees give the same
  compliant / not-compliant verdict on 636 of them and the same failed-control count on 631. The
  exception is `ip_forwarding.ipv6_forwarding` left out on a host that states `ipv6.disabled: true`:
  Ubuntu 20.04 accepts that, this tree reports the fact as not collected.
- **Different wording and different evidence rules.** The finding text is identical on 588 of the 637.
  Where it differs:
  - evidence-missing findings for text facts carry a section-level id here (`CIS 1.x`, `CIS 4.2.x`,
    `CIS 5.x`, `CIS 5.3.x`, `CIS 6.2`) where Ubuntu 20.04 names the control (`CIS 1.7.4`, `CIS 4.2.2.1`,
    ...), which is why the failed-control count differs on five inputs;
  - a missing text fact here is often reported twice (the evidence finding and the rule that reads the
    fact), once in Ubuntu 20.04;
  - the sshd_config, auditd.conf and bootloader parsers were rewritten separately (this tree also
    lists the `-etm` variants of the weak MACs and treats `AllowTcpForwarding all` as enabled);
  - some messages state the accepted modes differently ("0600" here, "0600 or more restrictive" there).
- **On empty input** both report 0 of 163 passed; this tree lists 202 findings, Ubuntu 20.04 lists 173.

The yes/no facts, the numbers and the applicability gates follow the same evidence rule in both trees
(only a JSON boolean answers a yes/no fact; "does not apply" is the gate fact sent as `false`), and the
same mutation test runs over both (`tests/test_bad_input_types.rego`).

To see the textual difference:

```bash
diff <(cat benchmarks/cis/ubuntu_20_04/*.rego) <(cat benchmarks/cis/debian_11/*.rego) \
  | grep '^[<>]' | grep -vE '^[<>] *(package |#|import )' | wc -l
# about 925 lines at the time of writing: not only package renames and display strings
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
