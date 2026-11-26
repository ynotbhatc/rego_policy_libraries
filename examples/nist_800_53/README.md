# A sample NIST SP 800-53 Rev 5 assessment: one family

`facts.json` is the Access Control (AC) evidence for one fictional system, `payroll.example.com`, in the shape the
`nist.sp800_53.access_control` module reads (`input.ac_controls`): account management, access enforcement,
information flow, least privilege, logon limits, session lock, remote and wireless access, plus the
organization-defined parameters (`odp`) each check compares against. Nothing in it comes from a real system.

Only AC is supplied. That is deliberate: most teams start with one family, and the same file shows what the
framework key does with the 19 families it has no facts for.

## Run it

From the repository root, the family on its own:

```bash
opa eval -d frameworks/federal/nist/sp_800_53/access_control -i examples/nist_800_53/facts.json -f pretty \
  'data.nist.sp800_53.access_control.compliance_report'
```

The framework key, on the same file (the key needs the whole `sp_800_53/` tree; it needs `crosswalk/` as well only
when the input carries benchmark results, see below):

```bash
opa eval -d frameworks/federal/nist/sp_800_53 -i examples/nist_800_53/facts.json -f pretty \
  'data.nist_800_53.main.compliance_report'
```

`bash examples/nist_800_53/check.sh` runs both, then the benchmark run below, and asserts the numbers on this page.

## What the output means

**The AC family:** `compliant` is `false`, `controls_evaluated` is 61 (AC base controls and enhancements) and
`violation_count` is 5. Every violation starts with its control id. None says "evidence missing", because every AC
fact is present.

**The framework key** (`nist_800_53`):

- `total_controls` is 546, `failed_controls` is 490, `compliant` is `false`.
- `control_result_counts`: 56 pass, 5 fail, 419 evidence missing, 66 not attested. The 61 AC controls are the
  56 passes and the 5 fails. Every other family reports evidence missing (no facts were collected) or not attested
  (organizational controls that need a signed attestation under `<family>_controls.<topic>.attestation`).
- `family_summary.AC` is `{"compliant": false, "violations": 5}`; every other family is non-compliant too.
- `baseline_results` repeats the picture per 800-53B and FedRAMP baseline: for FedRAMP High, 410 controls in scope,
  365 not passed.
- `assessed_at` is `2026-11-20`, taken from `assessment_date` in the file.

A missing family is never a pass: the key is non-compliant until every family has evidence.

## What is wrong with this system

- **AC-2(3)**: inactive accounts are disabled after 90 days; the organization set 35
- **AC-6(7)**: user privileges were last reviewed 210 days ago; the organization reviews every 90
- **AC-7**: five failed logons are allowed before lockout; the organization set three
- **AC-11**: the screen locks after 30 minutes idle; the organization set 15
- **AC-17(3)**: one remote access entry point bypasses the managed access control point

Fix one in the file, for example set `ac_controls.logon_attempts.maximum_attempts` to 3, and the family's
`violation_count` drops to 4. Delete a key, for example `ac_controls.session_lock`, and AC-11 and AC-11(1) do not pass: they fail
with "evidence missing".

## Adding benchmark results

The report can also take its technical verdicts from a benchmark. Put STIG results in the same input, in either of
the two shapes `crosswalk.correlation` reads, and load the crosswalk next to the module:

```json
{
  "ac_controls": { "...": "the declared evidence, as before" },
  "findings": [
    {"stig_id": "RHEL-09-411075", "status": "Not_a_Finding"},
    {"stig_id": "RHEL-09-211020", "status": "Open"}
  ],
  "reports": [ { "facts_supplied": true, "rule_results": [ {"rule": "RHEL-09-255010", "status": "Not_a_Finding"} ] } ]
}
```

`findings` is a flat list of rule results; `reports` is a list of whole STIG `compliance_report` objects (every
`stig/<platform>` main emits `rule_results` and `facts_supplied`). Use either or both.

```bash
python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); a.update(json.load(open(sys.argv[2]))); json.dump(a,sys.stdout)' \
  examples/nist_800_53/facts.json examples/nist_800_53/benchmark_findings.json |
opa eval -d frameworks/federal/nist/sp_800_53 -d crosswalk/correlation.rego \
  -d crosswalk.stig_800_53:crosswalk/stig_800_53/data.json -I -f pretty 'data.nist_800_53.main.compliance_report'
```

The crosswalk is DISA's own map (STIG rule to CCI to SP 800-53 control). The map file has to load at
`data.crosswalk.stig_800_53`, which is what the `crosswalk.stig_800_53:` prefix does; from the repository root
`opa eval -d .` does the same.

How the two kinds of evidence combine:

| Benchmark verdict for the control | Effect on the control |
|---|---|
| `gap`: at least one mapped rule is Open | The control fails, whatever its declared evidence or attestation says. The finding names the Open rules. |
| `satisfied`: every mapped rule passed (or is not applicable, with at least one pass) | Recorded on the row. The status does not change: the control's own evidence and attestation still decide whether it passes. |
| `not_reviewed`, `not_applicable` | Recorded on the row. The status does not change. |
| `not_evaluated`: no supplied rule maps to the control | Nothing changes. Every enhancement is in this group, because the map is at base-control granularity. |

Benchmark results never turn a control into a pass. A STIG covers the technical settings of the platform that was
scanned; the 800-53 control also covers other systems, procedures and organizational duties, which the declared
evidence and attestations speak to.

With `benchmark_findings.json` added to the sample:

- **AC-8** had passed on its declared evidence. `RHEL-09-211020` is Open and maps to AC-8, so AC-8 now fails;
  `control_result_counts` moves to 54 pass, 6 fail.
- **AC-7** is `satisfied` by the benchmark (`RHEL-09-411075`) and still fails: the declared lockout limit is 5
  against the organization's 3.
- `EXAMPLE-00-000001` is not in the crosswalk. It is listed under `benchmark_evidence.unmapped_rules` and speaks
  to no control.

Each row of `control_results` gains `benchmark: {status, rules, open_rules, not_reviewed_rules}` and the report
gains a `benchmark_evidence` block (the controls per verdict, rule counts, unmapped rule ids, reports without
facts). Neither appears when the input has no `findings` or `reports` key.

It fails closed: a report with `facts_supplied: false` counts every one of its rules as Open; benchmark results
that cannot be read, that contain no rule id the crosswalk knows, or that arrive when the crosswalk is not loaded
each add a `FAIL-CLOSED` finding.

## Next step

Add the next family's facts (`au_controls`, `ia_controls`, ...) to the same file. Each family module's header
comment lists the fact paths it reads, and running the key on `{}` lists every missing path by control.
