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

The framework key, on the same file (the key needs the whole `sp_800_53/` tree and nothing outside it):

```bash
opa eval -d frameworks/federal/nist/sp_800_53 -i examples/nist_800_53/facts.json -f pretty \
  'data.nist_800_53.main.compliance_report'
```

`bash examples/nist_800_53/check.sh` runs both and asserts the numbers below.

## What the output means

**The AC family:** `compliant` is `false`, `controls_evaluated` is 60 (AC base controls and enhancements) and
`violation_count` is 5. Every violation starts with its control id. None says "evidence missing", because every AC
fact is present.

**The framework key** (`nist_800_53`):

- `total_controls` is 542, `failed_controls` is 487, `compliant` is `false`.
- `control_result_counts`: 55 pass, 5 fail, 416 evidence missing, 66 not attested. The 60 AC controls are the
  55 passes and the 5 fails. Every other family reports evidence missing (no facts were collected) or not attested
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

## Next step

Add the next family's facts (`au_controls`, `ia_controls`, ...) to the same file. Each family module's header
comment lists the fact paths it reads, and running the key on `{}` lists every missing path by control.
