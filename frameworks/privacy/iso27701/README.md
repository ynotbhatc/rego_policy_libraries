# ISO/IEC 27701:2019 privacy information management

**Coverage label: experimental — not validated** (see
[`scripts/coverage_labels.json`](../../../scripts/coverage_labels.json) and the label table in
[COVERAGE.md](../../../COVERAGE.md)).

## Read this before relying on it

- The control list was compiled from public secondary sources: the publisher-distributed preview of the
  standard's table of contents, two NQA control analyses and the NIST Privacy Framework crosswalk. The sources
  and the inclusion rule are listed in the header of `iso27701_main.rego`.
- It has not been checked against the purchased standard. It should be verified against the purchased standard
  when one is bought. No ISO text is carried: ids are numbers, titles are the library's own paraphrases.
- Five clause 6 ids are marked `unconfirmed` because the sources disagree on them: 6.3.2.2, 6.12.1.1,
  6.14.2.1, 6.15.2.2 and 6.15.2.3 (`unconfirmed_ids` in the report, `id_source` per control).
- It has never been run on real evidence.

## What it evaluates

One result per control, 108 in all, edition 2019:

| group | ids | controls | how decided |
|---|---|---|---|
| clause 5, requirements extending ISO/IEC 27001 | 5.2.1 to 5.8.2 | 23 | attestation |
| clause 6, guidance extending ISO/IEC 27002 | 6.2.1.1 to 6.15.2.3 | 36 | 6 from system facts, 30 attestation |
| Annex A, PII controllers | 7.2.1 to 7.5.4 | 31 | 7.4.9 from system facts, 30 attestation |
| Annex B, PII processors | 8.2.1 to 8.5.8 | 18 | 8.4.3 from system facts, 17 attestation |

Each control reports `pass`, `fail`, `evidence_missing` or `not_attested`, the same status values as NIST
SP 800-53 and TISAX. Missing or mistyped evidence is never a pass. Annex A and Annex B apply unless
`input.iso27701.scope.pii_controller` / `pii_processor` is the boolean `false`.

Input: `input.iso27701.evidence.<area>.<fact>` for the technical controls (see `evidence_spec`),
`input.iso27701.attestations["<id>"] = {attested: true, by, date}` for the rest. The boolean fields the module
read before the rebuild (`pims_requirements.*`, `pii_controller.*`, `pii_processor.*`, `data_subject_rights.*`)
are still read for the control each one evidences (`legacy_inputs`).

## Layout

| file | package | area |
|---|---|---|
| `iso27701_main.rego` | `iso27701.main` | control list, evaluation, `compliance_report` |
| `iso27701_pims_requirements.rego` | `iso27701.pims_requirements` | view: clauses 5 and 6 |
| `iso27701_pii_controller.rego` | `iso27701.pii_controller` | view: Annex A |
| `iso27701_pii_processor.rego` | `iso27701.pii_processor` | view: Annex B |
| `iso27701_data_subject_rights.rego` | `iso27701.data_subject_rights` | view: 7.3.1 to 7.3.10 and 8.3.1 |

```bash
opa eval -d frameworks/privacy/iso27701 -f pretty 'data.iso27701.main.compliance_report.control_result_counts'
```
