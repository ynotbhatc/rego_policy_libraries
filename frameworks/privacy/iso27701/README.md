# ISO/IEC 27701:2019 privacy information management

**Coverage label: experimental — not validated** (see
[`scripts/coverage_labels.json`](../../../scripts/coverage_labels.json) and the label table in
[COVERAGE.md](../../../COVERAGE.md)).

## Read this before relying on it

- The module has not been checked against the published text of ISO/IEC 27701:2019, and it has never been run on
  real evidence. Its control ids and wording are the library's own reading, not an audited mapping.
- A rebuild against the 2019 edition waits for the standard's table of contents (issue #302). The 2025 revision is
  not covered.
- It declares 134 controls and the coverage scan finds 67 (`scripts/coverage_stamp.py`, known gap), so about half
  of what it declares is not evaluated.

Use it to explore how privacy controls can be expressed as policy, not as evidence for a certification audit.

## Layout

| file | package | area |
|---|---|---|
| `iso27701_pims_requirements.rego` | `iso27701.pims_requirements` | PIMS requirements (clauses 5 and 6) |
| `iso27701_pii_controller.rego` | `iso27701.pii_controller` | PII controllers (clause 7) |
| `iso27701_pii_processor.rego` | `iso27701.pii_processor` | PII processors (clause 8) |
| `iso27701_data_subject_rights.rego` | `iso27701.data_subject_rights` | data subject rights |
| `iso27701_main.rego` | `iso27701.main` | aggregate `compliance_report` |

```bash
opa eval -d frameworks/privacy/iso27701 -f pretty 'data.iso27701.main.compliance_report.compliant'
```
