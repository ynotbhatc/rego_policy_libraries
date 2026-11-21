# compliance_report → SARIF 2.1.0

**Status:** shipping
**Kind:** export (Tier 1, runtime)
**Covers:** every module that exposes `compliance_report` / `report` with a `violations` list — all of them
**Consumers:** GitHub code scanning (`upload-sarif`), Azure DevOps, VS Code SARIF viewer, Jenkins Warnings NG, DefectDojo

```bash
opa eval -f json -d . -i facts.json 'data.<key>.main.compliance_report' > report.json        # any framework key
python3 converters/exports/sarif/build.py report.json --key <key> -o results.sarif --validate \
    --subject host01 --artifact-uri facts/host01.json
# GitHub: - uses: github/codeql-action/upload-sarif@v3
#           with: { sarif_file: results.sarif }
```

Input: `opa eval -f json` output, the OPA REST response (`{"result": {...}}`) or the bare report; `--key` names the
package for the last two. `--validate` checks the output against `schema/sarif-2.1.0.json` and exits 1 when it does
not validate (2 without `jsonschema`). Several reports in one run: pass several files, or evaluate `data` for a whole
tree (`'data.ccpa'`); the reader walks the tree and picks up every report node.

| SARIF | from the report |
|---|---|
| `result` | one per violation message, `kind: fail`; message = the violation text. A `control_results` row that is not satisfied and has no message gets one result (`<id>: evidence_missing (evidence)`) |
| `level` | the module's severity: STIG CAT I / high → `error`, CAT II / medium → `warning`, CAT III / low → `note`; none stated → `error` (fail closed), `warning` for `not_attested` |
| `--include-pass` | `control_results` `pass` rows as `kind: pass`, `not_applicable` as `kind: notApplicable`, `level: none` (not raised as alerts) |
| `ruleId` | the OSCAL control id (`cis_rhel_9-CIS-1.3.1`): identical in the OSCAL catalog and the OCSF events |
| `rule.shortDescription` | the control statement from the inventory |
| `rule.properties.security-severity` | 8.0 / 5.5 / 3.0 from the worst stated severity, for code scanning's severity column |
| `rule.helpUri` | the Rego file at the release tag |
| `physicalLocation` | `--artifact-uri` (default: the first input path), line 1: the file in the scanned repository the results are reported against. Code scanning requires a physical location |
| `logicalLocations` | the Rego package the report came from |
| `partialFingerprints` | `controlFinding/v1`: hash of rule, message and subject, so distinct findings of one control stay distinct alerts |
| `automationDetails.id` | `rego_policy_libraries/<key>/<subject>/`: the code-scanning category, one per framework and subject |
| `properties.mapped` | `false` when the message prefix is not a control the inventory knows (section-level fail-closed notices); the result is kept, never dropped |
| `--all-rules` | embed every inventory control as a rule, for viewers that show the rule set |

`test/roundtrip.sh` evaluates CIS RHEL 9 and CCPA on empty input (fail-closed, so every section reports),
converts, and proves result count == violation count, every result names a rule that exists, at least 60 %
of results map to inventory controls, and the file validates against the vendored SARIF 2.1.0 schema.
`../_lib/test/roundtrip.sh` converts every framework key's report (bare, with `--key`) and validates each, and runs a
fixture with every `control_results` status through `--include-pass`.
