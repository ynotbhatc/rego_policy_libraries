# compliance_report → SARIF 2.1.0

**Status:** shipping
**Kind:** export (Tier 1, runtime)
**Covers:** every module that exposes `compliance_report` / `report` with a `violations` list — all of them
**Consumers:** GitHub code scanning (`upload-sarif`), Azure DevOps, VS Code SARIF viewer, Jenkins Warnings NG, DefectDojo

```bash
opa eval -f json -d benchmarks/cis/rhel_9 -i facts.json 'data.cis_rhel9.main.compliance_report' > report.json
python3 converters/exports/sarif/build.py report.json -o results.sarif
# GitHub: - uses: github/codeql-action/upload-sarif@v3
#           with: { sarif_file: results.sarif }
```

Several reports in one run: pass several files, or evaluate `data` for a whole tree (`'data.ccpa'`); the
reader walks the tree and picks up every report node.

| SARIF | from the report |
|---|---|
| `result` | one per violation, `level: error`, `kind: fail`; message = the violation text |
| `ruleId` | the OSCAL control id (`cis_rhel_9-CIS-1.3.1`): identical in the OSCAL catalog and the OCSF events |
| `rule.shortDescription` | the control statement from the inventory |
| `rule.helpUri` | the Rego file at the release tag |
| `logicalLocations` | the Rego package the report came from |
| `properties.mapped` | `false` when the message prefix is not a control the inventory knows (section-level fail-closed notices); the result is kept, never dropped |
| `--all-rules` | embed every inventory control as a rule (6,076), for viewers that show the rule set |

`test/roundtrip.sh` evaluates CIS RHEL 9 and CCPA on empty input (fail-closed, so every section reports),
converts, and proves result count == violation count, every result names a rule that exists, at least 60 %
of results map to inventory controls, and the file validates against the vendored SARIF 2.1.0 schema.
