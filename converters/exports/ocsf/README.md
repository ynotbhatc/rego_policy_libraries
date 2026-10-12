# compliance_report → OCSF 1.9.0 Compliance Finding

**Status:** shipping
**Kind:** export (Tier 1, runtime)
**Covers:** every module that exposes `compliance_report` / `report` with a `violations` list — all of them
**Consumers:** Amazon Security Lake, Splunk (OCSF add-on), Microsoft Sentinel, Google SecOps, Panther, any OCSF 1.x pipeline

```bash
opa eval -f json -d frameworks/privacy/ccpa -i facts.json 'data.ccpa' > report.json
python3 converters/exports/ocsf/build.py report.json -o findings.ndjson            # one event per line
python3 converters/exports/ocsf/build.py report.json -o findings.json --json       # or an array
python3 converters/exports/ocsf/validate.py findings.ndjson --online               # vendored schema + schema.ocsf.io
```

One `compliance_finding` (class_uid 2003, type_uid 200301, activity Create) per violation:

| OCSF | from the report |
|---|---|
| `compliance.control` / `standards` / `requirements` | control id, framework, control statement |
| `compliance.status_id` | 3 (Fail) — only violations are emitted; pass events are a later option |
| `compliance.checks[].uid`, `finding_info.uid` | the OSCAL control id, identical to the SARIF `ruleId` |
| `finding_info.src_url` | the Rego file at the release tag |
| `resources[]` | the Rego package the report came from |
| `severity_id` | `--severity` (default 3 Medium); `time` from `--time` (default now) |
| `cloud.provider` + `metadata.profiles: [cloud]` | only with `--cloud-provider aws|azure|gcp`; hosts and SaaS emit no cloud profile |
| `unmapped` | rego package and file, report path, whether the control mapped, the report's `compliant` |

`test/roundtrip.sh` proves one event per violation with uids identical to the SARIF/OSCAL ids and validates
against the vendored class schema (`schema/compliance_finding-1.9.0.schema.json`, from schema.ocsf.io);
`OCSF_ONLINE=1` also posts the first event to the public validator.
