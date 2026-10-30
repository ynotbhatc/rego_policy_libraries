# SAP Security Baseline Template v2.6 — ABAP stack

The first application-suite baseline in the library. One canonical catalog (SAP's own check ids), one Rego
rule per check that can be decided from facts read on the SAP host, and per-framework views derived from the
same results through data-only mapping tables.

**Entrypoint:** `POST /v1/data/sap_abap_baseline/main/compliance_report`
**Package:** `sap_abap_baseline.main` (checks, manual rules, registry and mappings are sibling files/packages)

## Where the checks come from

SAP publishes the Baseline Template as Focused Run *Configuration and Security Analytics* policies:
[SAP-samples/frun-csa-policies-best-practices](https://github.com/SAP-samples/frun-csa-policies-best-practices)
(Apache-2.0), `BaselinePolicies/SOS/v2.6/ABAP_ALL`. Each `<checkitem>` carries SAP's check id, the requirement
text, the priority and the compliant condition in the CSA expression language. The official Template document
(SAP Note 2253549) sits behind an S-user; the published policies are the same checks in machine-readable form,
so this module is drafted from them and pinned to the commit it was read at.

| What | Count |
|---|---|
| Checks SAP publishes for the ABAP stack (registry rows) | 355 |
| Translated by the importer from SAP's conditions | 127 |
| Hand-written (ACL files, age, kernel patch level) | 11 |
| **Assessable from host facts (v1)** | **138** |
| Not assessable in v1 (user tables, authorizations, audit slots, RFC destinations, clients ...) | 214 |
| Untranslatable conditions (joins across parameters) | 3 |

Those numbers are what `scripts/import_sap_baseline.py` prints; they are not estimates.

## Files

| File | Role |
|---|---|
| `sap_abap_baseline.rego` | METADATA, input contract, helpers, profile, results, projections, `compliance_report` |
| `sap_abap_baseline_checks.rego` | **generated** — one `violations` rule per translated check |
| `sap_abap_baseline_registry.rego` | **generated** — every check SAP publishes, keyed by id: level, requirement, assessable, basis, reason |
| `data/sap_baseline_v2_6_index.json` | **generated** — the same registry for tooling |
| `sap_abap_baseline_manual.rego` | hand-written rules; a `# MANUAL-CHECK: <id>` comment claims an id for the importer |
| `mapping_baseline.rego` | Baseline requirement view (derived from the registry) |
| `mapping_dsag.rego` | DSAG Prüfleitfaden S/4HANA section view (section numbers + this library's labels) |
| `mapping_nist_csf_2_0.rego` | NIST CSF 2.0 subcategory view (all 106 listed; assignment is editorial) |
| `tests/test_sap_abap_baseline.rego` | 62 tests |

## Input contract — `input.sap.abap.*`

Every value is a **string as the host presents it**; the collector never interprets.

```json
{
  "sap": {
    "abap": {
      "profile": "standard",
      "collected_at": "2026-10-29",
      "profile_parameters": {"login/min_password_lng": "12", "gw/acl_mode": "1", "icm/HTTP/admin_0": "PREFIX=/sap/admin,CLIENTHOST=10.0.0.1,ALLOWPUB=FALSE"},
      "transport_parameters": {"TLOGOCHECK": "1", "RECCLIENT": "ALL", "TP_RELEASE": "380.44.90"},
      "kernel": {"KERN_REL": "793_REL", "KERN_PATCHLEVEL": "401", "KERN_COMP_TIME": "Jan 15 2026"},
      "cryptolib": {"CCL": "8.5.50", "CCL_DATE": "2025-11-03"},
      "gateway": {
        "secinfo":  {"present": true,  "lines": ["P TP=* USER=* HOST=app1.example.com USER-HOST=internal"]},
        "reginfo":  {"present": true,  "lines": ["P TP=* HOST=app1.example.com ACCESS=internal CANCEL=internal"]},
        "prxyinfo": {"present": false, "lines": []}
      },
      "message_server": {"acl": {"present": true, "lines": ["HOST=*.example.com"]}}
    }
  }
}
```

| Key | Source on the host (as `<sid>adm`, no RFC, no DB) |
|---|---|
| `profile` | `critical` (p1) · `standard` (p1+p2) · `extended` (all, default) |
| `profile_parameters` | the **effective** parameters of the assessed instance: `sappfpar` / RZ11 view (DEFAULT.PFL overlaid by the instance profile, kernel defaults where resolvable). A parameter absent from the facts **fails** its check — the kernel default is not evidence |
| `transport_parameters` | `TP_DOMAIN_<SID>.PFL` / `tp` parameters (names as SAP's `TRANSPORT_TOOL` store) |
| `kernel` | `disp+work -version` → `KERN_REL`, `KERN_PATCHLEVEL`, `KERN_COMP_TIME` (names as SAP's `SAP_KERNEL` store) |
| `cryptolib` | CommonCryptoLib version `CCL` and build date `CCL_DATE` |
| `gateway.{secinfo,reginfo,prxyinfo}` | the ACL files named by `gw/sec_info`, `gw/reg_info`, `gw/prxy_info`: `present` + raw `lines` |
| `message_server.acl` | the file named by `ms/acl_info`: `present` + raw `lines` |
| `collected_at` | date the facts were read (`YYYY-MM-DD` or RFC 3339); the age checks measure against it so a stored result stays reproducible. Absent: OPA's clock |

## Report

```
controls_evaluated    assessable checks in the selected profile
violations            "<check id>: <SAP requirement text> (<state>)"
violation_details     [{id, level, severity, requirement, message}] — the same with the registry's severity
violation_count / compliant
results               {check id: compliant | violation | not_assessable | out_of_profile}   — every registry row
not_assessable        [{id, level, reason, stores}]  — what v1 does not evaluate, and why
projections           baseline | dsag_s4hana | nist_csf_2_0 → {framework, references[], summary}
```

Each projection reference carries `status` (`compliant` if any mapped check is compliant and none violates,
`violation` if any mapped check violates, `not_assessable` otherwise), the mapped canonical ids and the ids in
each state. A framework reference the Baseline gives no evidence for stays in the list as `not_assessable`.

## Semantics worth knowing

- **Fail-closed.** Empty input evaluates every in-profile check; all but six violate. The six are SAP's own
  `not_found="positive"` checks (the parameter may legitimately be absent: `DISCL-O_h`, `PWDPOL-A_j.5a`,
  `PWDPOL-A_l`) and the three ACL *content* checks, whose missing file is reported once by their `.1` sibling.
- **Variants.** Where SAP publishes several variants of one check id (e.g. `SSO-A_d`), a value that satisfies
  any of them passes; the generated rule says so in its comment. `CHANGE-A_g.4` (kernel patch level) is joined
  on the kernel release by SAP and is hand-written with the per-release minimums.
- **`_` in parameter-name patterns is literal.** SQL `LIKE 'icm/HTTP/admin_%'` means the literal underscore
  in SAP parameter names; the importer converts `NAME LIKE` patterns that way (values keep SQL semantics).
- **Regexes.** SAP's conditions use HANA regex; the importer rejects lookaround and backreferences (RE2) and
  compiles everything else — three checks fall out as untranslatable and say so in the registry.
- **Messages cite the id** (`PWDPOL-A_a.1: ... (is "8")`). The control counter (`make count`) requires a digit
  in a citation, so ids like `NETENC-A_e` count as uncited checks; the count is right, the `cited` split is
  conservative.

## Regenerating

```bash
git clone --depth 1 https://github.com/SAP-samples/frun-csa-policies-best-practices /tmp/frun
python3 -I scripts/import_sap_baseline.py \
    --source /tmp/frun/BaselinePolicies/SOS/v2.6/ABAP_ALL \
    --commit "$(git -C /tmp/frun rev-parse HEAD)" \
    --out benchmarks/sap/abap
opa test benchmarks/sap -p 4 && make coverage && make count
```

`--check` regenerates to memory and diffs against the committed files (for CI). A new Template version is a
new `--source` directory; hand-written ids and the mapping tables carry over unchanged unless SAP renumbers.

## Not in v1 (and said so in the registry)

HANA parameters (`HANA_ALL`), Java stack, Web Dispatcher and Cloud Connector policies; table-level checks
(standard users, password hashes, critical authorizations, clients, RFC destinations, audit slots) need RFC or
database access — each is a registry row with `reason` naming the store, so the report never overstates
coverage. SoD and role analytics are out of scope by design (SAP GRC's territory).
