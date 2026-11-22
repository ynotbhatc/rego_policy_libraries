# crosswalk — the 800-53 control spine

Joins the library's standards onto a shared NIST SP 800-53 substrate so a
control is **assessed once and reported against every standard that inherits
it**. See `docs/CONTROL_CORRELATION_PATTERN.md` for the measured pattern this
implements.

- `stig_800_53/data.json` — `stig_id → [800-53 control]` for 17 STIG
  platforms (3,787 rules) (loads at `data.crosswalk.stig_800_53`). Provenance in `.meta`.
- `correlation.rego` (`package crosswalk.correlation`) — given
  `input.findings` (any stig aggregator's finding list), emits
  `control_status[<800-53>] = "satisfied" | "gap"` (absent = not evaluated)
  and a `summary`. Gap wins; unassessed controls are never reported as passed.
  It also accepts `input.reports` (whole STIG `compliance_report` objects, read from `rule_results`), and
  `control_status` can be `not_reviewed` or `not_applicable` as well.
- `framework_overlay.rego` (`package crosswalk.framework_overlay`) reports the frameworks in
  `framework_maps/data.json` from the same spine (authoritative maps only).

## Framework modules read the spine

A framework module can take a control's technical verdict from benchmark results instead of only from declared
evidence. NIST SP 800-53 (`frameworks/federal/nist/sp_800_53`, key `nist_800_53`) is the first to do so.

The input is the framework's usual input plus benchmark results in the two shapes above, and no other:

```json
{
  "ac_controls": { "...": "the framework's own facts" },
  "reports":  [ { "facts_supplied": true, "rule_results": [ {"rule": "RHEL-09-255010", "status": "Open"} ] } ],
  "findings": [ {"stig_id": "RHEL-09-411075", "status": "Not_a_Finding"} ]
}
```

What a module reads:

| Rule | Gives |
|---|---|
| `correlation.control_evidence[<800-53 id>]` | `{status, rules, open_rules, not_reviewed_rules}`: the verdict with the rule ids behind it |
| `framework_overlay.control_evidence[<map key>][<framework control id>]` | `{status, spine, not_evaluated}` through `framework_maps`: `gap`, `satisfied` or `not_covered`, the evaluated 800-53 controls with their rules, and the mapped controls nothing spoke to |
| `correlation.evidence_supplied` | whether the input carries `reports` or `findings` at all |
| `correlation.spine_loaded` | whether the map is present in `data` |
| `correlation.unmapped_rules`, `correlation.reports_without_facts` | what could not be used |

The combination rule, as NIST SP 800-53 implements it:

1. A benchmark **gap** fails the control, whatever its declared evidence or attestation says.
2. A benchmark **satisfied** verdict is recorded on the control and changes nothing else. The control's own
   evidence and attestation still apply, so benchmark results never turn a control into a pass.
3. A control no supplied rule maps to stays **not evaluated** and is shown as such.
4. With no benchmark results in the input, the framework's report is what it was before.

Fail closed: a report with `facts_supplied: false` counts every rule in it as Open; a rule id the map does not
know speaks to no control; benchmark results that cannot be read, or that arrive when this package or its data is
not loaded, are a `FAIL-CLOSED` finding in the framework's report. Verdicts are carried through the maps as they
are. Nothing here scores, weights or ranks.

Loading: a framework module refers to `data.crosswalk.correlation` by reference only, so it still loads and
evaluates without this directory. To use benchmark results, load `correlation.rego` into the same OPA as the
framework and the map at `data.crosswalk.stig_800_53` (from the repository root `opa eval -d .` does that; for a
single file use `-d crosswalk.stig_800_53:crosswalk/stig_800_53/data.json`, or `PUT /v1/data/crosswalk/stig_800_53`
on a server). The map is at base-control granularity: an enhancement such as AC-2(1) never gets a verdict.

Add a standard: ship its `<id> → 800-53` map in the same shape, then the
overlap analysis in the pattern doc §7 applies unchanged.
