# crosswalk — the 800-53 control spine

Joins the library's standards onto a shared NIST SP 800-53 substrate so a
control is **assessed once and reported against every standard that inherits
it**. See `docs/CONTROL_CORRELATION_PATTERN.md` for the measured pattern this
implements.

- `stig_800_53/data.json` — `stig_id → [800-53 control]` for 15 STIG
  platforms (loads at `data.crosswalk.stig_800_53`). Provenance in `.meta`.
- `correlation.rego` (`package crosswalk.correlation`) — given
  `input.findings` (any stig aggregator's finding list), emits
  `control_status[<800-53>] = "satisfied" | "gap"` (absent = not evaluated)
  and a `summary`. Gap wins; unassessed controls are never reported as passed.

Add a standard: ship its `<id> → 800-53` map in the same shape, then the
overlap analysis in the pattern doc §7 applies unchanged.
