# crosswalk/attack_800_53 — MITRE ATT&CK v16.1 to NIST SP 800-53 Rev 5

`data.json` (loads at `data.crosswalk.attack_800_53`) maps each NIST SP 800-53 Rev 5 control to the ATT&CK
Enterprise techniques it mitigates: `map["AC-2"] = ["T1078", ...]`. Provenance is in `.meta`.

- **Source:** Center for Threat-Informed Defense, mappings-explorer (ATT&CK v16.1, Enterprise, 800-53 Rev 5,
  last updated 04/16/2025). Licence as stated by that repository: Apache 2.0. URL and sha256 in `.meta`.
- **Selection:** objects with `status != non_mappable` and `mapping_type == mitigates`: 5,314 of 5,410 source
  objects (the other 96 are `non_mappable`, techniques ATT&CK lists no mitigation for). Result: 109 controls,
  470 techniques, 5,264 distinct control-technique pairs (50 duplicate pairs collapsed).
- **Ids:** control ids are unpadded (`AC-2`, not the source's `AC-02`) to match `crosswalk/stig_800_53`.

## What it is not

It says a control *mitigates* a technique. It does not say the library checks that control. It is lookup data
only: no `.rego`, **zero control-level checks added**, and it does **not** feed the OSCAL baseline coverage.
Join it to a control status (for example from `crosswalk.correlation`) in a consumer if you want a
threat-informed view; the join is not done here.
