# Input schemas

Every module in this library evaluates one input document of facts. A key the module does not read is
ignored without an error: send `sshd.permit_root_login` where the rule reads `ssh_config.PermitRootLogin`
and the result is "evidence missing", or a finding about a default, with nothing saying the name was wrong.

`schemas/input/<framework key>/schema.json` is a JSON Schema (draft 2020-12) for the facts each framework
key reads, so a caller or a collector can check a document before it is evaluated. A framework key is the
`<key>` in `data.<key>.main.compliance_report` (`stig.rhel_9`, `cis_rhel9`, `cis_windows_2022`, `pci_dss`).
`schemas/index.json` lists every key with its derivation, the number of paths it knows and its sources.

The library stays policy only. The schemas describe the input contract; nothing here gathers facts.

## Generated, never written by hand

```bash
make schemas                                    # python3 scripts/gen_input_schemas.py
python3 scripts/gen_input_schemas.py --check    # stale schema or failing self-test = exit 1 (in make check-generated)
```

Each schema records where it came from in `x-derivation`. The levels, strongest first:

| `x-derivation` | Source | Types | `required` |
|---|---|---|---|
| `table` | The reviewed Linux STIG rule tables (RHEL 9, Oracle Linux 9, Oracle Linux 8, RHEL 10), through the same extraction that writes [`LINUX_COLLECTOR_CONTRACT.md`](../benchmarks/stig/LINUX_COLLECTOR_CONTRACT.md). Every path carries the rules that read it (`x-read-by`). | What the rule's accessor accepts plus the type in its pass fixture | The evidence list (`ev`) of every rule that always applies. Evidence of a rule with a Not Applicable clause is in `x-required-when-applicable` |
| `manifest` | The Windows CIS modules' `data/collector_manifest.json`: every registry value, audit subcategory, secedit key and user right the checks read | Seen in the module's passing test fixtures (`x-type-source: fixture`) | None: a value that does not exist is omitted |
| `static-scan+fixture` | Every `input.<path>` and `object.get(input, [...])` reference in the module's own sources, plus the shape of its all-pass test fixture (found by evaluation, as `make check-bad-input` finds it) | Seen in that fixture (`x-type-source: fixture`) | None: a scan cannot tell required evidence from optional |
| `paths-only` | The static scan alone; the key's tests hold no all-pass fixture | None | None |

Read the level before relying on a schema:

- A `table` schema is the contract. A document that validates carries every always-required path with an
  accepted type.
- A `manifest` schema names everything the checks read. Its leaf types are examples that pass, not the full
  set a check accepts.
- A `static-scan+fixture` schema names what the scan and the fixture can see. A module that reads through a
  local alias (`cfg := input.ssh_config`, then `cfg.PermitRootLogin`) contributes those nested names only if
  its fixture carries them. Validation finds misnamed keys and wrong types; it cannot say evidence is complete.
- A `paths-only` schema is a list of names, often only the top-level ones. It catches a misspelt top-level key
  and little else.

In every schema the top level is open (`additionalProperties: true`), because callers send shared fact
documents that feed several frameworks. The closed list of names the module reads is in `x-known-paths`
(and in each object's `properties`); the validator uses it to find misnamed keys.

Other annotations: `x-framework-key`, `x-entrypoint`, `x-source` (the files the schema was derived from),
`x-fixture` (the test rule that supplied shapes and examples), `x-variable-key` (an object keyed by a name
the rule supplies, such as a user SID), `x-accepted` (a path where any non-null value counts as collected).

## Validate a document

```bash
python3 scripts/validate_input.py stig.rhel_9 facts.json
python3 scripts/validate_input.py cis_rhel9 examples/rhel9/facts.json
python3 scripts/validate_input.py stig.rhel_9 facts.json --partial   # a partial document: skip MISSING
python3 scripts/validate_input.py cis_rhel9 facts.json --strict      # any key the module does not read fails
python3 scripts/validate_input.py --list                             # keys and their derivation
```

Python standard library only. Exit status 1 when it reports a problem:

| Finding | Meaning |
|---|---|
| `MISSING` | A required path is absent or null |
| `TYPE` | A value of a JSON type the module does not accept |
| `MISNAMED` | A key the module does not read, close to a name it does read (case, separators or a small spelling difference, at the same place or elsewhere in the document) while that name is absent |

Keys the module does not read and that resemble nothing it reads are listed as notes, since a shared document
legitimately carries them; `--strict` turns them into problems. A document wrapped as `{"input": {...}}`
(the OPA data API form) is unwrapped.

```console
$ python3 scripts/validate_input.py stig.rhel_9 facts.json --partial
stig.rhel_9 (schema derivation: table): 3 problems in facts.json
  MISNAMED  sshd.permit_root_login: not read by this module; did you mean ssh_config.PermitRootLogin?
  MISNAMED  sshd_runtime.PermitEmptyPasswords: not read by this module; did you mean ssh_config.PermitEmptyPasswords?
  MISNAMED  sshd_runtime.clientaliveinterval: not read by this module; did you mean ssh_config.ClientAliveInterval?
  note: 4 key(s) this module does not read: fips.fips_mode, sshd, sshd_runtime, inventory_hostname
```

The schemas are ordinary JSON Schema, so any draft 2020-12 validator checks types and required paths. The
misnamed-key check is specific to `validate_input.py`, because JSON Schema has no notion of "close to a
known name".

## What the self-tests prove

`gen_input_schemas.py --check` regenerates every schema in memory, fails on a difference from the committed
file, and for each schema checks that:

- every all-pass fixture found for the key validates with no problem;
- that fixture with one key re-spelled is reported `MISNAMED` at that key;
- that fixture with one value of an excluded type is reported `TYPE` at that value;
- for the `table` schemas, the fixture without one required path is reported `MISSING`, and each rule's own
  pass fixtures validate as partial documents;
- for a `paths-only` schema, a document holding one known top-level key re-spelled is reported `MISNAMED`.

For the fixture-derived levels the first check holds by construction (the types came from that fixture), so
it guards the generator and the validator against regressions more than it tests the schema. The `table`
checks are independent: the `required` list comes from the rule tables and the fixture from the generated
tests.

## Layout note

One directory per key, one `schema.json` in it. `opa test .` loads every JSON file under the root as data,
placed by directory, and two files in one directory that both define `$id` are a merge error. In this layout
a schema lands at `data.schemas.input["<key>"]`, which no package reads or defines.
