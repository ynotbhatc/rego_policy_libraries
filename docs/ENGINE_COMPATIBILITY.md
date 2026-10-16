# Rego engine compatibility

**Version:** v1.0
**Date:** 2026-10-16
**Authors:** Tim Coulter · Claude (Anthropic)

## Supported engines

This library is written for, and tested against, **Open Policy Agent** and **Enterprise OPA**.
CI pins OPA **v1.10.0** (`.github/workflows/opa-test.yml`). Tools that embed OPA's Go evaluator
(Conftest, Gatekeeper, Trivy, Regula and the others listed in the README) evaluate the same way.

**Other Rego engines are not supported.** A policy that loads and passes on OPA is not guaranteed
to load, or to reach the same decision, on an independent implementation of the language. A
compliance verdict is only as good as the engine that computed it.

## Tested: rego-cpp (regopy 1.5.2)

[rego-cpp](https://github.com/microsoft/rego-cpp) is Microsoft's C++ implementation of Rego;
`regopy` is its Python binding, used to evaluate Rego in-process without an OPA server. We ran
the whole library (commit `22750747`) through regopy **1.5.2** (the latest release, 2026-07-04) and compared it with
OPA 1.10.0 on 2026-10-16.

### Loading

| Result | Policy files (of 797, tests excluded) |
|---|---|
| Load and evaluate | 701 |
| Fail to load | **96** |

| Cause of the load failure | Files |
|---|---|
| `some k, v in x` inside a **set or array** comprehension (`{k \| some k, v in o}`, `[v \| some _, v in a]`): "Invalid collection" | 87 |
| rego-cpp internal error "bundle verify: raw index … >= local_count …" | 5 |
| Query fails with an empty error message | 3 |
| File ends in a comment with no trailing newline | 1 |

The same `some k, v in` form works in object comprehensions and in rule bodies.

### Decisions

Every package that loads was evaluated as `data.<package>` with an empty input under both
engines. Of 695 packages, 609 are identical, 41 differ only in ordering, timestamps or the last
digit of a float, **42 reach different decisions or values**, and 3 make regopy emit invalid
JSON. Only empty input was compared; identical output there does not prove identical behaviour
on real input.

The causes, each reproduced with a minimal module:

1. **`not` over an expression with an undefined argument is true in regopy.** In OPA,
   `not "vsftpd" in input.packages` with no `input.packages` leaves the rule undefined (the
   argument is undefined, so the body fails). regopy evaluates the negation as `true`. The same
   holds for `not contains(input.missing, "x")` and `not to_number("abc") > 0`. In this library
   that turns "package must not be installed" checks into passes on a host whose package list
   was never collected (**fail-open**), and fires violations OPA does not (stricter) in others.
   `not input.missing` behaves the same in both engines.
2. **A multi-line array literal inside a comprehension evaluates to empty.**
   `[r | r := [\n a == 1,\n b == 2,\n][_]; r]` returns `[]` in regopy; the same expression on one
   line returns the expected values. Scores and counts built this way come out as zero.
3. **Built-in functions regopy does not implement compile without error and evaluate to
   undefined.** OPA rejects an unknown function at compile time; regopy does not, so a missing
   built-in silently makes the rule undefined. Confirmed undefined in 1.5.2: `time.parse_rfc3339_ns`,
   `time.parse_ns`, `time.format`, `time.date`, `time.clock`, `time.weekday`, `time.add_date`,
   `time.diff`, `net.cidr_contains`, `net.cidr_merge`, `net.cidr_is_valid`,
   `strings.render_template`, `json.verify_schema`, `rego.metadata.rule`. In this library, 33
   policy files call at least one of them (32 call `time.parse_rfc3339_ns`).
4. **Smaller differences:** `sprintf("%q", …)` returns the literal `%q`; sets iterate in insertion
   order rather than sorted order (visible through `concat` and comprehensions); old
   `x { … }` rules without `if` are accepted.

### Tests

Almost all of the library's ~860 test files use `with input as`, mostly as
`r := pkg.rule with input as {...}` or `pkg.rule.field with input as {...}`. regopy 1.5.2 does
not compile either form ("shape `rego-localref` has no field `rego-refhead`"); a bare
`pkg.rule with input as {...}` works. The test suite therefore cannot be used to validate the
library on regopy; the comparison above was done by direct evaluation instead.

## If you target rego-cpp anyway

Not a supported configuration, but if a policy must run on rego-cpp 1.5.2:

- Build sets and arrays from object keys instead of `some k, v in`:
  `{k | some k in object.keys(o)}`, `[o[k] | some k in object.keys(o)]`.
- Guard every negation over input with an explicit presence check, so both engines agree:
  `is_array(input.packages)` before `not "vsftpd" in input.packages`. This is also the safer
  pattern on OPA, because it makes "not collected" a distinct, visible outcome.
- Keep array literals inside comprehensions on one line, or build them outside the comprehension.
- Avoid the built-ins listed above; for RFC 3339 timestamps there is no drop-in replacement.
- Don't rely on set iteration order; sort explicitly.
- End every file with a newline.
- Validate decisions with real inputs on both engines; this library's tests will not run there.

## Revision history

| Version | Date | Change |
|---|---|---|
| v1.0 | 2026-10-16 | First version: supported engines; regopy 1.5.2 results; authoring guidance |
