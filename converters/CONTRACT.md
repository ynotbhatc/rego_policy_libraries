# Converter contract

Every converter under `converters/` meets all of these before it is marked `shipping`.

1. **Control id and message, verbatim.** The violation message is the citation (`CIS 1.1.1: …`,
   `MAS TRM 9.1.5 …`). The target artefact carries it unchanged.
2. **Fail-closed semantics.** Absent evidence is a violation in every target that can express it. Targets that
   cannot (results formats such as OSCAL assessment-results, SARIF, OCSF) carry exactly what Rego evaluated and
   say so in their README.
3. **METADATA rides along.** `class`, `framework`, `source`, `domains` from the `# METADATA` block become tags,
   properties or labels in the target, whatever the format calls them.
4. **Generated, never hand-edited.** Output is produced by a script in the target's directory from the Rego
   tree at a release tag, and the script is idempotent. Hand edits to generated output are rejected in review.
5. **Round-trip test.** A fixture is evaluated by the Rego (via `opa eval`) and by the target engine or
   format; the set of violation ids must match. The test runs in `make check-converters` and in CI. A
   converter without a passing round-trip test does not ship.
6. **Coverage is stated, not implied.** The README lists which directories and how many control-level checks
   the converter covers (`scripts/count_controls.py <dir>`), and what it leaves out and why.
7. **Versioned with the library.** Output is tagged with the library release it came from
   (`v2.3.1`) and published with that release.
