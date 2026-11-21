# Mutation testing and golden cases

Two ways to check that a module's tests check something (issues #305 and #306).

## Mutation testing (`scripts/mutation_test.py`)

A mutant is the module with one small change. The script writes each mutant into a scratch copy of the module
directory and runs that directory's tests. A failing test kills the mutant. A mutant that every test still passes
survives: the tests never noticed that change to the rule.

```bash
make mutation MODULE=frameworks/financial/pci_dss/access_control
make mutation MODULE=benchmarks/cis/rhel_9 ARGS="--file ssh_validation.rego --json /tmp/cis_ssh.json"
python3 scripts/mutation_test.py benchmarks/stig/rhel_9 --ops eq,bound --jobs 8
```

| operator | change |
|---|---|
| `eq` | `==` to `!=` and back |
| `bound` | `>=` to `>`, `<=` to `<`, `>` to `>=`, `<` to `<=` |
| `bool` | `true` to `false` and back |
| `not` | drop one `not` |
| `drop` | delete one expression line of a rule body |

The report gives the kill score (killed / (killed + survived)) and lists every survivor as `file:line [op]
original -> mutant`. Comments and string literals are never mutated. Two kinds of mutant are left out of the score.
A mutant that no longer compiles counts as `invalid`. A run in which a test hit `--timeout` counts as `timeout`;
that usually means a loaded machine, so rerun with fewer `--jobs`.

How to use it:

- Only the tests inside MODULE run. Tests elsewhere, such as `frameworks/federal/nist/sp_800_53/tests/`, do not count
  toward the module's score.
- Some survivors are equivalent mutants. These are changes that cannot alter any result, such as dropping a guard
  that a later line repeats, or `>=` to `>` on a value that can never equal the bound. Read the survivor list. Do not
  aim for 100%.
- A survivor in a `default x := false` line, or a `drop` survivor in a list of controls, usually means no test
  starts from a passing configuration and breaks one element. That one-element test is the usual fix (see
  `frameworks/financial/pci_dss/access_control/tests/test_requirements_7_8_mutation_kills.rego`).
- The script is not wired into CI. A module of a few thousand lines makes about a thousand mutants, and the CIS
  RHEL 9 directory runs 1,586 tests per mutant. Use `--file` to narrow the run to one policy file.

## Golden cases (from the standard's own text)

A golden case writes down what the standard itself says passes and fails. It catches a wrong value, such as a
threshold copied wrong, that a test derived from the rule would copy too. Use them only where the text may be
reused:

- **NIST SP 800-53** is public domain. The cases quote the control statement in the OSCAL catalog, for example
  `frameworks/federal/nist/sp_800_53/access_control/tests/test_golden_ac_nist_text.rego`.
- **DISA STIG** check text is a US Government work. The cases use the command output the check text shows as the
  pass case and the "If ... this is a finding" condition as the fail case, for example
  `benchmarks/stig/rhel_9/tests/test_golden_stig_rhel9_check_text.rego`.
- **CIS, PCI DSS, ISO and other licensed text:** cite the id only and never quote it.

Each case cites the control or rule id and quotes at most one short phrase. When a golden case disagrees with the
rule, do not change the case to match. Report it, because the disagreement is what the case exists to find.
