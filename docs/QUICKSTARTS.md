# Quick starts: one sample input per platform

Each directory under [`examples/`](../examples/) holds a fictional `facts.json` in the shape one framework key reads,
a README that explains the result line by line, and a `check.sh` that asserts the exact result so the sample cannot
drift from the policy. Nothing in them comes from a real machine or tenant. Every sample is mostly compliant with a
few ordinary gaps, so the output shows both passes and findings.

You need [OPA](https://www.openpolicyagent.org/docs/) (and `python3` for `check.sh`). Run every command from the
repository root.

## Five minutes

1. Pick a platform from the table and run its command. The report's `violations` list is the to-do list: each line
   starts with the control id.
2. Open the example's README and fix one of the listed gaps in `facts.json`. Run the command again: the failed count
   drops by one.
3. Delete a section from `facts.json`. The controls that read it do not pass; they fail with `evidence missing`,
   because a fact that was not collected is not a fact that passed. (PCI DSS is the exception today: a missing
   section fails its requirement without saying `evidence missing`.)
4. Run the example's `check.sh` to confirm you are back on the documented result (`git checkout examples/` first).
5. Point `-i` at your own facts to assess your own system.

## The samples

| platform | framework key | command | headline |
|---|---|---|---|
| [RHEL 9 server](../examples/rhel9/) | `cis_rhel9` | `opa eval -d benchmarks/cis/rhel_9 -i examples/rhel9/facts.json -f pretty 'data.cis_rhel9.main.compliance_report'` | 25 of 352 controls fail, none evidence missing |
| [Windows Server 2022](../examples/cis_windows_2022/) | `cis_windows_2022` | `opa eval -d benchmarks/cis/windows_server_2022_modular --ignore tests -i examples/cis_windows_2022/facts.json -f pretty 'data.cis_windows_2022.main.compliance_report'` | 5 of 378 applicable controls fail (Level 2 member server), none evidence missing |
| [Microsoft 365 tenant](../examples/cis_m365_v7/) | `cis_m365_v7` | `opa eval -d benchmarks/cis/saas/m365_v7 --ignore tests -i examples/cis_m365_v7/facts.json -f pretty 'data.cis_m365_v7.main.compliance_report'` | 6 of 160 controls fail (E5 Level 2), none evidence missing |
| [NIST SP 800-53, Access Control family](../examples/nist_800_53/) | `nist.sp800_53.access_control` | `opa eval -d frameworks/federal/nist/sp_800_53/access_control -i examples/nist_800_53/facts.json -f pretty 'data.nist.sp800_53.access_control.compliance_report'` | 5 of 61 AC controls fail, none evidence missing |
| [NIST SP 800-53, whole catalog, same input](../examples/nist_800_53/) | `nist_800_53` | `opa eval -d frameworks/federal/nist/sp_800_53 -i examples/nist_800_53/facts.json -f pretty 'data.nist_800_53.main.compliance_report'` | of 546 controls: 56 pass, 5 fail, 419 evidence missing (no facts for the other families), 66 not attested |
| [PCI DSS 4.0.1 merchant](../examples/pci_dss/) | `pci_dss` | `opa eval -d frameworks/financial/pci_dss -i examples/pci_dss/facts.json -f pretty 'data.pci_dss.main.compliance_report'` | 3 of 12 requirements fail (4 checks) |
| [Kubernetes cluster](../examples/cis_kubernetes/) | `cis_kubernetes` | `opa eval -d benchmarks/cis/kubernetes -i examples/cis_kubernetes/facts.json -f pretty 'data.cis_kubernetes.main.compliance_report'` | 7 of 134 controls fail, 2 of them evidence missing |
| [AWS account](../examples/cis_aws/) | `cis_aws` | `opa eval -d benchmarks/cis/aws -i examples/cis_aws/facts.json -f pretty 'data.cis_aws.main.compliance_report'` | 6 of 94 controls fail (Level 2), 1 of them evidence missing |

How far each framework has been run on real evidence (validated, partial or experimental) is in the label table in
[COVERAGE.md](../COVERAGE.md). A sample that evaluates cleanly shows the policy's input contract, not that the
module has been validated.

To check all samples at once:

```bash
for c in examples/*/check.sh; do bash "$c" || exit 1; done
```
