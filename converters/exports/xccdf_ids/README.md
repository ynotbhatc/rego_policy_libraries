# CIS-CAT / XCCDF join table

**Status:** shipping
**Kind:** export (Tier 1, data)
**Covers:** the CIS host and SaaS modules (761 benchmark sections on 10 platforms)
**Consumers:** CIS-CAT Pro users who want to put their scan next to our evaluation

CIS-CAT names a rule `xccdf_org.cisecurity.benchmarks_rule_<section>_<Title_with_underscores>`. We carry
the section number ("CIS 1.3.1"); the title we do not, because the benchmark text is licensed. So
`dist/cis_xccdf_ids.csv` gives, per section the library evaluates: platform, Rego package, the benchmark name
and version the module declares, the section, our control id and OSCAL id, and the prefix to join on:

```
platform,rego_package,benchmark,benchmark_version,section,control_id,oscal_control_id,xccdf_rule_id_prefix,derived_from,rego_file
rhel_9,cis_rhel9.main,CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0,v2.0.0,1.3.1,CIS 1.3.1,cis_rhel_9-CIS-1.3.1,xccdf_org.cisecurity.benchmarks_rule_1.3.1_,,benchmarks/cis/rhel_9/...
```

Join: CIS-CAT rule id `startswith` `xccdf_rule_id_prefix`, same platform, same benchmark version. Modules that
are DERIVED from a sibling benchmark (Debian 11 from Ubuntu 20.04, Ubuntu 24.04 from 22.04) say so in
`derived_from`; a CIS-CAT scan against the platform's own benchmark will not share section numbers with the
sibling, so treat those rows as a hint, not a key.

`test/roundtrip.sh` proves every CIS section in the inventory appears once per platform, prefixes are
well-formed, every row carries a benchmark name, and RHEL 9 1.3.1 joins `..._rule_1.3.1_Ensure_AIDE_is_installed`.
