# CIS SaaS Benchmarks

Rego policies evaluating SaaS-tenant compliance against the CIS
Benchmarks family of SaaS-specific guidance. Unlike the OS / cloud
benchmarks elsewhere in this library, SaaS benchmarks operate on
**tenant-level state** pulled from the vendor's admin API rather
than per-host facts.

| Subdirectory | Benchmark | Vendor admin API |
|---|---|---|
| [`m365_v7/`](m365_v7/) | CIS Microsoft 365 Foundations Benchmark **v7.0.0** | Microsoft Graph |
| [`m365/`](m365/) | v3.1.0 — **DEPRECATED**, control ids do not match the benchmark | Microsoft Graph |

Companion fact-gathering Ansible modules live in the **AAC
compliance repo** at `collections/ansible_collections/aac/<vendor>/`.
This library only holds the Rego — the evaluation logic. Where the
state comes from is the Ansible side's concern.

Each subdirectory ships a per-vendor README documenting the
benchmark version, the section breakdown, and any Graph (or
equivalent) coverage gaps.
