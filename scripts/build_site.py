#!/usr/bin/env python3
"""Generate one GitHub Pages page per standard, plus sitemap.xml and robots.txt.

    python3 scripts/build_site.py

WHY THIS EXISTS
---------------
The repository is found by referral, not by search: 4 unique visitors arrived
from Google, Bing and Brave combined over 14 days. That is not a backlink
problem, it is a surface-area problem. Nobody searches "rego policy library" —
they search "CIS RHEL 9 rego policy" or "NERC CIP policy as code". A single
landing page cannot rank for two dozen different standards; a page per standard
can.

Pages are written to standard/<slug>.html, listed in sitemap.xml, and linked
from the landing page so a crawler can reach them.
"""

import html
import pathlib
import re
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = "https://ynotbhatc.github.io/rego_policy_libraries"
REPO = "https://github.com/ynotbhatc/rego_policy_libraries/blob/main"
OUTDIR = ROOT / "standard"
MIN_POLICIES = 4          # below this a page is too thin to be worth indexing

# Display names and search-intent descriptions for the standards that people
# actually search for. Anything not listed falls back to a derived title.
NAMES = {
    "benchmarks/cis/rhel_9": ("CIS RHEL 9", "CIS Benchmark for Red Hat Enterprise Linux 9"),
    "benchmarks/cis/rhel_8": ("CIS RHEL 8", "CIS Benchmark for Red Hat Enterprise Linux 8"),
    "benchmarks/cis/rhel_10": ("CIS RHEL 10", "CIS Benchmark for Red Hat Enterprise Linux 10"),
    "benchmarks/cis/ubuntu_22_04": ("CIS Ubuntu 22.04", "CIS Benchmark for Ubuntu 22.04 LTS"),
    "benchmarks/cis/ubuntu_24_04": ("CIS Ubuntu 24.04", "CIS Benchmark for Ubuntu 24.04 LTS"),
    "benchmarks/cis/ubuntu_20_04": ("CIS Ubuntu 20.04", "CIS Benchmark for Ubuntu 20.04 LTS"),
    "benchmarks/cis/debian_11": ("CIS Debian 11", "CIS Benchmark for Debian 11"),
    "benchmarks/cis/rocky_linux_8": ("CIS Rocky Linux 8", "CIS Benchmark for Rocky Linux 8"),
    "benchmarks/cis/rocky_linux_9": ("CIS Rocky Linux 9", "CIS Benchmark for Rocky Linux 9"),
    "benchmarks/cis/amazon_linux_2023": ("CIS Amazon Linux 2023", "CIS Benchmark for Amazon Linux 2023"),
    "benchmarks/cis/saas": ("CIS Microsoft 365", "CIS Benchmark for Microsoft 365 (SaaS)"),
    "benchmarks/cis/cloud": ("CIS Cloud Foundations", "CIS Foundations Benchmarks for AWS, Azure and GCP"),
    "benchmarks/cis/container": ("CIS Docker and Kubernetes", "CIS Benchmarks for Docker and Kubernetes"),
    "benchmarks/cis/openshift": ("CIS OpenShift", "CIS Benchmark for Red Hat OpenShift"),
    "benchmarks/cis/network_devices": ("CIS Network Devices", "CIS Benchmarks for Cisco IOS and network devices"),
    "benchmarks/cis/nginx": ("CIS NGINX", "CIS Benchmark for NGINX"),
    "benchmarks/cis/vmware": ("CIS VMware", "CIS Benchmarks for ESXi and vCenter"),
    "benchmarks/stig": ("DISA STIG", "DISA Security Technical Implementation Guides"),
    "frameworks/federal/nist": ("NIST", "NIST 800-53, 800-171, CSF and RMF"),
    "frameworks/federal/fisma": ("FISMA", "Federal Information Security Modernization Act"),
    "frameworks/federal/fedramp": ("FedRAMP", "Federal Risk and Authorization Management Program"),
    "frameworks/federal/cmmc": ("CMMC", "Cybersecurity Maturity Model Certification"),
    "frameworks/financial/pci_dss": ("PCI-DSS", "Payment Card Industry Data Security Standard"),
    "frameworks/financial/sox": ("SOX", "Sarbanes-Oxley IT general controls"),
    "frameworks/financial/dora": ("DORA", "EU Digital Operational Resilience Act"),
    "frameworks/management/iso27001": ("ISO 27001", "ISO/IEC 27001 information security management"),
    "frameworks/management/soc2": ("SOC 2", "SOC 2 Trust Services Criteria"),
    "frameworks/management/csa_ccm": ("CSA CCM", "Cloud Security Alliance Cloud Controls Matrix"),
    "frameworks/management/hitrust": ("HITRUST", "HITRUST CSF"),
    "frameworks/privacy/gdpr": ("GDPR", "EU General Data Protection Regulation"),
    "frameworks/privacy/hipaa": ("HIPAA", "HIPAA Security Rule"),
    "frameworks/privacy/ccpa": ("CCPA / CPRA", "California Consumer Privacy Act"),
    "frameworks/critical_infrastructure/nerc_cip": ("NERC-CIP", "NERC Critical Infrastructure Protection, CIP-002 to CIP-015"),
    "frameworks/critical_infrastructure/iec_62443": ("IEC 62443", "IEC 62443 industrial automation and control systems security"),
    "frameworks/critical_infrastructure/tsa_pipeline": ("TSA Pipeline", "TSA Pipeline Security Directives"),
    "frameworks/critical_infrastructure/ami": ("AMI / NIST IR 7628", "Advanced Metering Infrastructure and smart grid security"),
    "frameworks/compliance/cra": ("EU Cyber Resilience Act", "Regulation (EU) 2024/2847"),
    "frameworks/compliance/nis2": ("NIS2", "EU Network and Information Security Directive 2"),
    "frameworks/compliance/ncsc_caf": ("NCSC CAF", "UK NCSC Cyber Assessment Framework"),
    "frameworks/sovereignty/digital_sovereignty": ("Digital Sovereignty", "Data residency, encryption and sovereignty controls"),
    "governance/eu_ai_act": ("EU AI Act", "EU Artificial Intelligence Act"),
    "governance/ai": ("AI Governance", "AI system governance and authorization controls"),
    "governance/mcp": ("MCP Governance", "Model Context Protocol tool-call governance"),
    "governance/geisa": ("GEISA", "Grid Edge Interoperability and Security Architecture"),
    "enforcement/ansible": ("Ansible Policy Enforcement", "Gating Ansible playbooks and AAP job launches"),
    "enforcement/terraform": ("Terraform Policy Enforcement", "Gating Terraform plans"),
    "enforcement/kubernetes": ("Kubernetes Policy Enforcement", "Gating Kubernetes manifests"),
}


def is_test(p):
    return p.name.startswith("test_") or p.name.endswith("_test.rego")


def package_of(p):
    m = re.search(r"^package\s+([\w.]+)", p.read_text(errors="ignore"), re.M)
    return m.group(1) if m else ""


def slug(key):
    return key.replace("/", "-").replace("_", "-")


def page(title, desc, canonical, body, css):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<meta name="description" content="{html.escape(desc)}">
<link rel="canonical" href="{canonical}">
<meta property="og:title" content="{html.escape(title)}">
<meta property="og:description" content="{html.escape(desc)}">
<meta property="og:type" content="website">
<meta property="og:url" content="{canonical}">
<style>{css}</style>
</head>
<body>
{body}
</body>
</html>
"""


def main():
    css = (ROOT / "index.html").read_text()
    m = re.search(r"<style>(.*?)</style>", css, re.S)
    css = m.group(1).strip() if m else ""

    groups = defaultdict(list)
    for p in sorted(ROOT.rglob("*.rego")):
        rel = p.relative_to(ROOT)
        if rel.parts[0] not in ("benchmarks", "frameworks", "governance",
                                "enforcement", "threat_detection"):
            continue
        if is_test(p):
            continue
        key = "/".join(rel.parts[:3]) if len(rel.parts) > 3 else "/".join(rel.parts[:2])
        groups[key].append(rel)

    OUTDIR.mkdir(exist_ok=True)
    built = []
    for key, files in sorted(groups.items()):
        if len(files) < MIN_POLICIES:
            continue
        name, blurb = NAMES.get(key, (key.split("/")[-1].replace("_", " ").title(),
                                      f"{key} policies"))
        title = f"{name} Rego Policies for Open Policy Agent (OPA)"
        desc = (f"{len(files)} open-source Rego policies encoding {blurb}. "
                f"Apache 2.0, Rego v1, ready to load into OPA or Enterprise OPA.")
        s = slug(key)
        canonical = f"{SITE}/standard/{s}.html"

        rows = "\n".join(
            f'<li><a href="{REPO}/{f}"><code>{f.name}</code></a> '
            f'<span style="opacity:.7">{package_of(ROOT / f)}</span></li>'
            for f in sorted(files))

        body = f"""<h1>{html.escape(name)} — Rego Policies for OPA</h1>
<p>{html.escape(desc)}</p>

<h2>What this is</h2>
<p><strong>{len(files)} Rego policy files</strong> encoding {html.escape(blurb)}, part of the
<a href="{SITE}/">Rego Policy Libraries</a> — a standalone, dependency-free
collection of Open Policy Agent policies for published security and compliance
standards. No orchestrator, no agent, no vendor runtime.</p>

<h2>Load and query it</h2>
<pre><code>git clone https://github.com/ynotbhatc/rego_policy_libraries.git
opa eval -d rego_policy_libraries/{key} -f pretty 'data'</code></pre>
<p>Or load into a running OPA:</p>
<pre><code>for f in rego_policy_libraries/{key}/*.rego; do
  curl -X PUT --data-binary @"$f" "$OPA/v1/policies/$(basename $f .rego)"
done</code></pre>

<h2>Two ways to use these policies</h2>
<p><strong>Gating a change of state</strong> — evaluate a proposed action before it
proceeds, and refuse it if it violates the standard. <strong>Measuring state</strong> —
evaluate collected facts about an environment against the standard to produce
compliance evidence. The same policy content serves both; only the integration
differs.</p>

<h2>Policy modules</h2>
<ul>
{rows}
</ul>

<h2>Contributing</h2>
<p>Test coverage is published in
<a href="{REPO}/COVERAGE.md">COVERAGE.md</a>, and uncovered policies are the best
first contribution — each is small, self-contained, and either passes
<code>opa test</code> or does not. See
<a href="{REPO}/CONTRIBUTING.md">CONTRIBUTING.md</a>.</p>

<h2>Links</h2>
<ul>
<li><a href="https://github.com/ynotbhatc/rego_policy_libraries">Repository</a> (Apache 2.0)</li>
<li><a href="{SITE}/">All standards</a></li>
<li><a href="https://www.openpolicyagent.org/">Open Policy Agent</a></li>
</ul>
"""
        (OUTDIR / f"{s}.html").write_text(page(title, desc, canonical, body, css))
        built.append((s, name, len(files)))

    # sitemap
    urls = [f"{SITE}/"] + [f"{SITE}/standard/{s}.html" for s, _, _ in built]
    sm = ['<?xml version="1.0" encoding="UTF-8"?>',
          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for u in urls:
        sm.append(f"  <url><loc>{u}</loc></url>")
    sm.append("</urlset>")
    (ROOT / "sitemap.xml").write_text("\n".join(sm) + "\n")

    (ROOT / "robots.txt").write_text(
        "User-agent: *\nAllow: /\n\n" f"Sitemap: {SITE}/sitemap.xml\n")

    # index of standards, for crawlers and humans
    items = "\n".join(
        f'<li><a href="{s}.html">{html.escape(n)}</a> '
        f'<span style="opacity:.7">{c} policies</span></li>'
        for s, n, c in sorted(built, key=lambda x: x[1]))
    body = f"""<h1>Standards covered</h1>
<p>{len(built)} standards, each with its own page listing the policy modules and
how to load them. Part of the
<a href="{SITE}/">Rego Policy Libraries</a>.</p>
<ul>
{items}
</ul>
"""
    (OUTDIR / "index.html").write_text(page(
        "Compliance Standards Covered by Rego Policy Libraries",
        f"{len(built)} security and compliance standards encoded as Open Policy Agent Rego policies.",
        f"{SITE}/standard/", body, css))

    print(f"built {len(built)} standard pages + index, sitemap ({len(urls)} urls), robots.txt")
    for s, n, c in sorted(built, key=lambda x: -x[2])[:10]:
        print(f"  {c:>3}  {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
