#!/usr/bin/env python3
"""Generate the GitHub Pages catalog (index.html) from the repository tree.

Walks the policy directories, counts non-test .rego files per framework, and emits a
browse-by-standard catalog with live coverage counts and one-click links to each module.
Run from the repo root:  python3 scripts/gen_pages_catalog.py

The counts are read from the working tree, so the published catalog stays current: run
this in CI or before a release and commit the regenerated index.html.
"""
import os
import re
import subprocess

REPO = "ynotbhatc/rego_policy_libraries"
BRANCH = "main"
GSV = "7fdd8b57bc74ab1a"  # google-site-verification (do not lose)
TREE = f"https://github.com/{REPO}/tree/{BRANCH}"

ACRONYMS = {
    "rhel", "cis", "stig", "nist", "iso", "soc", "pci", "dss", "sox", "gdpr", "hipaa",
    "ccpa", "cpra", "nerc", "cip", "iec", "ami", "dora", "nis2", "ncsc", "caf", "csa",
    "ccm", "cobit", "glba", "itar", "tsa", "cmmc", "fisma", "fedramp", "sles", "ms",
    "sql", "aws", "gcp", "api", "mcp", "ai", "eu", "oidc", "finops", "geisa", "sbom",
    "slsa", "os", "ir", "sp", "rmf", "swift", "csp", "dfs", "sec", "ny", "cfr", "vee",
    "adm", "lee", "ios", "xe", "pims", "aims",
}
OVERRIDES = {
    "rhel_9": "RHEL 9", "rhel_8": "RHEL 8", "rhel_10": "RHEL 10",
    "iso27001": "ISO 27001", "iso27701": "ISO 27701", "iso_42001": "ISO 42001",
    "soc2": "SOC 2", "pci_dss": "PCI-DSS", "nist_800_82": "NIST 800-82",
    "sp_800_53": "NIST SP 800-53", "sp_800_171": "NIST SP 800-171",
    "nerc_cip": "NERC-CIP", "iec_62443": "IEC 62443", "eu_ai_act": "EU AI Act",
    "csa_ccm": "CSA CCM", "cisa_cpg": "CISA CPG", "tsa_pipeline": "TSA Pipeline",
    "ncsc_caf": "NCSC CAF", "amazon_linux_2023": "Amazon Linux 2023",
    "ubuntu_22_04": "Ubuntu 22.04", "ubuntu_24_04": "Ubuntu 24.04",
    "ubuntu_20_04": "Ubuntu 20.04", "windows_server_2022_modular": "Windows Server 2022",
    "windows_server_2019_modular": "Windows Server 2019", "windows_server_2025": "Windows Server 2025",
    "windows_11": "Windows 11", "windows_10": "Windows 10", "sles_15": "SLES 15",
    "vmware_vsphere_8": "vSphere 8 ESXi", "ms_sql_2016": "SQL Server 2016",
    "postgresql_16": "PostgreSQL 16", "openshift_4": "OpenShift 4",
    "cisco_ios_xe_router": "Cisco IOS-XE", "apache_2_4_unix": "Apache 2.4",
    "network_devices": "Network Devices", "saas": "SaaS (M365, Google WS)",
    "nist_ir7628": "NIST IR 7628 (AMI)", "rocky_linux_9": "Rocky Linux 9",
    "rocky_linux_8": "Rocky Linux 8", "debian_11": "Debian 11",
    "mysql": "MySQL", "postgresql": "PostgreSQL", "openshift": "OpenShift",
    "vmware": "VMware", "windows_server_2022": "Windows Server 2022 (legacy)",
    "web_servers": "Web Servers", "mobile_devices": "Mobile Devices",
    "network": "Network Devices (CIS)", "os": "OS (cross-platform)",
}


def label(name):
    if name in OVERRIDES:
        return OVERRIDES[name]
    parts = re.split(r"[_\-]", name)
    out = []
    for p in parts:
        out.append(p.upper() if p.lower() in ACRONYMS else p.capitalize())
    return " ".join(out)


def count_policies(path):
    if not os.path.isdir(path):
        return 0
    n = 0
    for root, _, files in os.walk(path):
        for f in files:
            if f.endswith(".rego") and not f.startswith("test_") and not f.endswith("_test.rego"):
                n += 1
    return n


def children(base):
    if not os.path.isdir(base):
        return []
    rows = []
    for d in sorted(os.listdir(base)):
        full = os.path.join(base, d)
        if not os.path.isdir(full) or d.startswith("_") or d.startswith("."):
            continue
        c = count_policies(full)
        if c > 0:
            rows.append((label(d), c, full))
    return sorted(rows, key=lambda r: -r[1])


SECTIONS = [
    ("CIS Benchmarks", "OS, cloud, container, database & network hardening", "benchmarks/cis"),
    ("DISA STIGs", "DoD Security Technical Implementation Guides", "benchmarks/stig"),
    ("Federal (US)", "NIST, FISMA, FedRAMP, CMMC, CISA CPG", "frameworks/federal"),
    ("Critical Infrastructure / OT", "NERC-CIP, IEC 62443, AMI, TSA Pipeline, NIST 800-82", "frameworks/critical_infrastructure"),
    ("Management Systems", "ISO 27001, SOC 2, CSA CCM, COBIT", "frameworks/management"),
    ("Financial", "PCI-DSS, SOX, GLBA", "frameworks/financial"),
    ("Privacy", "GDPR, HIPAA, CCPA/CPRA, ISO 27701", "frameworks/privacy"),
    ("Sector & Regional", "DORA, NIS2, NCSC CAF, NY DFS, SEC, SWIFT", "frameworks/compliance"),
    ("Regulatory", "ITAR and other regulatory regimes", "frameworks/regulatory"),
    ("Digital Sovereignty", "Data residency and sovereignty domains", "frameworks/sovereignty"),
    ("AI & MCP Governance", "EU AI Act, ISO 42001, agent authorization, MCP tool-call gating", "governance"),
    ("Enforcement Gates", "Ansible, Terraform, Dockerfile, Kubernetes, CI/CD, SLSA", "enforcement"),
    ("Threat Detection", "Behavioral detection policies", "threat_detection"),
]


def main():
    total = count_policies("benchmarks") + count_policies("frameworks") + \
        count_policies("governance") + count_policies("enforcement") + count_policies("threat_detection")
    framework_count = sum(len(children(b)) for _, _, b in SECTIONS)

    cards = []
    for title, blurb, base in SECTIONS:
        rows = children(base)
        if not rows:
            continue
        sect_total = sum(c for _, c, _ in rows)
        items = "\n".join(
            f'        <a class="mod" href="{TREE}/{p}" data-name="{nm.lower()}">'
            f'<span class="mod-name">{nm}</span><span class="mod-count">{c}</span></a>'
            for nm, c, p in rows
        )
        cards.append(f'''    <section class="cat" data-search="{(title + ' ' + blurb).lower()}">
      <div class="cat-head">
        <h2>{title} <span class="cat-total">{sect_total}</span></h2>
        <p>{blurb}</p>
      </div>
      <div class="mods">
{items}
      </div>
    </section>''')

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="google-site-verification" content="{GSV}" />
  <title>Rego Policy Libraries — Browse {total}+ OPA Compliance Policies by Standard</title>
  <meta name="description" content="Browse {total}+ production-ready Open Policy Agent (OPA) Rego policies by standard: CIS Benchmarks, DISA STIGs, NIST, NERC-CIP, IEC 62443, ISO 27001, SOC 2, PCI-DSS, EU AI Act and 55+ frameworks. Apache 2.0, Rego v1, OCI-ready.">
  <style>
    :root {{ --ink:#1b202b; --muted:#5c6573; --line:#d0d7de; --page:#ffffff; --card:#f6f8fa; --accent:#1f6feb; --accent2:#0f8f83; }}
    * {{ box-sizing:border-box; }}
    body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; color:var(--ink); background:var(--page); margin:0; line-height:1.5; }}
    .wrap {{ max-width:1040px; margin:0 auto; padding:0 20px 64px; }}
    header {{ background:linear-gradient(160deg,#0d1117,#1f2a44); color:#fff; padding:44px 20px 36px; }}
    header .wrap {{ padding-bottom:0; }}
    h1 {{ font-size:2.1em; margin:0 0 8px; letter-spacing:-.02em; }}
    .tag {{ color:#c9d4e6; font-size:1.05em; max-width:70ch; margin:0 0 18px; }}
    .stats {{ display:flex; gap:26px; flex-wrap:wrap; margin-top:10px; }}
    .stat b {{ display:block; font-size:1.7em; line-height:1; }}
    .stat span {{ color:#9db0cc; font-size:.85em; text-transform:uppercase; letter-spacing:.05em; }}
    .cta {{ margin-top:22px; display:flex; gap:10px; flex-wrap:wrap; }}
    .cta a {{ background:#fff; color:#12213b; text-decoration:none; font-weight:600; padding:9px 16px; border-radius:7px; font-size:.92em; }}
    .cta a.ghost {{ background:transparent; color:#fff; border:1px solid #46587a; }}
    pre {{ background:#0b0f17; color:#d7e0ee; border-radius:8px; padding:16px; overflow-x:auto; font-size:.86em; margin:22px 0 0; }}
    .search {{ position:sticky; top:0; background:var(--page); padding:18px 0 10px; border-bottom:1px solid var(--line); z-index:5; }}
    .search input {{ width:100%; padding:12px 14px; font-size:1em; border:1.5px solid var(--line); border-radius:9px; }}
    .cat {{ margin-top:30px; }}
    .cat-head h2 {{ font-size:1.28em; margin:0 0 2px; }}
    .cat-total {{ background:var(--accent); color:#fff; font-size:.6em; vertical-align:middle; border-radius:20px; padding:3px 9px; margin-left:6px; }}
    .cat-head p {{ color:var(--muted); margin:0 0 12px; font-size:.92em; }}
    .mods {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(230px,1fr)); gap:8px; }}
    .mod {{ display:flex; justify-content:space-between; align-items:center; gap:10px; text-decoration:none; color:var(--ink); background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px 13px; transition:border-color .12s,transform .12s; }}
    .mod:hover {{ border-color:var(--accent); transform:translateY(-1px); }}
    .mod-name {{ font-weight:600; font-size:.93em; }}
    .mod-count {{ background:#fff; border:1px solid var(--line); color:var(--muted); border-radius:20px; padding:1px 9px; font-size:.8em; font-variant-numeric:tabular-nums; }}
    .empty {{ color:var(--muted); padding:30px 0; display:none; }}
    footer {{ border-top:1px solid var(--line); margin-top:48px; padding-top:20px; color:var(--muted); font-size:.9em; }}
    footer a {{ color:var(--accent); text-decoration:none; }}
    @media (prefers-color-scheme:dark) {{
      :root {{ --ink:#e6edf3; --muted:#9198a1; --line:#30363d; --page:#0d1117; --card:#161b22; }}
      .mod-count {{ background:#0d1117; }}
      .cta a {{ background:#e6edf3; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <h1>Rego Policy Libraries</h1>
      <p class="tag">Browse {total}+ production-ready OPA Rego policies by standard — load one framework or the whole library. Rego v1, vendor-neutral, fail-closed, Apache&nbsp;2.0.</p>
      <div class="stats">
        <div class="stat"><b>{total}+</b><span>Policies</span></div>
        <div class="stat"><b>{framework_count}+</b><span>Standards</span></div>
        <div class="stat"><b>13</b><span>DISA STIG platforms</span></div>
        <div class="stat"><b>v1</b><span>Rego syntax</span></div>
      </div>
      <div class="cta">
        <a href="https://github.com/{REPO}">GitHub repo</a>
        <a class="ghost" href="https://github.com/{REPO}/blob/{BRANCH}/README.md">README</a>
        <a class="ghost" href="https://github.com/{REPO}/releases">Releases</a>
        <a class="ghost" href="https://github.com/{REPO}/discussions">Discussions</a>
      </div>
<pre>oras pull ghcr.io/{REPO}:latest   # OCI bundle, no clone
# every framework: data.&lt;package&gt;.main.compliance_report</pre>
    </div>
  </header>
  <div class="wrap">
    <div class="search"><input id="q" type="search" placeholder="Filter by standard — e.g. NERC, STIG, ISO, RHEL, AI…" autocomplete="off"></div>
    <p class="empty" id="empty">No standard matches that filter.</p>
{chr(10).join(cards)}
    <footer>
      Part of the <a href="https://github.com/ynotbhatc/compliance">Ansible Automated Compliance (AAC)</a> platform ·
      Apache 2.0 · generated from the repository tree, so counts stay current ·
      <a href="https://github.com/{REPO}/blob/{BRANCH}/CONTRIBUTING.md">Contributing</a> ·
      <a href="https://github.com/{REPO}/issues?q=is%3Aopen+label%3A%22good+first+issue%22">Good first issues</a>
    </footer>
  </div>
  <script>
    var q = document.getElementById('q'), cats = document.querySelectorAll('.cat'), empty = document.getElementById('empty');
    q.addEventListener('input', function () {{
      var t = q.value.trim().toLowerCase(), shown = 0;
      cats.forEach(function (cat) {{
        var mods = cat.querySelectorAll('.mod'), any = false;
        var catMatch = cat.getAttribute('data-search').indexOf(t) !== -1;
        mods.forEach(function (m) {{
          var hit = !t || catMatch || m.getAttribute('data-name').indexOf(t) !== -1;
          m.style.display = hit ? '' : 'none';
          if (hit) any = true;
        }});
        cat.style.display = any ? '' : 'none';
        if (any) shown++;
      }});
      empty.style.display = shown ? 'none' : 'block';
    }});
  </script>
</body>
</html>
'''
    with open("index.html", "w") as f:
        f.write(html)
    print(f"wrote index.html — {total} policies, {framework_count} standards across {len(SECTIONS)} sections")


if __name__ == "__main__":
    main()
