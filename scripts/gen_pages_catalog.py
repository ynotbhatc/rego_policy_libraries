#!/usr/bin/env python3
"""Generate the GitHub Pages catalog (index.html) from the repository tree.

scripts/build_site.py runs this first on every site build (CI runs it on every pull request), so
the homepage is regenerated with the rest of the site. The headline figures come from
build_site.figures(), the same README line and docs/metrics.json that CI verifies.

Walks the policy directories, counts non-test .rego files per framework, and emits a
browse-by-standard catalog with live coverage counts and one-click links to each module.
Run from the repo root:  python3 scripts/gen_pages_catalog.py
                         python3 scripts/gen_pages_catalog.py --check   # writes nothing; fails when a policy
                         # tree is in no section or the section counts do not add up to the README policy count

Every count on the page is policy files (scripts/rego_ast.policy_files, the README's definition), and the
sections must add up to the headline: reconcile() stops the build otherwise.

The counts are read from the working tree, so the published catalog stays current: run
this in CI or before a release and commit the regenerated index.html.
"""
import os
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

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
    "windows_10_modular": "Windows 10 Enterprise", "windows_11_modular": "Windows 11 Enterprise",
    "vmware_vsphere_8": "vSphere 8 ESXi", "ms_sql_2016": "SQL Server 2016",
    "postgresql_16": "PostgreSQL 16", "openshift_4": "OpenShift 4", "rke2": "RGS RKE2",
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


def _policy_files():
    """Every policy file, by the one definition the README count uses (scripts/rego_ast.policy_files: no tests,
    no tests/ directories, no converters/). The catalog counted with its own walk before, which is how its
    sections came to add up to less than the headline."""
    from rego_ast import policy_files
    return list(policy_files("."))


_POLICIES = None


def count_policies(path):
    """Policy files under path (a directory, counted recursively)."""
    global _POLICIES
    if _POLICIES is None:
        _POLICIES = _policy_files()
    prefix = str(path).rstrip("/") + "/"
    return sum(1 for rel in _POLICIES if rel.startswith(prefix))


def children(base):
    """(label, policy files, path) per sub-directory of base that holds policy files, plus one row for policy
    files that sit directly in base, so a section's rows always add up to count_policies(base)."""
    if not os.path.isdir(base):
        return []
    rows = []
    for d in sorted(os.listdir(base)):
        full = os.path.join(base, d)
        if not os.path.isdir(full) or d.startswith(".") or d == "tests":
            continue
        c = count_policies(full)
        if c > 0:
            rows.append((label(d.lstrip("_")), c, full))
    loose = count_policies(base) - sum(c for _, c, _ in rows)
    if loose > 0:
        rows.append((label(os.path.basename(base)), loose, base))
    return sorted(rows, key=lambda r: -r[1])


def section_rows(base):
    """Rows of one section. base is a directory (one row per sub-directory) or a list of (name, directory)
    pairs for a section that gathers several small trees (one row per tree)."""
    if isinstance(base, str):
        return children(base)
    return sorted(((name, count_policies(d), d) for name, d in base if count_policies(d) > 0), key=lambda r: -r[1])


def section_dirs(base):
    return [base] if isinstance(base, str) else [d for _, d in base]


# Every top-level policy tree must be in exactly one section: reconcile() fails the site build when a
# directory is added without one, so the per-section counts always add up to the headline policy count.
SECTIONS = [
    ("CIS Benchmarks", "OS, cloud, container, database & network hardening", "benchmarks/cis"),
    ("DISA STIGs", "DoD Security Technical Implementation Guides", "benchmarks/stig"),
    ("Federal & Kubernetes Hardening Baselines", "CISA SCuBA for Microsoft 365, NSA/CISA Kubernetes hardening, Pod Security Standards",
     [("CISA SCuBA M365", "benchmarks/scuba"), ("NSA/CISA Kubernetes Hardening", "benchmarks/nsa_cisa"),
      ("Kubernetes Pod Security Standards", "benchmarks/pss")]),
    ("Software Supply Chain", "SLSA, S2C2F, SSDF, NIST SP 800-161 overlays", "benchmarks/supply_chain"),
    ("Application Suite Baselines", "SAP Security Baseline (ABAP)", "benchmarks/sap"),
    ("Federal (US)", "NIST, FISMA, FedRAMP, CMMC, CISA CPG", "frameworks/federal"),
    ("Critical Infrastructure / OT", "NERC-CIP, IEC 62443, AMI, TSA Pipeline, NIST 800-82", "frameworks/critical_infrastructure"),
    ("Management Systems", "ISO 27001, SOC 2, CSA CCM, COBIT", "frameworks/management"),
    ("Financial", "PCI-DSS, SOX, DORA, GLBA, NY DFS, SEC, SWIFT", "frameworks/financial"),
    ("Privacy", "GDPR, HIPAA, CCPA/CPRA, ISO 27701", "frameworks/privacy"),
    ("EU & UK Cyber Regulation", "NIS2, Cyber Resilience Act, NCSC CAF", "frameworks/compliance"),
    ("Regional", "BSI C5, ACSC Essential Eight, UK Cyber Essentials, UK MoD DCC, CERT-In, METI", "frameworks/regional"),
    ("Regulatory", "ITAR and other regulatory regimes", "frameworks/regulatory"),
    ("Digital Sovereignty", "Data residency and sovereignty domains", "frameworks/sovereignty"),
    ("AI & MCP Governance", "EU AI Act, ISO 42001, agent authorization, MCP tool-call gating", "governance"),
    ("Enforcement Gates", "Ansible, Terraform, Dockerfile, Kubernetes, CI/CD, SLSA", "enforcement"),
    ("Crosswalks", "Control correlation between frameworks (STIG to NIST SP 800-53, framework overlays)", "crosswalk"),
    ("Threat Detection", "Behavioral detection policies", "threat_detection"),
]


def reconcile(headline=None):
    """Return a list of problems: policy files no section lists, a file listed twice, section rows that do not
    add up, or a section sum that differs from the headline policy count (the README figure CI verifies)."""
    global _POLICIES
    if _POLICIES is None:
        _POLICIES = _policy_files()
    problems = []
    dirs = [d.rstrip("/") + "/" for _, _, base in SECTIONS for d in section_dirs(base)]
    claimed = {rel: [d for d in dirs if rel.startswith(d)] for rel in _POLICIES}
    orphans = sorted(rel for rel, ds in claimed.items() if not ds)
    twice = sorted(rel for rel, ds in claimed.items() if len(ds) > 1)
    if orphans:
        trees = sorted({"/".join(rel.split("/")[:2]) for rel in orphans})
        problems.append(f"{len(orphans)} policy file(s) are in no catalog section; add a section for: {', '.join(trees)}")
    if twice:
        problems.append(f"{len(twice)} policy file(s) are in more than one catalog section, e.g. {twice[0]}")
    total = 0
    for title, _, base in SECTIONS:
        rows_sum = sum(c for _, c, _ in section_rows(base))
        want = sum(count_policies(d) for d in section_dirs(base))
        total += rows_sum
        if rows_sum != want:
            problems.append(f"section {title!r}: its rows add up to {rows_sum}, its directories hold {want}")
    if total != len(_POLICIES):
        problems.append(f"catalog sections add up to {total}, the tree holds {len(_POLICIES)} policy files")
    if headline is not None and total != headline:
        problems.append(f"catalog sections add up to {total}, the published headline says {headline} "
                        "(README count line; run scripts/count_controls.py --check-readme)")
    return problems


def main():
    # Headline figures are not counted here: they are the ones CI verifies (README count line and
    # docs/metrics.json, via build_site.figures), so the homepage cannot disagree with the README again.
    from build_site import GITHUB, LABEL_PAGE, SITE, SITE_NAME, coverage_labels, figures, label_badge, labels_under, social_head
    os.chdir(pathlib.Path(__file__).resolve().parent.parent)
    fig = figures()
    total, checks = fig["files"], fig["checks"]
    if "--check" in sys.argv:
        # no files written: only that every policy file is in exactly one section and the sections add up
        problems = reconcile(int(str(total).replace(",", "")))
        if problems:
            sys.exit("catalog sections do not reconcile with the policy count:\n  " + "\n  ".join(problems))
        print(f"catalog sections reconcile: {len(SECTIONS)} sections add up to {total} policy files")
        return
    stig_platforms = fig["stig_platforms"] or str(len(children("benchmarks/stig")))
    framework_count = sum(len(section_rows(b)) for _, _, b in SECTIONS)
    # the per-section counts are the same unit as the headline (policy files) and must add up to it
    problems = reconcile(int(str(total).replace(",", "")))
    if problems:
        sys.exit("scripts/gen_pages_catalog.py: catalog counts do not reconcile:\n  " + "\n  ".join(problems))

    label_rows = coverage_labels()   # one badge per card: the coverage label of the framework keys under it
    cards = []
    for title, blurb, base in SECTIONS:
        rows = section_rows(base)
        if not rows:
            continue
        sect_total = sum(c for _, c, _ in rows)
        items = "\n".join(
            f'        <a class="mod" href="{TREE}/{p}" data-name="{nm.lower()}">'
            f'<span class="mod-name">{nm}</span>{label_badge(labels_under(label_rows, p))}'
            f'<span class="mod-count">{c}</span></a>'
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

    title = f"{SITE_NAME} — Browse {total} OPA Compliance Policies by Standard"
    desc = (f"Browse {total} production-ready Open Policy Agent (OPA) Rego policies holding {checks} control-level checks, "
            f"by standard: CIS Benchmarks, DISA STIGs, NIST, NERC-CIP, IEC 62443, ISO 27001, SOC 2, PCI-DSS, EU AI Act: "
            f"{framework_count} standards in all. Apache 2.0, Rego v1, OCI-ready.")
    jsonld = {
        "@context": "https://schema.org",
        "@type": "SoftwareSourceCode",
        "name": SITE_NAME,
        "description": desc,
        "url": f"{SITE}/",
        "codeRepository": GITHUB,
        "license": "https://www.apache.org/licenses/LICENSE-2.0",
        "programmingLanguage": "Rego",
        "runtimePlatform": "Open Policy Agent",
    }
    if fig["version"]:
        jsonld["version"] = fig["version"]
    head = "\n".join("  " + line for line in social_head(title, desc, f"{SITE}/", jsonld).splitlines())
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="google-site-verification" content="{GSV}" />
  <title>{title}</title>
  <meta name="description" content="{desc}">
{head}
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
    .mod-name {{ font-weight:600; font-size:.93em; flex:1; }}
    .mod-count {{ background:#fff; border:1px solid var(--line); color:var(--muted); border-radius:20px; padding:1px 9px; font-size:.8em; font-variant-numeric:tabular-nums; }}
    .empty {{ color:var(--muted); padding:30px 0; display:none; }}
    .lbl {{ display:inline-block; font-size:.7rem; font-weight:600; letter-spacing:.03em; text-transform:uppercase; border-radius:20px; padding:1px 8px; vertical-align:middle; border:1px solid; white-space:nowrap; }}
    .lbl-validated {{ color:#0b6b46; background:#dcf5e8; border-color:#7fd1a8; }}
    .lbl-partial {{ color:#7a4d00; background:#fff1d1; border-color:#e8bf6a; }}
    .lbl-experimental {{ color:var(--muted); background:transparent; border-color:var(--line); }}
    .lbl-mixed {{ color:#3d4f9c; background:#e8ecfb; border-color:#a7b4ea; }}
    a.lbl-link {{ text-decoration:none; }}
    .mod .lbl {{ font-size:.6rem; padding:0 6px; }}
    .legend a {{ color:var(--accent); }}
    .legend {{ color:var(--muted); font-size:.9em; margin:14px 0 0; }}
    table {{ border-collapse:collapse; width:100%; font-size:.9em; }}
    th, td {{ text-align:left; vertical-align:top; border-bottom:1px solid var(--line); padding:6px 8px; }}
    footer {{ border-top:1px solid var(--line); margin-top:48px; padding-top:20px; color:var(--muted); font-size:.9em; }}
    footer a {{ color:var(--accent); text-decoration:none; }}
    @media (prefers-color-scheme:dark) {{
      :root {{ --ink:#e6edf3; --muted:#9198a1; --line:#30363d; --page:#0d1117; --card:#161b22; }}
      .mod-count {{ background:#0d1117; }}
      .lbl-validated {{ color:#7ee2b0; background:#0f2e21; border-color:#1f6f4a; }}
      .lbl-partial {{ color:#f2c66d; background:#33270b; border-color:#7a5a1a; }}
      .lbl-mixed {{ color:#aab8f5; background:#1a2142; border-color:#3d4f9c; }}
      .cta a {{ background:#e6edf3; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <h1>Rego Policy Libraries</h1>
      <p class="tag">Browse {total} production-ready OPA Rego policies by standard — load one framework or the whole library. Rego v1, vendor-neutral, fail-closed, Apache&nbsp;2.0.</p>
      <div class="stats">
        <div class="stat"><b>{total}</b><span>Policies</span></div>
        <div class="stat"><b>{checks}</b><span>Control-level checks</span></div>
        <div class="stat"><b>{framework_count}</b><span>Standards</span></div>
        <div class="stat"><b>{stig_platforms}</b><span>DISA STIG platforms</span></div>
        <div class="stat"><b>v1</b><span>Rego syntax</span></div>
      </div>
      <p class="tag" style="font-size:.85em;margin:12px 0 0">The number beside each standard and section is policy files (tests excluded); the {len(cards)} sections add up to the {total} policies above.</p>
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
    <p class="legend">Each card carries its <a href="{LABEL_PAGE}">coverage label</a>: <span class="lbl lbl-validated">validated</span> run on real evidence, <span class="lbl lbl-partial">partial</span> evidence or collector incomplete, <span class="lbl lbl-experimental">experimental</span> not yet run on real evidence.</p>
{chr(10).join(cards)}
    <footer>
      Part of the <a href="https://github.com/Ansible-Automated-Compliance/aac">Ansible Automated Compliance (AAC)</a> platform ·
      Apache 2.0 · generated from the repository tree, so counts stay current ·
      <a href="standard/">One page per standard</a> ·
      <a href="largest-policy-library.html">How big, measured</a> ·
      <a href="{LABEL_PAGE}">Coverage labels</a> ·
      <a href="llms.txt">llms.txt</a> ·
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
