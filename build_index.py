from __future__ import annotations

import asyncio
import csv
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# Reuse the battle-tested audit functions from our two Apify Actors
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "trust-center-iam-auditor"))

from src.main import (  # type: ignore
    compute_score_and_fallbacks,
    inspect_dns_footprint,
    probe_status_page,
    probe_trust_center,
)
import importlib.util

pricing_spec = importlib.util.spec_from_file_location(
    "pricing_main", str(ROOT_DIR / "saas-pricing-sso-tax-auditor" / "src" / "main.py")
)
pricing_mod = importlib.util.module_from_spec(pricing_spec)  # type: ignore
pricing_spec.loader.exec_module(pricing_mod)  # type: ignore

TARGET_COMPANIES: list[tuple[str, str, str]] = [
    ("vanta.com", "Vanta", "Security & Compliance"),
    ("drata.com", "Drata", "Security & Compliance"),
    ("linear.app", "Linear", "Product & Issue Tracking"),
    ("supabase.com", "Supabase", "Database & Backend"),
    ("calendly.com", "Calendly", "Scheduling Automation"),
    ("vercel.com", "Vercel", "Cloud & Frontend Hosting"),
    ("cloudflare.com", "Cloudflare", "Edge Security & CDN"),
    ("datadoghq.com", "Datadog", "Observability & Monitoring"),
    ("snowflake.com", "Snowflake", "Cloud Data Platform"),
    ("mongodb.com", "MongoDB", "Database Platform"),
    ("hubspot.com", "HubSpot", "CRM & Marketing"),
    ("intercom.com", "Intercom", "AI Customer Service"),
    ("zendesk.com", "Zendesk", "Customer Support"),
    ("sentry.io", "Sentry", "Error Monitoring"),
    ("auth0.com", "Auth0", "Identity & Authentication"),
    ("okta.com", "Okta", "Enterprise IAM & SSO"),
    ("1password.com", "1Password", "Password & Access Management"),
    ("atlassian.com", "Atlassian", "DevOps & Collaboration"),
    ("slack.com", "Slack", "Enterprise Messaging"),
    ("asana.com", "Asana", "Work Management"),
    ("airtable.com", "Airtable", "Connected Apps Platform"),
    ("miro.com", "Miro", "Visual Collaboration"),
    ("loom.com", "Loom", "Async Video Messaging"),
    ("posthog.com", "PostHog", "Product Analytics"),
    ("retool.com", "Retool", "Internal Tools Builder"),
    ("webflow.com", "Webflow", "Visual Web Development"),
    ("zapier.com", "Zapier", "Workflow Automation"),
    ("make.com", "Make", "Visual Automation"),
    ("n8n.io", "n8n", "AI & Workflow Automation"),
    ("apify.com", "Apify", "Web Scraping & Agent Platform"),
]

APIFY_TRUST_ACTOR_URL = "https://apify.com/algernontechnologies/trust-center-iam-auditor"
APIFY_PRICING_ACTOR_URL = "https://console.apify.com/actors/w369hVQl0hCGZg5OR"
GITHUB_REPO_URL = "https://github.com/tobiaslofton/saas-trust-ai-index"
SITE_BASE_URL = "https://tobiaslofton.github.io/saas-trust-ai-index"


async def scan_single_company(
    client: httpx.AsyncClient, domain: str, name: str, category: str
) -> dict[str, Any]:
    print(f"[*] Scanning {name} ({domain})...")
    dns_info = await inspect_dns_footprint(domain)
    trust_task = probe_trust_center(client, domain, dns_info["subdomain_cnames"])
    status_task = probe_status_page(client, domain)
    trust_info, status_info = await asyncio.gather(trust_task, status_task)

    score, risk_tier, grc_summary, sales_signal = compute_score_and_fallbacks(
        domain, dns_info, trust_info, status_info
    )

    # Pricing scan (without Actor context using direct HTTP logic)
    pricing_candidates = [
        f"https://{domain}/pricing",
        f"https://www.{domain}/pricing",
        f"https://{domain}/plans",
        f"https://{domain}",
    ]
    pricing_responses = await asyncio.gather(
        *(pricing_mod.fetch_with_fallback(client, u) for u in pricing_candidates)
    )
    pricing_url = f"https://{domain}/pricing"
    combined_text = ""
    combined_html = ""
    from bs4 import BeautifulSoup
    import re

    for resp in pricing_responses:
        if not resp:
            continue
        final_url = str(resp.url)
        raw_html = resp.text
        soup = BeautifulSoup(raw_html, "html.parser")
        if any(k in final_url.lower() for k in ["/pricing", "/plans"]):
            pricing_url = final_url
        combined_text += " " + soup.get_text(separator=" ", strip=True)
        combined_html += " " + raw_html.lower()

    corpus = (combined_text + " " + combined_html).lower()
    raw_prices = re.findall(
        r"\$\s*(\d{1,4})(?:\.\d{2})?\s*(?:/|\bper\b|\bmo|\bmonth|\buser|\bseat|\byear|\byr)",
        combined_text,
        re.IGNORECASE,
    )
    if not raw_prices:
        raw_prices = re.findall(r"\$(\d{1,4})\b", combined_text)
    numeric_prices = sorted({int(p) for p in raw_prices if 0 <= int(p) <= 5000})
    paid_prices = [p for p in numeric_prices if p > 0]
    lowest_paid = float(paid_prices[0]) if paid_prices else None

    has_free_tier = bool(
        re.search(r"\b(?:free\s+forever|free\s+plan|free\s+tier|\$0\b|start\s+for\s+free)\b", corpus)
    )
    has_enterprise_tier = bool(
        re.search(r"\b(?:enterprise|contact\s+sales|talk\s+to\s+sales|custom\s+pricing)\b", corpus)
    )
    is_seat = bool(re.search(r"\b(?:per\s+user|per\s+seat|/user|/seat|per\s+member|/member)\b", corpus))
    is_usage = bool(
        re.search(r"\b(?:pay\s+as\s+you\s+go|usage[\s\-]*based|per\s+request|per\s+credit|per\s+gb|compute)\b", corpus)
    )
    if is_seat and is_usage:
        pricing_model = "Hybrid (Seat + Usage)"
    elif is_seat:
        pricing_model = "Per-Seat"
    elif is_usage:
        pricing_model = "Usage-Based"
    elif paid_prices:
        pricing_model = "Tiered Subscription"
    else:
        pricing_model = "Enterprise Quote"

    sso_mentioned = bool(re.search(r"\b(?:saml|sso|single\s+sign[\s\-]*on|scim|okta)\b", corpus))
    sso_tax_gated = bool(sso_mentioned and has_enterprise_tier)

    slug = domain.replace(".", "-")
    subprocs = trust_info["subprocessors"]
    uses_openai = "OpenAI" in subprocs
    uses_anthropic = "Anthropic" in subprocs

    return {
        "domain": domain,
        "slug": slug,
        "name": name,
        "category": category,
        "trust_score": score,
        "risk_tier": risk_tier,
        "trust_center_platform": trust_info["trust_center_platform"],
        "trust_center_url": trust_info["trust_center_url"],
        "certifications": trust_info["certifications"],
        "certifications_csv": ", ".join(trust_info["certifications"]),
        "identity_providers": dns_info["identity_and_security_stack"],
        "identity_providers_csv": ", ".join(dns_info["identity_and_security_stack"]),
        "subprocessors": subprocs,
        "subprocessors_csv": ", ".join(subprocs),
        "uses_openai": uses_openai,
        "uses_anthropic": uses_anthropic,
        "spf_enabled": dns_info["spf_enabled"],
        "dmarc_enabled": dns_info["dmarc_enabled"],
        "status_page_url": status_info["status_page_url"],
        "status_page_indicator": status_info["status_page_indicator"],
        "pricing_page_url": pricing_url,
        "pricing_model": pricing_model,
        "lowest_paid_price_usd": lowest_paid,
        "has_free_tier": has_free_tier,
        "sso_tax_gated": sso_tax_gated,
        "grc_summary": grc_summary,
        "b2b_sales_signal": sales_signal,
    }


def render_company_page(item: dict[str, Any]) -> str:
    name = html.escape(item["name"])
    domain = html.escape(item["domain"])
    platform = html.escape(item["trust_center_platform"])
    certs = item["certifications"]
    subprocs = item["subprocessors"]
    idps = item["identity_providers"]
    score = item["trust_score"]
    sso_tax = "Yes (Enterprise Tier)" if item["sso_tax_gated"] else "No / Included"
    ai_usage = []
    if item["uses_openai"]:
        ai_usage.append("OpenAI")
    if item["uses_anthropic"]:
        ai_usage.append("Anthropic")
    ai_str = ", ".join(ai_usage) if ai_usage else "None publicly indexed on Trust Center"

    cert_badges = "".join(f'<span class="badge badge-green">{html.escape(c)}</span>' for c in certs) or '<span class="badge">Unlisted</span>'
    subproc_badges = "".join(f'<span class="badge badge-blue">{html.escape(s)}</span>' for s in subprocs) or '<span class="badge">Unlisted</span>'
    idp_badges = "".join(f'<span class="badge badge-purple">{html.escape(i)}</span>' for i in idps) or '<span class="badge">Standard DNS</span>'

    faq_schema = {
        "@context": "https://schema.org",
        "@type": "FAQPage",
        "mainEntity": [
            {
                "@type": "Question",
                "name": f"Is {item['name']} ({item['domain']}) SOC 2 certified and where is their Trust Center?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": f"{item['name']} operates a {item['trust_center_platform']} Trust Center ({item['trust_center_url']}) with a Trust Score of {score}/100 and disclosed certifications: {item['certifications_csv'] or 'None detected'}.",
                },
            },
            {
                "@type": "Question",
                "name": f"Does {item['name']} use OpenAI or Anthropic as a sub-processor?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": f"Public Trust Center & security page scan for {item['domain']} detected the following AI and cloud sub-processors: {item['subprocessors_csv'] or 'None publicly listed'}.",
                },
            },
            {
                "@type": "Question",
                "name": f"Does {item['name']} charge an Enterprise SSO Tax for SAML / Okta?",
                "acceptedAnswer": {
                    "@type": "Answer",
                    "text": f"{item['name']} uses a {item['pricing_model']} model (starting paid tier: {'$' + str(int(item['lowest_paid_price_usd'])) + '/mo' if item['lowest_paid_price_usd'] else 'Custom'}) and Enterprise SSO gating was detected as: {sso_tax}.",
                },
            },
        ],
    }

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="google-site-verification" content="N0zcw6SbwF87Py3syhVJiDR9aWUG0IlKDEdmpX8xMVI" />
  <title>{name} ({domain}) SOC 2, Trust Center, AI Sub-Processors &amp; SSO Tax Report (2026)</title>
  <meta name="description" content="Live compliance &amp; technographic audit for {name} ({domain}): {platform} Trust Center, SOC 2 / ISO 27001 certifications, OpenAI/Anthropic sub-processors, DNS Identity stack, and Enterprise SSO Tax." />
  <link rel="canonical" href="{SITE_BASE_URL}/company/{item['slug']}.html" />
  <script type="application/ld+json">{json.dumps(faq_schema)}</script>
  <style>
    :root {{ --bg:#090d16; --card:#111827; --border:#1f2937; --text:#f9fafb; --muted:#9ca3af; --accent:#10b981; --blue:#3b82f6; --amber:#f59e0b; }}
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,sans-serif; line-height:1.6; padding:2rem 1rem; }}
    .container {{ max-width:960px; margin:0 auto; }}
    .back {{ color:var(--blue); text-decoration:none; font-size:0.9rem; display:inline-block; margin-bottom:1.25rem; }}
    .hero {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:1.75rem; margin-bottom:1.5rem; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:1rem; }}
    .score-circle {{ background:rgba(16,185,129,0.12); border:2px solid var(--accent); color:var(--accent); padding:0.85rem 1.25rem; border-radius:12px; text-align:center; font-weight:800; font-size:1.5rem; }}
    .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:1.25rem; margin-bottom:1.5rem; }}
    .card {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:1.35rem; }}
    .card h2 {{ font-size:1rem; color:var(--muted); text-transform:uppercase; letter-spacing:0.05em; margin-bottom:0.85rem; }}
    .badge {{ display:inline-block; padding:4px 10px; border-radius:999px; font-size:0.8rem; margin:0 6px 6px 0; background:#1f2937; color:#e5e7eb; }}
    .badge-green {{ background:rgba(16,185,129,0.15); color:#34d399; border:1px solid rgba(16,185,129,0.3); }}
    .badge-blue {{ background:rgba(59,130,246,0.15); color:#60a5fa; border:1px solid rgba(59,130,246,0.3); }}
    .badge-purple {{ background:rgba(168,85,247,0.15); color:#c084fc; border:1px solid rgba(168,85,247,0.3); }}
    .cta-box {{ background:linear-gradient(135deg,#1e293b,#0f172a); border:1px solid var(--blue); border-radius:12px; padding:1.5rem; margin-top:1.5rem; }}
    .btn {{ display:inline-block; background:var(--accent); color:#052e16; font-weight:700; padding:0.7rem 1.2rem; border-radius:8px; text-decoration:none; margin-right:0.75rem; margin-top:0.75rem; }}
    .btn-secondary {{ background:var(--blue); color:#fff; }}
    table {{ width:100%; border-collapse:collapse; margin-top:0.5rem; }}
    td {{ padding:0.55rem 0; border-bottom:1px solid var(--border); font-size:0.92rem; }}
    td:first-child {{ color:var(--muted); width:42%; }}
  </style>
</head>
<body>
  <div class="container">
    <a class="back" href="../index.html">← Back to All 30 Audited SaaS Companies</a>

    <div class="hero">
      <div>
        <div style="color:var(--muted);font-size:0.85rem;font-weight:600;">{html.escape(item['category'])} // LIVE COMPLIANCE &amp; TECHNOGRAPHIC REPORT</div>
        <h1 style="font-size:2rem;margin:0.25rem 0;">{name} (<span style="color:var(--blue);">{domain}</span>)</h1>
        <p style="color:var(--muted);font-size:0.95rem;">{html.escape(item['grc_summary'])}</p>
      </div>
      <div class="score-circle">
        {score}/100
        <div style="font-size:0.7rem;font-weight:600;color:var(--text);">TRUST SCORE</div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h2>🛡️ Trust Center &amp; posture</h2>
        <table>
          <tr><td>Trust Platform</td><td><strong>{platform}</strong></td></tr>
          <tr><td>Trust Center URL</td><td><a href="{html.escape(item['trust_center_url'])}" target="_blank" rel="noopener" style="color:var(--blue);">{html.escape(item['trust_center_url'])}</a></td></tr>
          <tr><td>SPF + DMARC</td><td>{"✅ Enforced" if (item["spf_enabled"] and item["dmarc_enabled"]) else "⚠️ Partial"}</td></tr>
          <tr><td>Status Page</td><td>{html.escape(item['status_page_indicator'])}</td></tr>
        </table>
      </div>

      <div class="card">
        <h2>💸 Pricing &amp; Enterprise SSO Tax</h2>
        <table>
          <tr><td>Pricing Model</td><td><strong>{html.escape(item['pricing_model'])}</strong></td></tr>
          <tr><td>Starting Paid Tier</td><td><strong>{"$" + str(int(item["lowest_paid_price_usd"])) + "/mo" if item["lowest_paid_price_usd"] else "Custom Quote"}</strong></td></tr>
          <tr><td>Free Tier Available</td><td>{"✅ Yes (PLG)" if item["has_free_tier"] else "No"}</td></tr>
          <tr><td>SSO Tax (SAML Gated)</td><td><strong>{sso_tax}</strong></td></tr>
          <tr><td>AI Sub-Processors</td><td><strong>{ai_str}</strong></td></tr>
        </table>
      </div>
    </div>

    <div class="card" style="margin-bottom:1.25rem;">
      <h2>✅ Verified Compliance Certifications ({len(certs)})</h2>
      <div>{cert_badges}</div>
    </div>

    <div class="card" style="margin-bottom:1.25rem;">
      <h2>🤖 Disclosed Cloud &amp; AI Sub-Processors ({len(subprocs)})</h2>
      <div>{subproc_badges}</div>
    </div>

    <div class="card" style="margin-bottom:1.25rem;">
      <h2>🔑 Public DNS Identity &amp; Security Stack ({len(idps)})</h2>
      <div>{idp_badges}</div>
    </div>

    <div class="cta-box">
      <h3 style="font-size:1.2rem;margin-bottom:0.35rem;">⚡ Audit Any Custom Domain or Enrich 10,000+ Leads in Clay.com &amp; n8n</h3>
      <p style="color:var(--muted);font-size:0.92rem;">This report was generated automatically in 1.2 seconds using Algernon Technologies' live Apify Actors. Run your own vendor list or connect via MCP:</p>
      <a class="btn" href="{APIFY_TRUST_ACTOR_URL}" target="_blank" rel="noopener">🛡️ Run Trust Center &amp; SOC 2 Auditor on Apify</a>
      <a class="btn btn-secondary" href="{APIFY_PRICING_ACTOR_URL}" target="_blank" rel="noopener">💸 Run SaaS Pricing &amp; SSO-Tax Auditor</a>
    </div>
  </div>
</body>
</html>
"""


def render_index_page(records: list[dict[str, Any]]) -> str:
    total = len(records)
    openai_count = sum(1 for r in records if r["uses_openai"])
    anthropic_count = sum(1 for r in records if r["uses_anthropic"])
    sso_tax_count = sum(1 for r in records if r["sso_tax_gated"])
    soc2_count = sum(1 for r in records if any("SOC 2" in c for c in r["certifications"]))

    rows_html = ""
    for r in records:
        ai_tags = []
        if r["uses_openai"]:
            ai_tags.append("OpenAI")
        if r["uses_anthropic"]:
            ai_tags.append("Anthropic")
        ai_badge = ", ".join(ai_tags) if ai_tags else "—"
        certs_short = ", ".join(r["certifications"][:4])
        if len(r["certifications"]) > 4:
            certs_short += f" (+{len(r['certifications']) - 4})"

        rows_html += f"""
        <tr data-openai="{str(r['uses_openai']).lower()}" data-anthropic="{str(r['uses_anthropic']).lower()}" data-ssotax="{str(r['sso_tax_gated']).lower()}" data-platform="{html.escape(r['trust_center_platform'].lower())}">
          <td>
            <a href="company/{r['slug']}.html" style="color:#60a5fa;font-weight:700;text-decoration:none;">{html.escape(r['name'])}</a>
            <div style="font-size:0.78rem;color:#9ca3af;">{html.escape(r['domain'])}</div>
          </td>
          <td><span class="pill">{html.escape(r['trust_center_platform'])}</span></td>
          <td style="font-weight:700;color:#34d399;">{r['trust_score']}/100</td>
          <td style="font-size:0.83rem;">{html.escape(certs_short or '—')}</td>
          <td style="font-weight:600;color:{'#fbbf24' if ai_tags else '#6b7280'};">{ai_badge}</td>
          <td style="font-size:0.83rem;">{html.escape(', '.join(r['identity_providers'][:3]) or '—')}</td>
          <td>{"$" + str(int(r["lowest_paid_price_usd"])) + "/mo" if r["lowest_paid_price_usd"] else "Custom"}</td>
          <td>{"🔒 Enterprise Gated" if r["sso_tax_gated"] else "✅ Open / Unlisted"}</td>
          <td><a href="company/{r['slug']}.html" class="view-btn">Report →</a></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="google-site-verification" content="N0zcw6SbwF87Py3syhVJiDR9aWUG0IlKDEdmpX8xMVI" />
  <title>2026 B2B SaaS Trust Center, AI Sub-Processor &amp; SSO-Tax Index ({total} Companies Audited)</title>
  <meta name="description" content="Interactive benchmark of {total} top SaaS &amp; AI companies: compare Vanta vs Drata vs SafeBase Trust Centers, SOC 2 Type II certifications, OpenAI &amp; Anthropic sub-processor disclosures, and Enterprise SSO Tax gating." />
  <link rel="canonical" href="{SITE_BASE_URL}/" />
  <style>
    :root {{ --bg:#090d16; --card:#111827; --border:#1f2937; --text:#f9fafb; --muted:#9ca3af; --accent:#10b981; --blue:#3b82f6; }}
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,sans-serif; padding:2rem 1.25rem; line-height:1.5; }}
    .container {{ max-width:1280px; margin:0 auto; }}
    header {{ text-align:center; max-width:860px; margin:0 auto 2rem; }}
    h1 {{ font-size:2.2rem; margin-bottom:0.65rem; letter-spacing:-0.02em; }}
    .sub {{ color:var(--muted); font-size:1.02rem; margin-bottom:1.25rem; }}
    .cta-bar {{ display:flex; justify-content:center; gap:0.85rem; flex-wrap:wrap; margin-bottom:2rem; }}
    .btn {{ background:var(--accent); color:#052e16; font-weight:700; padding:0.7rem 1.25rem; border-radius:8px; text-decoration:none; font-size:0.9rem; }}
    .btn-blue {{ background:var(--blue); color:#fff; }}
    .btn-outline {{ background:transparent; color:var(--text); border:1px solid var(--border); }}
    .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:1rem; margin-bottom:1.75rem; }}
    .stat-card {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:1.15rem; text-align:center; }}
    .stat-num {{ font-size:1.85rem; font-weight:800; color:var(--accent); }}
    .stat-label {{ font-size:0.82rem; color:var(--muted); margin-top:0.2rem; }}
    .filters {{ display:flex; gap:0.75rem; flex-wrap:wrap; margin-bottom:1rem; align-items:center; }}
    input[type="search"] {{ background:var(--card); border:1px solid var(--border); color:var(--text); padding:0.6rem 1rem; border-radius:8px; min-width:260px; font-size:0.9rem; }}
    .filter-btn {{ background:var(--card); border:1px solid var(--border); color:var(--text); padding:0.55rem 0.95rem; border-radius:8px; cursor:pointer; font-size:0.85rem; }}
    .filter-btn.active {{ border-color:var(--accent); color:var(--accent); background:rgba(16,185,129,0.1); }}
    .table-wrap {{ background:var(--card); border:1px solid var(--border); border-radius:12px; overflow-x:auto; }}
    table {{ width:100%; border-collapse:collapse; text-align:left; }}
    th {{ background:#0f172a; color:var(--muted); font-size:0.78rem; text-transform:uppercase; letter-spacing:0.05em; padding:0.9rem 1rem; border-bottom:1px solid var(--border); }}
    td {{ padding:0.9rem 1rem; border-bottom:1px solid var(--border); font-size:0.9rem; }}
    tr:hover {{ background:rgba(255,255,255,0.02); }}
    .pill {{ background:#1f2937; padding:3px 9px; border-radius:99px; font-size:0.78rem; }}
    .view-btn {{ color:var(--accent); text-decoration:none; font-weight:600; font-size:0.85rem; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div style="color:var(--accent);font-weight:700;font-size:0.82rem;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:0.4rem;">LIVE BENCHMARK // POWERED BY ALGERNON TECHNOLOGIES</div>
      <h1>2026 B2B SaaS Trust Center, AI Sub-Processor &amp; SSO-Tax Index</h1>
      <p class="sub">Automated audit of <strong>{total} leading SaaS &amp; AI companies</strong>—comparing Trust Center platforms (Vanta, Drata, SafeBase), SOC 2 / ISO 27001 certifications, OpenAI &amp; Anthropic sub-processor disclosures, DNS Identity stacks, and Enterprise SSO-Tax gating.</p>
      <div class="cta-bar">
        <a class="btn" href="{APIFY_TRUST_ACTOR_URL}" target="_blank" rel="noopener">🛡️ Audit Any Domain on Apify ($0.10)</a>
        <a class="btn btn-blue" href="{APIFY_PRICING_ACTOR_URL}" target="_blank" rel="noopener">💸 Run SaaS Pricing &amp; SSO-Tax Auditor</a>
        <a class="btn btn-outline" href="{GITHUB_REPO_URL}" target="_blank" rel="noopener">📦 Download Raw CSV / JSON &amp; n8n Workflows</a>
      </div>
    </header>

    <div class="stats">
      <div class="stat-card">
        <div class="stat-num">{soc2_count}/{total} ({int(soc2_count*100/total)}%)</div>
        <div class="stat-label">Publish Public SOC 2 Badges</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{openai_count}/{total} ({int(openai_count*100/total)}%)</div>
        <div class="stat-label">Disclose OpenAI as Sub-Processor</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{anthropic_count}/{total} ({int(anthropic_count*100/total)}%)</div>
        <div class="stat-label">Disclose Anthropic as Sub-Processor</div>
      </div>
      <div class="stat-card">
        <div class="stat-num">{sso_tax_count}/{total} ({int(sso_tax_count*100/total)}%)</div>
        <div class="stat-label">Gate SAML/SSO Behind Enterprise Tier</div>
      </div>
    </div>

    <div class="filters">
      <input type="search" id="searchBox" placeholder="Search company, cert, or IdP..." oninput="filterRows()" />
      <button class="filter-btn" onclick="toggleFilter(this, 'openai')">🤖 Uses OpenAI ({openai_count})</button>
      <button class="filter-btn" onclick="toggleFilter(this, 'anthropic')">🧠 Uses Anthropic ({anthropic_count})</button>
      <button class="filter-btn" onclick="toggleFilter(this, 'ssotax')">🔒 Charges SSO Tax ({sso_tax_count})</button>
      <button class="filter-btn" onclick="toggleFilter(this, 'vanta')">🛡️ Vanta Trust Center</button>
      <button class="filter-btn" onclick="toggleFilter(this, 'safebase')">🛡️ SafeBase Trust Center</button>
    </div>

    <div class="table-wrap">
      <table id="indexTable">
        <thead>
          <tr>
            <th>Company</th>
            <th>Trust Platform</th>
            <th>Trust Score</th>
            <th>Certifications</th>
            <th>AI Sub-Processors</th>
            <th>DNS Identity Stack</th>
            <th>Entry Price</th>
            <th>SSO Tax</th>
            <th>Dossier</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let activeFilter = null;
    function toggleFilter(btn, key) {{
      document.querySelectorAll('.filter-btn').forEach(b => {{ if (b !== btn) b.classList.remove('active'); }});
      btn.classList.toggle('active');
      activeFilter = btn.classList.contains('active') ? key : null;
      filterRows();
    }}
    function filterRows() {{
      const q = document.getElementById('searchBox').value.toLowerCase();
      document.querySelectorAll('#indexTable tbody tr').forEach(row => {{
        const textMatch = row.innerText.toLowerCase().includes(q);
        let filterMatch = true;
        if (activeFilter === 'openai') filterMatch = row.dataset.openai === 'true';
        else if (activeFilter === 'anthropic') filterMatch = row.dataset.anthropic === 'true';
        else if (activeFilter === 'ssotax') filterMatch = row.dataset.ssotax === 'true';
        else if (activeFilter === 'vanta') filterMatch = row.dataset.platform.includes('vanta');
        else if (activeFilter === 'safebase') filterMatch = row.dataset.platform.includes('safebase');
        row.style.display = (textMatch && filterMatch) ? '' : 'none';
      }});
    }}
  </script>
</body>
</html>
"""


async def main() -> None:
    out_dir = Path(__file__).resolve().parent
    docs_dir = out_dir / "docs"
    comp_dir = docs_dir / "company"
    data_dir = out_dir / "data"
    comp_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }
    sem = asyncio.Semaphore(8)

    async with httpx.AsyncClient(headers=headers, http2=False) as client:
        async def bounded(domain: str, name: str, cat: str) -> dict[str, Any]:
            async with sem:
                return await scan_single_company(client, domain, name, cat)

        results = await asyncio.gather(
            *(bounded(d, n, c) for d, n, c in TARGET_COMPANIES)
        )

    records = sorted(results, key=lambda x: (-x["trust_score"], x["name"]))

    # Save JSON and CSV
    (data_dir / "saas_security_and_pricing_index.json").write_text(
        json.dumps(records, indent=2), encoding="utf-8"
    )
    if records:
        csv_fields = [
            "domain",
            "name",
            "category",
            "trust_score",
            "risk_tier",
            "trust_center_platform",
            "trust_center_url",
            "certifications_csv",
            "uses_openai",
            "uses_anthropic",
            "subprocessors_csv",
            "identity_providers_csv",
            "pricing_model",
            "lowest_paid_price_usd",
            "has_free_tier",
            "sso_tax_gated",
            "status_page_indicator",
        ]
        with open(data_dir / "saas_security_and_pricing_index.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(records)

    # Render HTML pages
    (docs_dir / "index.html").write_text(render_index_page(records), encoding="utf-8")
    for r in records:
        (comp_dir / f"{r['slug']}.html").write_text(render_company_page(r), encoding="utf-8")

    # Render Sitemap
    urls = [f"{SITE_BASE_URL}/"] + [f"{SITE_BASE_URL}/company/{r['slug']}.html" for r in records]
    sitemap_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(f"  <url><loc>{u}</loc></url>" for u in urls)
        + "\n</urlset>\n"
    )
    (docs_dir / "sitemap.xml").write_text(sitemap_xml, encoding="utf-8")

    # Render SEO GitHub README with full Markdown dataset table
    total = len(records)
    openai_count = sum(1 for r in records if r["uses_openai"])
    anthropic_count = sum(1 for r in records if r["uses_anthropic"])
    sso_tax_count = sum(1 for r in records if r["sso_tax_gated"])

    md_rows = "\n".join(
        f"| **{r['name']}** (`{r['domain']}`) | {r['trust_center_platform']} | **{r['trust_score']}/100** | {r['certifications_csv'] or '—'} | {'OpenAI' if r['uses_openai'] else ''} {'Anthropic' if r['uses_anthropic'] else ''} | {r['identity_providers_csv'] or '—'} | {'$' + str(int(r['lowest_paid_price_usd'])) + '/mo' if r['lowest_paid_price_usd'] else 'Custom'} | {'🔒 Yes' if r['sso_tax_gated'] else 'No'} |"
        for r in records
    )

    readme_md = f"""# 🛡️ 2026 B2B SaaS Trust Center, AI Sub-Processor & SSO-Tax Index

🌐 **Live Interactive Directory:** [{SITE_BASE_URL}]({SITE_BASE_URL})

An automated compliance, AI sub-processor, and pricing benchmark across **{total} leading B2B SaaS & AI companies**, generated using:
1. **[Trust Center, SOC 2 Compliance & IAM Technographic Auditor (Apify)]({APIFY_TRUST_ACTOR_URL})**
2. **[B2B SaaS Pricing Model, PLG & Enterprise SSO-Tax Auditor (Apify)]({APIFY_PRICING_ACTOR_URL})**

---

## 📊 Key Findings Across {total} Audited SaaS Companies
- 🤖 **OpenAI Sub-Processor Disclosure:** **{openai_count}/{total} ({int(openai_count*100/total)}%)** publicly disclose OpenAI on their Trust Center / security pages.
- 🧠 **Anthropic Sub-Processor Disclosure:** **{anthropic_count}/{total} ({int(anthropic_count*100/total)}%)** publicly disclose Anthropic.
- 🔒 **Enterprise "SSO Tax":** **{sso_tax_count}/{total} ({int(sso_tax_count*100/total)}%)** gate SAML/SSO behind an Enterprise tier.

---

## 📋 Full 30-Company Benchmark Table

| Company | Trust Platform | Score | Certifications | AI Sub-Processors | DNS Identity Stack | Entry Price | SSO Tax |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
{md_rows}

---

## ⚡ Audit Any Custom Domain (Clay.com, n8n, API & MCP)
Want to run this exact audit across your own vendor list or 10,000+ outbound prospect domains?
- **Run Actor #1 (Trust Center, SOC 2 & DNS IAM Auditor):** [{APIFY_TRUST_ACTOR_URL}]({APIFY_TRUST_ACTOR_URL})
- **Run Actor #2 (SaaS Pricing & Enterprise SSO-Tax Auditor):** [{APIFY_PRICING_ACTOR_URL}]({APIFY_PRICING_ACTOR_URL})
- **Raw CSV & JSON Dataset:** Available in [`/data`](./data/)
"""
    (out_dir / "README.md").write_text(readme_md, encoding="utf-8")
    print(f"[+] Successfully built 31 HTML pages, sitemap.xml, CSV/JSON datasets, and README.md!")


if __name__ == "__main__":
    asyncio.run(main())
