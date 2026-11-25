---
name: web-security-and-launch-audit
description: >-
  Audits any live website or landing page for HTTP security headers (CSP, HSTS,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy),
  HTTPS redirect hygiene, TLS certificate expiry, exposed sensitive paths
  (.env, .git, source maps), robots.txt/sitemap.xml, and TTFB latency. Use when
  auditing a site's security posture or launch readiness.
---

# Web Security & Launch Audit

## Overview

Non-invasive, read-only security and launch-readiness audit for public websites and landing pages. Checks HTTP security headers, TLS certificate validity, HTTPS redirect behavior, accidentally exposed files (`.env`, `.git/HEAD`, `sitemap.xml`, `robots.txt`), and server response latency.

## Dependencies

- **`chrome-devtools`** (optional): For visual verification, console error checks, and Core Web Vitals (LCP/CLS) on top of the CLI security audit.

## Quick Start

```bash
uv run scripts/web_audit.py audit --url https://example.com --output /tmp/web-audit.json
```

## Utility Scripts

`scripts/web_audit.py` uses Python 3 standard library only (`urllib`, `ssl`, `socket`) with built-in request pacing (rate-limited polite probes) and writes structured JSON to `--output`.

### Subcommands
- **`audit --url <https://...> --output <path.json>`**:
  - Measures TTFB and checks HTTP→HTTPS redirect behavior.
  - Inspects TLS certificate expiry days remaining and issuer.
  - Grades 6 core security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`) and flags leaky `Server` / `X-Powered-By` headers.
  - Checks `robots.txt` and `sitemap.xml` presence.
  - Safely checks (HEAD/GET status only) whether sensitive paths (`/.env`, `/.git/HEAD`) accidentally return `200 OK` with non-HTML content.

## Workflow

1. **Run Automated Audit:** Execute `web_audit.py audit --url <target> --output /tmp/web-audit.json`.
2. **Score & Prioritize Findings:**
   - **Critical:** Exposed `/.env` or `/.git/HEAD`, expired/near-expiry TLS cert (`< 14 days`), missing HTTPS redirect.
   - **High:** Missing `Strict-Transport-Security`, `Content-Security-Policy`, or `X-Content-Type-Options`.
   - **Medium:** Missing `Referrer-Policy`, `Permissions-Policy`, `X-Frame-Options`, or missing `robots.txt` / `sitemap.xml`.
3. **Provide Exact Fix Snippets:** Output drop-in header configs for Cloudflare, Vercel (`vercel.json`), Netlify (`_headers`), or Nginx.

## Common Mistakes

- **False positives on SPA catch-all routes:** Single-page apps often return `200 OK` with `text/html` (`index.html`) for `/.env` or `/.git/HEAD`; `web_audit.py` inspects `Content-Type` and signature bytes (`ref: refs/` or `KEY=VALUE`) to avoid false alarms.
- **Skipping HTTP→HTTPS redirect check:** Always test `http://` as well as `https://` to ensure plaintext requests redirect with `301`/`308`.
