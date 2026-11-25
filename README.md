# Web Security & Launch Audit

Agent skill and Python 3 stdlib CLI for auditing live websites and landing pages: HTTP security headers, TLS expiry, TTFB latency, `robots.txt`/`sitemap.xml`, and accidentally exposed `.env` / `.git/HEAD` files (with SPA false-positive filtering).

## Install as an Agent Skill

```bash
npx skills add prasadabhishek/web-security-and-launch-audit
```

## Standalone CLI Usage

```bash
uv run scripts/web_audit.py audit --url https://example.com --output /tmp/web-audit.json
```

## License

MIT
