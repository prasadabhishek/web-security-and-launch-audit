#!/usr/bin/env python3
"""Read-only live website security headers, TLS, and launch-readiness auditor (stdlib only)."""

import argparse
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

REQUIRED_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]


def check_tls(hostname: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) if not_after else None
                days_left = (exp_dt - datetime.now(timezone.utc)).days if exp_dt else None
                return {
                    "ok": True,
                    "tls_version": ssock.version(),
                    "not_after": not_after,
                    "days_until_expiry": days_left,
                }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def fetch(url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "web-security-and-launch-audit/1.0"})
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(4096)
            ttfb_ms = round((time.monotonic() - t0) * 1000, 1)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return {"status": resp.status, "final_url": resp.geturl(), "ttfb_ms": ttfb_ms, "headers": headers, "body_preview": body.decode("utf-8", errors="ignore")}
    except urllib.error.HTTPError as e:
        ttfb_ms = round((time.monotonic() - t0) * 1000, 1)
        headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return {"status": e.code, "final_url": url, "ttfb_ms": ttfb_ms, "headers": headers, "body_preview": ""}
    except Exception as e:
        return {"status": None, "error": str(e), "headers": {}, "body_preview": ""}


def cmd_audit(url: str, output: Path) -> None:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host:
        print(f"Error: invalid URL: {url}", file=sys.stderr)
        sys.exit(1)

    main_res = fetch(url)
    headers = main_res.get("headers", {})
    present = {h: headers.get(h) for h in REQUIRED_HEADERS if h in headers}
    missing = [h for h in REQUIRED_HEADERS if h not in headers]
    leaky = {h: headers[h] for h in ["server", "x-powered-by"] if h in headers}

    tls_info = check_tls(host, parsed.port or 443) if parsed.scheme == "https" else {"skipped": "non-https"}

    base = f"{parsed.scheme}://{parsed.netloc}"
    time.sleep(0.3)
    robots = fetch(base + "/robots.txt")
    time.sleep(0.3)
    sitemap = fetch(base + "/sitemap.xml")
    time.sleep(0.3)
    dot_env = fetch(base + "/.env")
    time.sleep(0.3)
    dot_git = fetch(base + "/.git/HEAD")

    env_exposed = (
        dot_env.get("status") == 200
        and "text/html" not in dot_env.get("headers", {}).get("content-type", "")
        and "=" in dot_env.get("body_preview", "")
    )
    git_exposed = (
        dot_git.get("status") == 200
        and "ref: refs/" in dot_git.get("body_preview", "")
    )

    score = round(((len(present)) / len(REQUIRED_HEADERS)) * 100)
    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "final_url": main_res.get("final_url"),
        "http_status": main_res.get("status"),
        "ttfb_ms": main_res.get("ttfb_ms"),
        "tls": tls_info,
        "security_headers_score_pct": score,
        "present_security_headers": present,
        "missing_security_headers": missing,
        "leaky_headers": leaky,
        "seo_launch": {
            "robots_txt_status": robots.get("status"),
            "sitemap_xml_status": sitemap.get("status"),
        },
        "exposure_checks": {
            "env_exposed": env_exposed,
            "git_head_exposed": git_exposed,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2))
    print(
        f"Success! Web audit written to: {output} | Status={main_res.get('status')} | "
        f"Headers={score}% ({len(missing)} missing) | TTFB={main_res.get('ttfb_ms')}ms"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Live Website Security & Launch Readiness Auditor")
    sub = parser.add_subparsers(dest="command", required=True)
    p_a = sub.add_parser("audit", help="Audit a live URL")
    p_a.add_argument("--url", required=True)
    p_a.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "audit":
        cmd_audit(args.url, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
