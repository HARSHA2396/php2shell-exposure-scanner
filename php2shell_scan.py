#!/usr/bin/env python3
"""
PHP2Shell exposure scanner — CVE-2026-109618 / CVE-2026-109619

================================================================================
 Detection-only tool. Fingerprints PHP version and compares against the
 vendor-fixed releases to produce a patch-status verdict.

 This tool does NOT attempt to trigger, probe, or exploit the underlying
 memory-safety bug. It never sends out-of-memory-inducing requests, crafted
 multipart bodies, or anything targeting the vulnerable code path. It only
 reads standard HTTP response headers and the landing page HTML.

 Authorized use only. Run this only against systems you own or have explicit
 written permission to test.
================================================================================

Usage:
    python3 php2shell_scan.py https://example.com
    python3 php2shell_scan.py -i urls.txt --format json
    python3 php2shell_scan.py https://example.com --format csv --out report.csv
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Vendor-fixed versions per branch (from the PHP security advisory).
# Vulnerable range: PHP 5.4 up to (but not including) these builds.
# ---------------------------------------------------------------------------
FIXED_VERSIONS: dict[tuple[int, int], tuple[int, int, int]] = {
    (8, 5): (8, 5, 12),
    (8, 4): (8, 4, 27),
    (8, 3): (8, 3, 36),
    (8, 2): (8, 2, 35),
}
EOL_CEILING = (8, 1)  # branches at or below this are end-of-life: vulnerable, no official fix
CVES = ["CVE-2026-109618", "CVE-2026-109619"]
INTERIM_MITIGATION = (
    "session.upload_progress.enabled=0, opcache.enable=0, "
    "fatal_error_backtraces=0 (PHP 8.5), and restart all workers. "
    "These reduce exposure but do not replace patching."
)

USER_AGENT = "php2shell-exposure-scan/1.0 (authorized-testing-only)"
MAX_BODY = 131_072  # bytes of HTML read for CMS/platform sniffing
TIMEOUT = 10.0


@dataclass
class Result:
    url: str
    checked_at: str = ""
    php_version: str | None = None
    version_source: str | None = None
    php_detected: bool = False
    server_header: str | None = None
    status: str = "unknown"  # vulnerable | patched | unknown | error
    reason: str = ""
    recommendation: str = ""
    cves: list[str] = field(default_factory=lambda: list(CVES))


# ---------------------------------------------------------------------------
# HTTP — read-only GET/HEAD requests, standard headers and HTML body only.
# No crafted payloads, no multipart bodies, no attempts to induce errors.
# ---------------------------------------------------------------------------
def fetch(url: str, timeout: float = TIMEOUT) -> tuple[int, dict[str, str], str]:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(MAX_BODY).decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, body
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_BODY).decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, headers, body


# ---------------------------------------------------------------------------
# Fingerprinting — passive only: standard response headers + landing HTML.
# ---------------------------------------------------------------------------
def extract_php_version(headers: dict[str, str]) -> str | None:
    for header in ("x-powered-by", "server"):
        if m := re.search(r"PHP/(\d+\.\d+\.\d+)", headers.get(header, ""), re.IGNORECASE):
            return m.group(1)
    return None


def php_is_present(headers: dict[str, str], body: str) -> bool:
    blob = " ".join(headers.get(h, "") for h in ("server", "x-powered-by", "set-cookie"))
    if re.search(r"\bPHP\b|PHPSESSID", blob, re.IGNORECASE):
        return True
    return bool(re.search(r"\.php(?:[\"'?/ >]|$)", body, re.IGNORECASE))


def parse_version(ver: str) -> tuple[int, int, int] | None:
    parts = ver.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0]), int(parts[1]), int(parts[2])


def assess(version: str | None, php_detected: bool) -> tuple[str, str, str]:
    """Return (status, reason, recommendation) for a detected PHP version."""
    if version is None:
        if php_detected:
            return (
                "unknown",
                "PHP detected but version not disclosed in headers (expose_php may be off)",
                "Confirm the PHP version out-of-band (e.g. via your deployment inventory, "
                "not via active probing) and compare against the fixed builds below.",
            )
        return (
            "unknown",
            "No PHP signature found in response",
            "Could not confirm this target runs PHP from passive signals alone.",
        )

    parsed = parse_version(version)
    if parsed is None:
        return ("unknown", f"Unrecognized version string: {version}", "Verify the PHP version manually.")

    major, minor, _ = parsed
    branch = (major, minor)

    if major < 5 or (major == 5 and minor < 4):
        return (
            "unknown",
            f"PHP {version} predates the affected range (5.4+); banner may be inaccurate",
            "Confirm the real version before concluding this host is unaffected.",
        )

    if branch <= EOL_CEILING:
        return (
            "vulnerable",
            f"PHP {version} is on an end-of-life branch with no official fix",
            f"Upgrade to a supported, patched branch. Interim mitigation: {INTERIM_MITIGATION}",
        )

    fixed = FIXED_VERSIONS.get(branch)
    if fixed is None:
        if branch > max(FIXED_VERSIONS):
            return ("unknown", f"PHP {version} is newer than tracked branches; likely patched",
                    "Confirm against the current PHP security advisory.")
        return ("unknown", f"No fixed-version data for branch {major}.{minor}",
                "Check the PHP security advisory for this branch.")

    if parsed >= fixed:
        fixed_str = ".".join(map(str, fixed))
        return ("patched", f"PHP {version} >= fixed {fixed_str} for this branch",
                "No action needed for PHP2Shell specifically; keep normal patch cadence.")

    fixed_str = ".".join(map(str, fixed))
    return (
        "vulnerable",
        f"PHP {version} < fixed {fixed_str} for branch {major}.{minor}",
        f"Upgrade to {fixed_str} or later and restart every worker. "
        f"Until then, interim mitigation: {INTERIM_MITIGATION}",
    )


def check_url(url: str) -> Result:
    res = Result(url=url, checked_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    try:
        _, headers, body = fetch(url)
    except Exception as exc:  # noqa: BLE001 - surfacing any transport failure as a result
        res.status = "error"
        res.reason = f"request failed: {exc}"
        return res

    res.server_header = headers.get("server")
    res.php_detected = php_is_present(headers, body)
    version = extract_php_version(headers)
    if version:
        res.version_source = "response headers"
    res.php_version = version
    res.status, res.reason, res.recommendation = assess(version, res.php_detected)
    return res


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
STATUS_LABEL = {"vulnerable": "VULNERABLE", "patched": "PATCHED", "unknown": "UNKNOWN", "error": "ERROR"}


def render_table(results: list[Result]) -> str:
    rows = [[STATUS_LABEL[r.status], r.php_version or "-", r.url, r.reason] for r in results]
    headers = ["STATUS", "PHP", "URL", "REASON"]
    widths = [max(len(h), *(len(row[i]) for row in rows)) if rows else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths))]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(cell.ljust(w) for cell, w in zip(row, widths)))
    return "\n".join(lines)


def render_json(results: list[Result]) -> str:
    return json.dumps({"results": [asdict(r) for r in results]}, indent=2)


def render_csv(results: list[Result]) -> str:
    buf = io.StringIO()
    fields = [f.name for f in Result.__dataclass_fields__.values()]
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for r in results:
        row = asdict(r)
        row["cves"] = ",".join(row["cves"])
        writer.writerow(row)
    return buf.getvalue()


def summary(results: list[Result]) -> str:
    counts = {s: sum(r.status == s for r in results) for s in ("vulnerable", "patched", "unknown", "error")}
    return (
        f"{len(results)} target(s) scanned | "
        f"vulnerable: {counts['vulnerable']} | patched: {counts['patched']} | "
        f"unknown: {counts['unknown']} | error: {counts['error']}"
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure scanner. "
                     "Detection only — fingerprints PHP version, never sends an exploit payload."
    )
    p.add_argument("urls", nargs="*", help="target URLs, e.g. https://example.com")
    p.add_argument("-i", "--input", type=argparse.FileType("r"),
                   help="file with one URL per line")
    p.add_argument("--format", choices=["table", "json", "csv"], default="table")
    p.add_argument("--out", help="write output to a file instead of stdout")
    return p


def load_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.urls)
    if args.input:
        targets += [line.strip() for line in args.input if line.strip() and not line.startswith("#")]
    seen, ordered = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    targets = load_targets(args)
    if not targets:
        print("error: no targets given (pass URLs or -i FILE)", file=sys.stderr)
        return 2

    results = [check_url(u) for u in targets]

    match args.format:
        case "json":
            output = render_json(results)
        case "csv":
            output = render_csv(results)
        case _:
            output = render_table(results)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output if output.endswith("\n") else output + "\n")
        print(f"Wrote report for {len(results)} target(s) to {args.out}", file=sys.stderr)
    else:
        print(output)

    print(summary(results), file=sys.stderr)
    return 1 if any(r.status == "vulnerable" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
