# PHP2Shell Exposure Scanner

A lightweight, detection-only Python tool for assessing potential exposure to **PHP2Shell (CVE-2026-109618 and CVE-2026-109619)** by identifying PHP version information exposed through standard HTTP response headers and landing-page HTML.

The scanner compares a detected PHP version against the fixed-version thresholds configured in the script and reports `VULNERABLE`, `PATCHED`, `UNKNOWN`, or `ERROR`.

> **Important:** This is a version-fingerprinting aid, not proof of exploitability. It does not trigger the underlying memory-safety issues, verify a fix through runtime testing, or account for every vendor's backported patches. Validate results against the relevant vendor security advisory and the actual package or container image version.

## Features

- Python standard library only; no third-party packages required.
- Scans one URL or multiple targets from a text file.
- Uses ordinary HTTP `GET` requests and reads response headers plus a limited amount of landing-page HTML.
- Checks `X-Powered-By` and `Server` headers for a PHP version.
- Supports table, JSON, and CSV reports.
- Can write reports to a file.
- Returns a non-zero exit code when a target is classified as `VULNERABLE`.
- Does **not** send exploit payloads or deliberately malformed multipart requests.

## Requirements

- Python 3.10 or newer
- Network access to the authorized target URLs
- Permission to assess each target

Check your Python version:

```bash
python3 --version
```

No `pip install` step is required.

## Installation

Save the scanner as `php2shell_scan.py`.

Make it executable on Linux, if desired:

```bash
chmod +x php2shell_scan.py
```

## Usage

### 1. Scan a single site

```bash
python3 php2shell_scan.py https://yourapp.example
```

Example output:

```text
STATUS      PHP      URL                      REASON
----------  -------  -----------------------  --------------------------------------------
VULNERABLE  8.3.10   https://yourapp.example  PHP 8.3.10 < fixed 8.3.36 for branch 8.3
```

The exact result depends on the target's response. A one-line summary is printed to standard error, for example:

```text
1 target(s) scanned | vulnerable: 1 | patched: 0 | unknown: 0 | error: 0
```

### 2. Scan multiple sites

Create a file named `urls.txt` with one URL per line:

```text
https://app1.example
https://app2.example
https://staging.yourapp.example
```

Lines beginning with `#` are treated as comments.

Run:

```bash
python3 php2shell_scan.py -i urls.txt
```

You can also pass several URLs directly:

```bash
python3 php2shell_scan.py https://app1.example https://app2.example
```

Duplicate URLs are removed while preserving their original order.

### 3. Choose an output format

**JSON:**

```bash
python3 php2shell_scan.py -i urls.txt --format json
```

**CSV:**

```bash
python3 php2shell_scan.py -i urls.txt --format csv
```

**Table (default):**

```bash
python3 php2shell_scan.py -i urls.txt --format table
```

### 4. Save a report to a file

Save a CSV report:

```bash
python3 php2shell_scan.py -i urls.txt --format csv --out report.csv
```

Save a JSON report:

```bash
python3 php2shell_scan.py -i urls.txt --format json --out scan.json
```

When `--out` is specified, the report is written to that file and a confirmation message is printed to standard error. The scan summary is also printed to standard error.

## Understanding the verdicts

| Status | Meaning | Recommended action |
|---|---|---|
| `VULNERABLE` | The detected version is below the configured fixed version for a tracked branch, or belongs to an end-of-life branch covered by the script's rule. | Confirm against the vendor advisory and installed package version. Upgrade to a supported, fixed release and restart affected workers. |
| `PATCHED` | The detected version is at or above the configured fixed threshold for a tracked branch. | Confirm vendor packaging and backports; continue normal patch management. |
| `UNKNOWN` | The version could not be determined, the branch is not covered by the script, or available fingerprint information is insufficient. | Check deployment inventory, package metadata, container image details, or your configuration-management database. Do not assume the host is safe. |
| `ERROR` | The HTTP request failed, for example because of DNS, connection, or TLS problems. | Check the URL, network reachability, and certificate configuration. |

The scanner uses passive response signals. A missing PHP version does **not** mean that PHP is absent or that the target is safe.

## Fixed-version thresholds configured in this script

The current script contains these thresholds:

| PHP branch | Fixed version configured |
|---|---:|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |

The script treats PHP 8.1 and earlier as end-of-life under its configured rule. Branches without a listed threshold may be reported as `UNKNOWN`.

**Verify these values before operational use.** They are values encoded in the supplied script, not a guarantee that the list is complete or current. Check the official PHP security advisory and your operating-system or runtime vendor's advisory for the relevant CVEs. Distributions may backport security fixes without changing the upstream version string in the way this scanner expects.

## How detection works

1. The scanner sends a standard HTTP `GET` request to each supplied URL.
2. It reads response headers and up to 128 KiB of the response body.
3. It looks for a PHP version in the `X-Powered-By` or `Server` headers.
4. It checks for other passive PHP indicators, such as PHP-related headers, `PHPSESSID`, or `.php` references in the HTML.
5. It compares any extracted version with the fixed-version thresholds configured in the script.
6. It prints the verdict and recommendation.

Because version extraction depends on information exposed by the target, the scanner can miss PHP deployments that suppress version banners, sit behind a reverse proxy, or use nonstandard headers.

## CI and automation

The script exits with code `1` if any result is `VULNERABLE`, and `0` if no result is classified as `VULNERABLE`. Invalid invocation or missing targets returns `2`.

Example shell workflow:

```bash
python3 php2shell_scan.py -i urls.txt --format json --out scan.json
scan_status=$?

if [ "$scan_status" -eq 1 ]; then
  echo "Potentially vulnerable PHP hosts found — review scan.json"
elif [ "$scan_status" -eq 0 ]; then
  echo "No targets were classified as vulnerable. Review UNKNOWN and ERROR results too."
else
  echo "Scanner could not complete normally (exit code: $scan_status)"
fi
```

Do not interpret exit code `0` as proof that all targets are secure: results may still be `UNKNOWN` or `ERROR`.

## Scope and limitations

- **Authorized use only:** Scan only systems you own or have explicit permission to assess.
- **Detection only:** The tool does not exploit either CVE and does not confirm memory disclosure or remote code execution.
- **Version-banner dependency:** Suppressed or rewritten headers can prevent version detection.
- **Backported fixes:** Vendor patches may not be reflected in the upstream version string.
- **Tracked branches only:** Thresholds for branches not listed in the script may be incomplete.
- **Single endpoint:** The scanner checks the URL supplied; it does not crawl an entire application or enumerate every backend worker.
- **HTTP errors:** HTTP error responses may still contain headers that the scanner can inspect, but transport failures are reported as `ERROR`.
- **TLS verification:** HTTPS certificate validation is enabled; certificate or TLS failures may prevent scanning.

## Mitigation notes

Prioritize upgrading to a supported release confirmed to contain the relevant fixes. The supplied script also mentions interim configuration mitigations, including disabling session upload progress and certain runtime features. Treat such mitigations as temporary risk reduction only, verify them against the official advisory for your exact PHP build, and restart affected workers after changes. They are not substitutes for patching.

## Responsible use

This project is intended for defensive exposure management and authorized security testing. Obtain permission before scanning a system, follow your organization's testing rules, and report suspected vulnerabilities through the appropriate security contact or disclosure process.

## Disclaimer

This tool provides a preliminary assessment based on observable version information and the thresholds included in its source code. Its output is not a guarantee of vulnerability or safety. The maintainer and contributors make no warranty regarding completeness, accuracy, or suitability for a particular environment.
