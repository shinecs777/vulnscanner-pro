# VulnScanner Pro

VulnScanner Pro is a Flask-based, evidence-first vulnerability assessment
scaffold for **authorized** network and website assessments only. It records
scan requests, validates targets against SSRF and input-injection checks,
defines a normalized SQLite schema for assets, findings, and CVE correlations,
and exposes explicit scanner/report boundaries that raise `NotImplementedError`
rather than returning fabricated results.

## Features

Implemented in this scaffold:

- Flask application with CSRF protection and conservative security headers.
- Target validation for IP/CIDR and HTTP(S) URLs, including shell-metacharacter
  rejection, cloud metadata blocking, internal-suffix blocking, and DNS-based
  SSRF checks.
- SQLite schema for assessments, assets, findings, CVE records, and
  finding-to-CVE links with foreign keys, cascades, CHECK constraints, and a
  per-assessment finding fingerprint uniqueness rule.
- Assessment intake that persists the validated request and records an honest
  `not_implemented` status when a scanner boundary is reached.
- Dark-themed UI for submitting scans and reviewing recent assessments.
- Rotating application logging and automated tests.

Not implemented yet (loud stubs, no fake data):

- Nmap execution and XML parsing.
- Web header/content checks.
- NVD CVE lookups and caching.
- PDF report generation.
- Findings comparison.

## Prerequisites

- Python 3.10+
- Nmap installed locally (required once the network scanner is implemented)
- Optional: an NVD API key for higher CVE lookup rate limits

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Configuration is environment-driven. Safe defaults are used when variables
are unset:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | random per process | Flask session/CSRF signing |
| `DATABASE` | `scans.db` | SQLite database path |
| `NMAP_PATH` | `C:\Users\shine\Downloads\nmap.exe` | Nmap executable |
| `NMAP_TIMEOUT` | `300` | Nmap timeout in seconds |
| `NVD_API_URL` | NVD CVE API 2.0 endpoint | CVE lookup endpoint |
| `NVD_API_KEY` | empty | Optional NVD API key |
| `NVD_RATE_LIMIT_NO_KEY` | `6` | Seconds between unauthenticated NVD calls |
| `NVD_CACHE_TTL_DAYS` | `7` | CVE cache lifetime |
| `WEB_TIMEOUT` | `10` | Web request timeout in seconds |
| `BLOCKED_HOSTS` | metadata/localhost set | Comma-separated blocked hosts |
| `BLOCK_PRIVATE_RANGES` | `true` | Block private addresses for URL targets |
| `LOG_LEVEL` | `INFO` | Logging level |
| `LOG_FILE` | `logs/app.log` | Rotating log destination |
| `DEBUG` | `false` | Enables a startup warning only; the server stays non-debug |

Example:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export NVD_API_KEY="your-key"
export BLOCK_PRIVATE_RANGES=true
```

## Running

```bash
python app.py
```

Open <http://127.0.0.1:5000>. The server always binds to `127.0.0.1:5000` with
`debug=False`. The SQLite database is created at runtime by `init_db()`.

## Testing

```bash
pytest tests/
```

With coverage:

```bash
pytest --cov=core --cov=scanners --cov=reports tests/
```

## Project structure

```text
vuln_scanner/
├── app.py                     Flask routes, security headers, startup
├── config.py                  Environment-backed Config class
├── requirements.txt           Pinned dependencies
├── README.md                  This document
├── .gitignore                 Ignored runtime and tooling artifacts
├── core/
│   ├── __init__.py            Core package marker
│   ├── database.py            get_db() context manager
│   ├── models.py              SQL schema and init_db()
│   ├── validator.py           Input validation and SSRF defenses
│   └── logger.py              Console + rotating file logging
├── scanners/
│   ├── __init__.py            Scanner package marker
│   ├── network_scanner.py     Nmap boundary (Phase 2 stub)
│   ├── web_scanner.py         Web checks boundary (Phase 3 stub)
│   └── cve_lookup.py          NVD lookup boundary (Phase 4 stub)
├── reports/
│   ├── __init__.py            Reports package marker
│   └── pdf_generator.py       PDF boundary (Phase 5 stub)
├── templates/
│   ├── index.html             Scan form and recent assessments
│   ├── findings.html          Assessment findings placeholder
│   └── comparison.html        Comparison placeholder
├── static/
│   └── style.css              Dark theme, risk colors, buttons, tables
└── tests/
    ├── __init__.py            Test package marker
    ├── test_validator.py      IP/URL validation and SSRF tests
    ├── test_scanners.py       Stub behavior tests
    ├── test_api.py            Flask route, CSRF, and header tests
    └── test_database.py       Schema, FK, and uniqueness tests
```

## Limitations

- Network scan will cover the top 100 TCP ports only.
- Version detection is fingerprint-based, not proof of vulnerability.
- Header findings are configuration weaknesses, not exploitable
  vulnerabilities.
- CVE correlation is not proof of exploitability; findings can be marked as
  needing verification.
- Scanners and report generation are not implemented in this scaffold and
  raise `NotImplementedError` instead of returning invented data.
- This is not a replacement for manual penetration testing.

## Security notes

- All user-supplied targets pass through `core.validator` before persistence
  or scanner dispatch.
- Shell metacharacters (`; & | ` $ > <`, newlines, NUL) are rejected.
- Legacy/octal/integer IPv4 forms such as `2130706433` and `0177.0.0.1` are
  normalized and blocked when they map to forbidden ranges.
- Loopback, link-local, multicast, reserved, and unspecified addresses are
  always rejected. Private URL targets are rejected by default via
  `BLOCK_PRIVATE_RANGES`, while private network scan targets remain available
  for authorized internal assessments.
- URL hostnames are resolved with `socket.getaddrinfo()`, and **every**
  resolved address is checked to prevent DNS-based SSRF bypasses.
- Cloud metadata hosts (`169.254.169.254`, `metadata.google.internal`, and
  related aliases) and `.local` / `.internal` suffixes are blocked.
- Non-HTTP(S) schemes and URLs with embedded credentials are rejected.
- Subprocess use is documented to require argument lists and must never use
  `shell=True`; user input must be validated first.
- CSRF protection is enabled for state-changing requests, and responses send
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and a
  restrictive `Content-Security-Policy`.
- There is no SQL string concatenation; all statements use parameters.

## Roadmap

- Full TCP port scanning with configurable port sets.
- Authenticated web testing behind explicit authorization and credential
  handling.
- Finding comparison view across assessments.
- Scheduled scans with safe concurrency and rate limits.
- Nmap XML parsing and evidence-backed network findings.
- NVD API integration with caching and rate-limit handling.
- PDF report generation with severity summaries and evidence.
