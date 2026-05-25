# lancer-mobsf

Rust-native mobile security analysis tool — part of the Lancer bug bounty toolkit. Performs static analysis of Android APKs and iOS IPAs, with AI-assisted triage, CVE correlation, threat intelligence, and custom Frida hook script generation.

## Features

- **Android static analysis** — manifest parsing, certificate inspection, ELF binary hardening checks, permission auditing, hardcoded-secret scanning, tracker detection, network security config analysis
- **iOS static analysis** — IPA extraction, Info.plist analysis, binary hardening checks, ATS inspection
- **AI triage** — uses Claude to rank findings, generate executive summaries, and suggest remediation (requires `ANTHROPIC_API_KEY`)
- **CVE correlation** — matches detected third-party libraries against the NVD database (requires `NVD_API_KEY`)
- **Threat intelligence** — VirusTotal hash lookup (requires `VIRUSTOTAL_API_KEY`)
- **Frida script generation** — AI-generated targeted Frida hook scripts from the decompiled class/method inventory (requires `ANTHROPIC_API_KEY`)
- **Dynamic analysis** — ADB device listing, session management, screenshot capture, mitmproxy traffic capture
- **HTML/JSON/PDF reports** — full-featured reports with MASVS v2 scoring, exported component tables, certificate details, native library hardening summary
- **MobSF-compatible REST API** — drop-in replacement for MobSF v1 endpoints
- **WebSocket progress** — real-time scan progress via `/ws/scan/:id`

## Quick Start

### Build

**Windows:**
```
build.bat
```
Output: `build\lancer-mobsf.exe`

**Linux / macOS:**
```bash
./build-linux.sh
```
Output: `build/lancer-mobsf`

**Requirements:** [Rust / Cargo](https://rustup.rs), Visual C++ Build Tools 2019+ (Windows only)

### CLI Usage

```bash
# Start API server (default port 7777)
lancer-mobsf serve --port 7777

# Scan an APK and print a text report
lancer-mobsf scan app.apk

# Scan and write HTML report
lancer-mobsf scan app.apk --format html --out report.html

# Scan and write JSON report
lancer-mobsf scan app.apk --format json --out report.json

# Retrieve a stored scan report
lancer-mobsf report <scan-id> --format html --out report.html

# List recent scans
lancer-mobsf list
```

## API Overview

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/upload` | Upload APK/IPA for scanning |
| `GET` | `/api/scans` | List recent scans |
| `GET` | `/api/scan/:id` | Get scan status |
| `GET` | `/api/scan/:id/findings` | Get scan findings |
| `GET` | `/api/scan/:id/report` | HTML report |
| `GET` | `/api/scan/:id/report.json` | JSON report |
| `GET` | `/api/scan/:id/report.pdf` | PDF report (requires weasyprint) |
| `POST` | `/api/scan/:id/triage` | Trigger AI triage (async) |
| `GET` | `/api/scan/:id/cves` | CVE correlation results |
| `POST` | `/api/scan/:id/generate-frida` | Generate Frida hook script |
| `GET` | `/api/scan/:id/frida-scripts` | List generated Frida scripts |
| `GET` | `/api/scan/:id/frida-scripts/:filename` | Download a Frida script |
| `GET` | `/api/devices` | List connected ADB devices |
| `POST` | `/api/dynamic/start` | Start dynamic analysis session |
| `GET` | `/ws/scan/:id` | WebSocket scan progress |

**MobSF v1 compatible endpoints:** `/api/v1/upload`, `/api/v1/scan`, `/api/v1/report_json`, `/api/v1/scorecard`, `/api/v1/scans`, `/api/v1/delete_scan`, `/api/v1/download_pdf`

### Frida Script Generation

```bash
curl -X POST http://localhost:7777/api/scan/<id>/generate-frida \
  -H 'Content-Type: application/json' \
  -d '{"intent": "bypass root detection", "class_filter": "com.example.*"}'
```

The endpoint returns a `GeneratedFridaScript` object with `script_content`, `description`, `target_classes`, and an optional `warning`.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Optional | Enables AI triage and Frida script generation |
| `VIRUSTOTAL_API_KEY` | Optional | Enables VirusTotal threat intelligence lookups |
| `NVD_API_KEY` | Optional | Enables CVE correlation via NVD (rate limit lifted with key) |
| `MOBSF_API_KEY` | Optional | Enables `Authorization: Token <key>` auth on v1 endpoints |
