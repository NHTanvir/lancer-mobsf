# RESEARCH DOSSIER: MobSF (Mobile Security Framework)

> Part of the Lancer ecosystem. A Rust clone of MobSF — all-in-one mobile app security testing framework. Build with Claude Code.
> Upstream: github.com/MobSF/Mobile-Security-Framework-MobSF (Python/Django, v4.x). Most bug bounty hunters' first mobile triage tool.

## Feature Parity Mandate

**`lancer-mobsf` MUST ship with 100% feature parity to the upstream `mobsf` tool — every flag, every subcommand, every output format, every probe / detector / module / payload / mode — plus a native Rust GUI on top.** This is not a "subset clone" — this is a full reimplementation in Rust with a GUI wrapper.

### Parity contract

- **Every CLI flag** documented in upstream `mobsf --help` (and the long-form man page / docs) must work in `lancer-mobsf --cli`.
- **Every output format** the upstream tool emits (text, JSON, XML, CSV, SARIF, custom formats) must round-trip through `lancer-mobsf` byte-equivalent where the format allows.
- **Every probe / detector / module / category / payload class / built-in script** must be ported. None silently dropped.
- **Every supported target type / input format / protocol / file format / language** must work.
- **Every configuration option** (config files, env vars, registry / settings entries) must be honoured.
- **Companion binaries / sub-tools** in the upstream suite (if any) must each get their own binary in this workspace.

### GUI on top

Every feature reachable via CLI is also reachable from the GUI (see `## GUI (Lancer-standard pattern)` below). The GUI is not a subset — it is an alternate frontend over the same `core` library that the CLI uses. The `core` crate is GUI-agnostic.

### Verification

- The `## Granular feature catalog` section below enumerates everything that must be supported.
- Reference: `tests/upstream_parity/` will pin upstream flag combinations + canned outputs as parity tests. CI fails if any flag is unsupported or output diverges.
- A `lancer-mobsf --self-test` flag runs the full parity matrix against a bundled reference target and prints pass/fail per upstream feature group.

### What is allowed to diverge

- **Performance** — Rust-native, async-first; we are allowed to be faster.
- **Memory footprint** — we are allowed to be smaller.
- **GUI** — entirely new (no upstream GUI to copy except where the upstream ships its own GUI like Zenmap / Wireshark UI / Ghidra GUI / jadx-gui — in which case our GUI must cover every panel the upstream GUI has, plus the Lancer-standard layout from `## GUI` below).
- **AI augmentation** — net-new (see `## AI augmentation ideas`).

### What is NOT allowed to diverge

- Any flag silently dropped, renamed, or behavior-changed compared to upstream.
- Any output format / record schema diverging in field names, types, or semantics.
- Any built-in script / detector / module not ported (mark explicitly with `[N/A — see note]` if genuinely impossible in Rust, e.g. NSE Lua scripts requiring features not in `mlua`).

## What it actually does

MobSF is an all-in-one automated mobile application security testing framework. You drop an APK, IPA, or APPX file in, and it produces a comprehensive security report combining static analysis (manifest issues, hardcoded secrets, dangerous permissions, insecure code patterns) and optional dynamic analysis (real-time API tracing, traffic capture, runtime behavior monitoring via Frida instrumentation on a connected Android device or emulator).

Concretely:
- **Static APK analysis**: Decompiles APK to smali + Java pseudocode (via jadx), parses `AndroidManifest.xml`, runs hundreds of regex/AST-based rules against the source, scores risk
- **Static IPA analysis**: Extracts binary, parses `Info.plist`, checks App Transport Security, URL schemes, hardcoded keys, weak crypto, jailbreak detection presence
- **Dynamic analysis**: Spins up an instrumented Android VM (their own "MobSF-VM" or a connected device with root + Frida), runs the app, captures HTTP/HTTPS traffic via mitmproxy, dumps file system changes, takes screenshots, exposes Frida REPL to user
- **Malware analysis**: VirusTotal integration, behavior signature matching, domain/IP reputation
- **MAS (Mobile Application Security) compliance**: Scores against OWASP MASVS/MASTG
- **API**: REST endpoints so CI pipelines can submit builds

It's the de-facto open-source mobile pentest tool — most bug bounty hunters run an APK through MobSF as the first triage step before manual analysis.

## Cloning reality check

**Brutally honest scope assessment for a solo Rust dev in 6-12 months:**

| Component | Clonable in 6-12 months? | Why |
|---|---|---|
| APK unpacking + manifest parsing | YES | `zip` + `axmldecoder` crates exist |
| DEX → semi-readable bytecode listing | YES | `dex` crate handles parsing |
| DEX → Java pseudocode (jadx equivalent) | NO | jadx is ~200k LOC of Java; no Rust equivalent. Wrap jadx as subprocess. |
| Regex/pattern rule engine | YES | Trivial — read MobSF's rules YAMLs and port |
| IPA static (plist, binary header checks) | YES | `plist` + `goblin` (Mach-O) |
| Web UI + report HTML | YES | Axum + Svelte (already your Lancer stack) |
| Dynamic analysis (emulator orchestration) | NO | MobSF ships a custom modified AVD image, Frida server pre-installed, mitmproxy CA pre-injected. Months of devops alone. |
| Frida script injection (talking to device) | MAYBE | Wrap `frida-core` via FFI for v1 |
| iOS dynamic | NO | Requires jailbroken iDevice + Frida + custom infra. Skip. |
| MASVS/MASTG scoring | YES | Just a JSON ruleset mapping findings to OWASP categories |
| VirusTotal integration | YES | HTTP API call |
| Malware behavior signatures | PARTIAL | Port their signatures, skip the ML-classifier they hint at |

**Realistic MVP target (Phase 1, 6-9 months)**: Rust + Axum static-only mobile scanner that ingests APK + IPA, produces HTML/JSON report comparable to MobSF v1 static output. Skip dynamic entirely v1. This alone is genuinely useful and ships.

**Phase 2 (months 9-18)**: Wrap `frida-core` for optional device hooking; orchestrate user's own connected device, don't ship a VM.

**Never realistic for solo dev**: Bundled instrumented emulator image, full iOS dynamic, ML-based malware classification. These are MobSF's least-loved features anyway.

## Internal architecture

MobSF is a Django monolith. Top-level layout:

```
Mobile-Security-Framework-MobSF/
├── mobsf/
│   ├── MobSF/              # Django project settings
│   ├── StaticAnalyzer/     # The core scanning engine
│   │   ├── views/
│   │   │   ├── android/    # APK pipeline
│   │   │   │   ├── static_analyzer.py    # Orchestrator
│   │   │   │   ├── manifest_analysis.py
│   │   │   │   ├── manifest_view.py
│   │   │   │   ├── code_analysis.py      # Pattern matching against decompiled source
│   │   │   │   ├── binary_analysis.py    # NDK / .so checks
│   │   │   │   ├── cert_analysis.py      # APK signing
│   │   │   │   ├── network_security.py   # NSC XML parsing
│   │   │   │   ├── permissions.py
│   │   │   │   ├── playstore.py          # Google Play metadata fetch
│   │   │   │   ├── strings.py            # Strings extraction
│   │   │   │   └── ...
│   │   │   ├── ios/        # IPA pipeline (mirrors android/)
│   │   │   ├── windows/    # APPX pipeline (rarely used)
│   │   │   └── common/     # Shared utilities (firebase check, etc.)
│   │   ├── tools/          # Bundled binaries: jadx, apktool, baksmali, aapt
│   │   └── tests/
│   ├── DynamicAnalyzer/    # Device-side runtime analysis
│   │   ├── views/android/
│   │   │   ├── analysis.py
│   │   │   ├── operations.py    # adb-driven actions (install, launch, screenshot)
│   │   │   ├── frida_core.py    # Frida script injection
│   │   │   └── ...
│   │   └── tools/frida/    # Pre-built Frida scripts bundled
│   ├── MalwareAnalyzer/
│   │   ├── views/
│   │   │   ├── android/apkid.py    # APKiD detection (packer/obfuscator)
│   │   │   ├── android/permissions.py
│   │   │   └── VirusTotal/
│   ├── install/            # OS-specific install scripts
│   └── templates/          # Django HTML templates for the report UI
├── poetry.lock
└── manage.py
```

### Static analysis pipeline (APK)

The orchestrator is `mobsf/StaticAnalyzer/views/android/static_analyzer.py::static_analyzer()`. Pipeline:

1. **Hash + dedupe**: SHA256 the APK; if same hash exists in `StaticAnalyzerAndroid` table, return cached
2. **Unzip APK** into `uploads/<MD5>/` — APK is just a zip with `classes.dex`, `resources.arsc`, `AndroidManifest.xml` (binary XML), `META-INF/` (signatures), `lib/<abi>/*.so`
3. **Manifest decode**: Binary AXML → text XML via internal port of `androguard`'s parser
4. **Manifest analysis** (`manifest_analysis.py`): walks the parsed tree, flags
   - `android:debuggable="true"`
   - `android:allowBackup="true"` (without `fullBackupContent` rules)
   - `android:usesCleartextTraffic="true"`
   - Exported activities/services/receivers/providers without permissions
   - Custom permission protection levels
   - Deep links (`<intent-filter>` with `<data>`)
   - SDK version mismatches
5. **Permission analysis** (`permissions.py`): looks up each `<uses-permission>` against a curated CSV of permission risk levels (dangerous/normal/signature)
6. **Cert analysis** (`cert_analysis.py`): parses `META-INF/CERT.RSA` (or v2/v3 signature blocks), extracts signer, checks v1/v2/v3 scheme presence, hashes the cert, checks against known debug-cert SHA
7. **Network security config**: parses `res/xml/network_security_config.xml`, flags `cleartextTrafficPermitted="true"` and missing pinning
8. **APK → Java**: shells out to bundled `jadx`. Falls back to `apktool` (smali) if jadx fails or times out
9. **Code analysis** (`code_analysis.py`): walks the extracted Java source tree, applies a giant ruleset of regex patterns from `views/android/rules/android_rules.yaml`. Each rule:
   ```yaml
   - id: android_logging
     message: The App logs information. Sensitive data should never be logged.
     type: Regex
     pattern: \bLog\.([vdeiw]|wtf)\s*\(
     severity: info
     input_case: exact
     cwe: cwe-532
     owasp-mobile: m1
     masvs: storage-3
   ```
10. **Binary (NDK) analysis**: scans `lib/*/*.so`, runs against checks for `RELRO`, `Stack Canary`, `NX`, `PIE`, `RPATH`, `RUNPATH`, `Symbols stripped`, `Fortify`. Done by parsing ELF headers.
11. **Strings extraction**: `aapt` for resource strings + binary strings extraction from .so
12. **Firebase URLs check**: regex hunts Firebase DB URLs in source, pings each to see if publicly readable (`<url>/.json` returning data = misconfig)
13. **Domain reputation**: extracts URLs from source, queries Google Safe Browsing
14. **Hardcoded secrets**: regex sweep (API keys, AWS, JWT, private keys) using patterns derived from gitleaks/truffleHog
15. **MASVS/MASTG mapping**: each finding tagged with MASVS category; aggregate into compliance score
16. **Save to SQLite** + render `templates/static_analysis/android_binary_analysis.html`

### Static analysis pipeline (IPA)

Mirrors the Android pipeline but with iOS-specific checks:
1. Unzip IPA → `Payload/AppName.app/`
2. Parse `Info.plist` (`plist` Python lib)
3. ATS (App Transport Security) check on `NSAppTransportSecurity` dict
4. URL scheme registration check (`CFBundleURLTypes`)
5. Provisioning profile parse (`embedded.mobileprovision` is a CMS blob containing a plist)
6. Mach-O binary checks (`macholib`): PIE flag, stack canary, ARC, encrypted (FairPlay), code signature
7. `class-dump`-equivalent: extracts Objective-C class/method names from the `__objc_classlist` section
8. Swift symbol demangling (when available)
9. Strings extraction
10. Code analysis: regex patterns against extracted symbols/strings (limited compared to Android since no source decompile)

### Dynamic analysis pipeline

1. User connects a rooted Android device or starts MobSF-VM
2. APK pushed via adb, installed
3. MobSF launches the app, hooks Frida server (pre-installed on MobSF-VM), injects bundled scripts:
   - `frida-scripts/android/default/` — universal SSL pinning bypass, root detection bypass, certificate dumper, crypto API logger
4. Live logcat + Frida output streamed to the web UI via WebSocket
5. mitmproxy intercepts traffic (CA pre-installed in MobSF-VM's user store; for normal devices, user must install)
6. User clicks "Start Activity Tester" — Frida script walks all exported activities and launches each via Intent, captures crashes
7. User clicks "Exported Activity Tester" — fuzzes intents
8. Screenshots taken on key events
9. After session, filesystem delta computed by comparing `/data/data/<pkg>/` before/after
10. Results merged into report

### Plugin system

There isn't a real plugin system. "Rules" are YAML files in `views/{android,ios}/rules/`; adding a rule = editing YAML. Frida scripts are JS files in `tools/frida/`; adding a hook = dropping a JS file. There is no plugin API in the Burp/IDA sense.

### Database schema

SQLite by default. Django ORM. Main models:
- `StaticAnalyzerAndroid` — one row per APK scan (MD5 PK, package name, version, permissions JSON, certificate info, findings JSON, score)
- `StaticAnalyzerIOS` — same shape for IPA
- `StaticAnalyzerWindows` — APPX
- `RecentScansDB` — scan history listing
- `EnqueuedScan` — async queue (Celery-style but in-process)

Findings are stored as serialized JSON blobs in TEXT columns — not relationally modeled. Fine for a single-user tool, bad for analytics.

## Granular feature catalog

**Android static checks (~250 distinct rules)**:
- Manifest: 30+ checks (debuggable, backup, cleartext, exported, deep links, protectionLevel issues)
- Code: Logging, WebView config (JS enabled, file:// access, `addJavascriptInterface`), SSL (TrustAllX509TrustManager, HostnameVerifier accepting all), insecure random (`java.util.Random` for crypto), MD5/SHA1 for security, weak ciphers (DES, RC4, AES ECB), hardcoded crypto keys, world-readable/writable file modes, external storage writes, intent redirection, Janus vulnerability, SQL injection (raw queries with concat), task hijacking (taskAffinity issues), pending intent mutability, broadcast issues, etc.
- Network Security Config parsing
- Domain extraction + URL reputation
- Firebase misconfig
- Hardcoded secrets (AWS, Google, JWT, SSH keys, etc.)
- Permission analysis with risk scoring
- Tracker library detection (using Exodus Privacy database)
- Third-party library detection
- Native binary analysis (RELRO/Canary/NX/PIE/Fortify/Symbols)
- APKiD packer/obfuscator detection
- VirusTotal lookup
- MalwareBazaar lookup

**iOS static checks (~100 rules)**:
- Info.plist analysis (ATS, URL schemes, background modes, NSLocation/Camera/etc. usage descriptions present)
- Provisioning profile parse
- Embedded entitlements
- Mach-O hardening (PIE, ARC, stack canary, encrypted)
- Class-dump → method name regex
- ATS violations (NSAllowsArbitraryLoads etc.)
- Universal Links (`com.apple.developer.associated-domains`)
- Push notification entitlement
- Insecure crypto API string matches
- Hardcoded keys/URLs
- Jailbreak detection presence (heuristic — looks for `jailbroken`, `cydia` strings)

**Dynamic features (Android only)**:
- Activity/service/provider launcher
- Exported activity tester (fuzzes intents)
- Frida REPL in browser
- Live API monitor (universal hooks log every interesting method call)
- Universal SSL pinning bypass (OkHttp, HttpsURLConnection, TrustManagerImpl, Conscrypt, Cronet, Flutter)
- Root detection bypass
- Anti-debugging bypass
- Crypto API logger (logs all `javax.crypto.Cipher` operations with plaintext + keys)
- File system change tracker
- HTTP(S) capture via mitmproxy
- Screenshot capture
- Memory dump
- KeyStore dump
- Shared Preferences dump

**Report formats**: HTML (web UI), PDF (WeasyPrint), JSON (REST API), SARIF (mobsfscan sibling), SonarQube format (mobsfscan)

## Supported input formats (full upstream parity matrix)

| Family | Format | Detail | Lancer status |
|---|---|---|---|
| Android | APK | Standard package | Phase 1 |
| Android | AAB | App Bundle — auto-convert AAB→APK via bundletool subprocess before pipeline | Phase 1 |
| Android | XAPK | Multi-APK wrapper (splits + assets) — unzip + re-merge | Phase 1 |
| Android | APKS / split APKs | Pull from device + base+config merge | Phase 2 |
| Android | ZIP (source) | Java/Kotlin source tree — invoke `mobsfscan` engine path | Phase 2 |
| iOS | IPA | Standard package | Phase 2 |
| iOS | dylib | Dynamic library Mach-O — header + symbol checks only | Phase 2 |
| iOS | .a | Static archive — ELF/Mach-O `ar` unpack then header checks (v4.4.1 fixed extraction CVE) | Phase 2 |
| iOS | .so | Shared object (cross-compiled native) — ELF header + hardening checks | Phase 2 |
| iOS | ZIP (source) | Swift/Objective-C source tree → mobsfscan engine path | Phase 2 |
| Windows | APPX | Re-added in v4.3; still niche | Phase 3 (deferred / [N/A] candidate) |

All input formats must be accepted via `lancer-mobsf scan <path>`, REST `POST /api/v1/upload`, and the GUI drag-and-drop sidebar. CLI must reject unsupported types with the same exit code as upstream.

## Source-code scan engine (mobsfscan parity)

Upstream ships `MobSF/mobsfscan` as a separate companion CLI. We ship `lancer-mobsfscan` binary in the same workspace.

- **Languages**: Java, Kotlin, Swift, Objective-C (engine reuses the same YAML ruleset as the APK pipeline plus an iOS-source ruleset)
- **Engine**: Upstream uses semgrep + libsast pattern matcher. Rust equivalent: combined `regex-automata::meta` for fixed-pattern rules + `tree-sitter` (with `tree-sitter-java`, `tree-sitter-kotlin`, `tree-sitter-swift`, `tree-sitter-objc`) for AST-based rules. semgrep itself has no Rust equivalent; for parity we ship a `--semgrep-compat` mode that shells out to semgrep if it is on PATH and translates rule output.
- **Output formats**: JSON, SARIF (for GitHub Code Scanning), SonarQube, HTML, plain text
- **Config**: honours a `.mobsf` config file in the project root (suppressions, custom rule dir, severity overrides)
- **CI/CD**: GitHub Action wrapper (workflow YAML) + GitLab CI template + pre-commit hook
- **Exit codes**: non-zero on findings above a configured severity threshold (matches upstream behaviour)

## Reporting + export parity

- **HTML report**: full styled report (web UI) — match upstream template structure, include MASVS table, findings cards, charts, certificate trust chain visualisation, NSC summary
- **PDF report**: WeasyPrint upstream → Lancer uses `headless_chrome` (Chromium PDF) or shells out to `weasyprint` for byte-equivalent layout. The Rust-native `printpdf`/`genpdf` route is too low-fidelity for parity.
- **JSON report**: full scan record (must be field-equivalent to upstream REST `/api/v1/report_json` schema so existing CI integrations consuming MobSF JSON work unchanged)
- **SARIF report**: for code-scan flows (mobsfscan parity)
- **SBOM**: see below
- **CSV / Markdown**: additional Lancer-standard exports
- **STIX 2.1**: malware-analyser export (matches upstream `MalwareAnalyzer` JSON-LD output)

## SBOM (Software Bill of Materials) — v4.3+ feature

Upstream added Android SBOM analysis in v4.3.0. Lancer-mobsf must:

- Extract every embedded library (Java jars, AAR transitive deps, native `.so` libraries with name+version where detectable from symbol tables, embedded SDKs)
- Emit **CycloneDX 1.6 JSON** and **SPDX 2.3 JSON** (use `cyclonedx-bom` / `spdx-rs` crates)
- Cross-reference component versions against the **OSV.dev** database and the local NVD mirror for CVE matches
- Surface a per-finding "vulnerable component" badge in the GUI Findings table
- iOS SBOM is upstream-roadmap; Lancer ships it earlier (Phase 3) since the data shape is the same

## MASVS / MASTG parity (v2 + ongoing)

- Each finding tagged with **MASVS category** (MASVS-STORAGE, MASVS-CRYPTO, MASVS-AUTH, MASVS-NETWORK, MASVS-PLATFORM, MASVS-CODE, MASVS-RESILIENCE, MASVS-PRIVACY) AND the specific **MASTG test ID** (e.g. `MASTG-TEST-0001`)
- Aggregate L1 / L2 compliance score
- Render the MASVS compliance dashboard with pass/fail per requirement, gap analysis, and recommended fixes
- Pull MASTG YAML at build (https://github.com/OWASP/owasp-mastg) and bake into the binary
- Lancer-mobsf is registered as **MASTG-TOOL-0035** equivalent — list in `--version` output

## Behavior analysis + anti-analysis bypass (v4.3+)

- **Ported Quark rules**: upstream replaced Quark engine with native ported rules in v4.3 — Lancer ports the same rules (YAML in `rules/behavior/`) and applies them post-decompile
- **Behavior signature matching**: combines API call sequences, permission combinations, and string evidence into "this app sends SMS without UI", "this app uses accessibility service for screen scrape", etc.
- **Anti-analysis detection**: flag packed/obfuscated/native-bridged samples (APKiD + custom signatures)
- **Anti-analysis bypass**: handle reserved-filename conflicts on Windows extraction, zip-bomb caps, path-traversal guards, malicious SVG icons (v4.4.1 CVEs all need parity hardening)

## Malware analyser parity

Upstream `MalwareAnalyzer` hits multiple back-ends. Lancer-mobsf must wire each:

- **VirusTotal** v3 API — hash lookup + optional sample upload
- **MalwareBazaar** — hash lookup
- **Triage** (tria.ge / Recorded Future) — hash lookup
- **Hybrid Analysis** — hash lookup
- **MetaDefender** — multi-engine hash lookup
- **APKiD** — packer / obfuscator / anti-emulation fingerprinting (ship as embedded YARA rules via `yara-x` crate)
- **Tracker / SDK identification** — Exodus Privacy DB
- **Domain / IP reputation** — Google Safe Browsing + AbuseIPDB
- **Behaviour signatures** — ported Quark + native signatures

All back-ends keyed via `~/.config/lancer-mobsf/integrations.toml` (matches upstream's settings.py pattern).

## Dynamic analyser parity (full upstream surface)

**Android dynamic** (full parity with upstream v4.4):
- Real device (rooted, USB or wireless ADB) OR Genymotion / Android Studio AVD orchestration
- Frida 17+ server lifecycle management (auto-push frida-server matching device arch)
- Frida script library (bundled in `frida-scripts/`):
  - Universal SSL pinning bypass (OkHttp 3/4/5, HttpsURLConnection, TrustManagerImpl, Conscrypt, Cronet, Flutter, Xamarin, React Native, Cordova)
  - Root detection bypass
  - Anti-debugging / anti-frida bypass
  - Crypto API logger (`javax.crypto.Cipher`, `Mac`, `MessageDigest`, `KeyStore`)
  - File / SharedPreferences / SQLite tap
  - WebView call tap
  - Intent tap
  - Custom hook builder UI (user picks class/method → script generated)
- Live API monitor (universal hooks)
- Live logcat stream
- HTTP(S) capture via integrated Lancer proxy engine (Burp/MITM clone reuse)
- Activity / Service / Provider / Receiver launcher
- Exported component fuzzer (intent fuzz)
- Deep-link trigger (v4.0.7) — drive `am start -d <uri>` from GUI
- Screenshot capture at events
- File-system delta (`/data/data/<pkg>/` diff)
- KeyStore dump
- SharedPreferences dump
- SQLite DB dump (with SQL viewer — note v4.4.6 patched SQLi in this viewer; ours uses parameterised `sqlx` queries from day 1)
- Memory dump
- Bridge support for Frida (v4.4.1)
- Split-APK pull from device (v4.2)

**iOS dynamic** (parity surface — even if we mark much of it [DEFERRED]):
- Jailbroken iDevice path (USB, libimobiledevice)
- Corellium cloud path (REST API to spin a virtual iDevice; v4.3+ added this)
- Frida 17+ server on the device
- iOS Frida script library: SSL pinning bypass (NSURLSession, AFNetworking, Alamofire, TrustKit), jailbreak detection bypass, biometric bypass, pasteboard tap, keychain dump
- IPA install + launch
- HTTP(S) capture via Lancer proxy
- File system / NSUserDefaults dump
- Screenshot capture
- Phase 4 target; until then `--ios-dynamic=corellium` mode shells out to upstream MobSF if available (graceful degrade)

## REST API parity (must match upstream byte-for-byte)

Endpoint surface (every upstream `/api/v1/*` route must work so existing CI integrations swap base URL only):

- `POST /api/v1/upload` — accept apk/aab/xapk/zip/ipa/dylib/.a/.so/appx; returns `{hash, scan_type, file_name}`
- `POST /api/v1/scan` — trigger static scan
- `POST /api/v1/scan_logs` — real-time scan log stream (v4.0.7)
- `POST /api/v1/scan_status` — scan status polling (v4.0.7)
- `POST /api/v1/report_json` — full JSON report
- `POST /api/v1/report_pdf` — PDF report
- `POST /api/v1/view_source` — view decompiled source
- `POST /api/v1/delete_scan` — drop a scan
- `GET  /api/v1/scans` — list scans (with v4.1.3 search by package/app/file)
- `POST /api/v1/suppress_by_rule` / `suppress_by_files` — rule suppression
- `POST /api/v1/list_suppressions` / `delete_suppression`
- `POST /api/v1/compare` — diff two scans
- `POST /api/v1/dynamic/start_analysis` — kick off dynamic
- `POST /api/v1/dynamic/get_report` — dynamic report
- `POST /api/v1/dynamic/view_logcat`, `frida_logs`, `httptools` — dynamic stream pulls
- `POST /api/v1/dynamic/sast` — runtime SAST replay
- `GET  /api/v1/dynamic/get_apps` — installed app list
- `GET  /api/v1/dynamic/get_endpoints` — captured HTTP endpoints
- `POST /api/v1/async_scan_status` (v4.3) — async queue status
- `POST /api/v1/sbom` — SBOM export
- `POST /api/v1/malware_lookup` — multi-source malware lookup

All endpoints require an API key in `Authorization: <key>` header (upstream pattern).

## MCP server parity (v4.3+ feature)

Upstream v4.3+ added an MCP (Model Context Protocol) server so AI agents (Claude, 5ire, Cursor, etc.) can drive scans. Lancer-mobsf must ship:

- `lancer-mobsf mcp` subcommand boots an MCP server over stdio (and `--sse` flag for SSE transport, `--http` for streamable HTTP)
- Tools exposed:
  - `upload_file(path)` → scan_hash
  - `start_scan(scan_hash)` → status
  - `get_scan_status(scan_hash)`
  - `get_scan_summary(scan_hash, severity_filter?)` — auto-filtered to avoid context overflow (large strings/secrets paginated)
  - `get_findings(scan_hash, masvs_category?, cwe?)`
  - `get_sbom(scan_hash, format)`
  - `start_dynamic(scan_hash, target_device?)`
  - `stop_dynamic(scan_hash)`
  - `get_dynamic_report(scan_hash)`
- MCP manifest published in `mcp-manifest.json` for client auto-discovery

## Enterprise / auth parity (v4.0.7 + v4.3.2)

- API-key auth (default)
- **SSO**: SAML 2.0 + OIDC; Okta tested upstream — Lancer wires generic OIDC + the `samael` crate for SAML
- **Role-based access**: `Admin`, `Maintainer`, `Viewer` with user-defined SSO role mapping (v4.3.2)
- Anti-SSRF guards on Firebase URL probe and asset-link verifier (v4.3.2 hardening)
- Strict user-email validation (v4.4.1)
- Audit log (who ran what scan when) — net-new in Lancer for compliance use cases

## Backend / runtime parity

- **SQLite default**, **PostgreSQL** supported out-of-the-box (v4.1.3 made Postgres default in Docker) — Lancer uses `sqlx` with both feature flags
- **Async queue**: upstream v4.3 moved to `django-q2` — Lancer uses `tokio` task queue + `sqlx`-backed durable job table (`scan_jobs`) for crash-safe resume
- **Docker image** parity: ship `lancer-mobsf` Docker image (Alpine + cargo-chef build) for drop-in upstream replacement; expose same env vars (`MOBSF_*`)
- **Bundled jadx** subprocess (matches upstream — jadx-only pipeline since v4.x dropped bundled apktool)
- **bundletool** subprocess for AAB → APK conversion (v4.0.7 feature)

## Frida 17+ requirement (v4.4.1)

Upstream v4.4.1 mandates Frida 17+. Lancer-mobsf:
- Ships `frida` crate pinned to bindings matching `frida-core` 17+
- Auto-detects device frida-server version; refuses < 17 with clear error and auto-push of bundled frida-server binaries for arm/arm64/x86/x86_64
- Honours new Frida bridge support (multi-language script hosting)

## Web API Viewer (upstream UI feature)

- Captured HTTP/HTTPS endpoints view with request/response detail
- Manual replay / edit-and-send (mini-Repeater)
- Send-to-Lancer (parent Burp clone) for full intruder/repeater workflow
- Mark endpoint as sensitive, attach finding

## Asset linker mapping (v4.x feature)

- Track which UI screen / activity / view controller contains which finding
- Build an "asset graph" from manifest + decompiled resources + runtime screenshots
- GUI: click a finding → highlight which screen/UI element exposes it
- Especially valuable for triage (manual exploit needs the navigation path)

## Engineering hard parts

1. **Java pseudocode generation is a research-grade problem.** Reusing jadx is the only sane path. Writing your own DEX → Java decompiler in Rust is 1-2 person-years.
2. **AXML (binary Android Manifest) parsing** is non-trivial but solved — port androguard's logic or use `axmldecoder` (incomplete for newer namespaces; you'll find bugs).
3. **APK v2/v3/v4 signature scheme verification** requires re-implementing the full APK signing block parser; not hard but tedious. The cert parsing itself is just ASN.1/X.509.
4. **Mach-O parsing** with `goblin` is OK for headers, but extracting Objective-C class metadata from `__objc_classlist`/`__objc_classname`/`__objc_methname` sections is finicky pointer-chasing that goblin doesn't do for you. `objc2` ecosystem has some helpers; you'll write code.
5. **Swift symbol demangling**: there is `swift-demangle` (Apple binary) and a Rust port `swift-demangle-rs` exists but lags Swift versions. Plan to shell out.
6. **Frida script orchestration over ADB**: managing device state, port-forwards, server lifecycle, USB disconnects, multi-device. Real complexity is in the long tail of device weirdness, not the happy path.
7. **mitmproxy replacement in Rust**: `hudsucker` is the only real option and it's smaller than mitmproxy. For your Burp clone (Lancer) you're already solving this; reuse the same engine.
8. **Provisioning profile parsing**: CMS-signed plist. Use `cms` crate + `plist`.
9. **Rule engine performance**: MobSF's regex-everywhere approach is O(rules × files × file_size). On a big APK with hundreds of decompiled Java files, this takes minutes in Python. Rust will be 10-100x faster naturally, but consider building a single combined NFA via `regex-automata::meta` to scan each file once.
10. **Tracker/library detection** needs a maintained database (Exodus Privacy publishes one as JSON). Easy to consume; ongoing curation problem.
11. **MASVS/MASTG mapping** changes every year. Easy code, ongoing rule maintenance.
12. **iOS class-dump replacement**: writing this from scratch is a project. There's `class-dump-rs` but it's incomplete. Plan to shell out to `class-dump` binary or `objc-classdump-rs`.

## Rust library mapping

| Need | Crate | Notes |
|---|---|---|
| APK zip extraction | `zip` | Standard, mature |
| Binary AndroidManifest.xml | `axmldecoder` or `abxml-rs` | axmldecoder is more maintained |
| DEX parsing | `dex` | Mature; provides class/method/instruction iteration |
| DEX → smali listing | Hand-write atop `dex` | Smali is just human-readable Dalvik bytecode |
| DEX → Java | Wrap jadx subprocess | Don't write your own. Period. |
| Native ELF analysis | `goblin` | Headers, sections, symbols |
| Hardening checks (NX, RELRO, etc.) | `checksec-rs` or hand-roll over goblin | checksec-rs covers most |
| iOS plist | `plist` | Handles XML + binary plist |
| Mach-O | `goblin` | Full Mach-O support |
| Swift demangling | `swift-demangle-rs` or shell out to `swift-demangle` | Rust crate often lags |
| Obj-C symbol parsing | hand-roll on `goblin` Mach-O sections | No good crate |
| Regex rule engine | `regex` + `regex-automata::meta` for combined automata | Use `aho-corasick` for fixed-string rule prefilter |
| Cert/signature parsing | `x509-cert`, `cms`, `pkcs7` | RustCrypto ecosystem |
| AXML to actual XML output | `quick-xml` | For emitting human-readable manifest |
| HTTP traffic interception | `hudsucker` | MITM library |
| ADB protocol | `adb_client` or `mozdevice` | adb_client is pure Rust |
| Frida integration | `frida` (frida-rust) | Bindings to frida-core |
| Web framework | `axum` | Matches Lancer |
| JSON serialization | `serde_json` | Standard |
| YAML rule loading | `serde_yaml` | Standard |
| HTML templating | `askama` or `minijinja` | minijinja is more flexible |
| Async runtime | `tokio` | Standard |
| Database | `sqlx` (SQLite) | Matches Lancer probably |
| PDF report | `printpdf` or `genpdf` or shell out to `weasyprint` | Native Rust PDF is painful; consider shelling out |
| Frontend | Svelte | Matches Lancer |
| Tracker DB | Pull Exodus JSON at build | https://etip.exodus-privacy.eu.org/api/ |
| OWASP MASVS rules | Pull from MASTG repo at build | They publish YAML |

## 2024-2026 state

- **MobSF 4.x** (released throughout 2024-2025) brought MASVS/MASTG v2 integration, improved iOS support, better Frida script library, queue-based scanning with proper async, deprecated Windows APPX support (removed late 2025), added asset linker mapping for tracking which screen contains which finding
- **MobSF 4.3+** added MCP server support so AI agents can drive scans
- **Async + Hyperscan**: MobSF moved hot regex paths to Hyperscan in 2025 builds — gave 5-10x speedup on big APKs. Your Rust clone gets that for free via combined regex automata.
- **Python 3.12+** required as of 2025
- **Dropped legacy Android tooling**: removed bundled apktool in favor of jadx-only pipeline (jadx now does resource decoding too)
- **MAS-Track integration**: optional cloud component for tracking finding triage across scans
- The maintainer (Ajin Abraham) is active but largely solo. PR turnaround can be slow.

### 2026-05-30 research note (deep-research pass)

Verified against upstream README, releases page, mobsf.live and the v4.4.x changelog. Concrete additions / corrections folded into the catalog above:

- **Latest stable**: v4.4.6 (March 2026) — patched SQLi in SQLite DB viewer; v4.4.5 improved URL case preservation and IP detection.
- **Frida 17+ is now mandatory** (v4.4.1, Aug 2025). Corellium iOS devices must run Frida server >=17. Bridge support added.
- **iOS dynamic via Corellium** is a first-class upstream path now (not jailbreak-only). Lancer-mobsf treats this as Phase 4 with a `--ios-dynamic=corellium` mode that can either shell out to upstream MobSF or hit Corellium REST directly.
- **MCP server** (v4.3+) is real and used by AI agents (Claude / 5ire / Cursor). See `## MCP server parity` for the tool surface we mirror.
- **Async queue**: upstream moved to `django-q2` in v4.3.0. Lancer-mobsf uses a tokio + sqlx durable job queue for crash-safe resume — semantically equivalent, faster.
- **SBOM**: Android SBOM ingest landed in v4.3.0. CycloneDX 1.6 + SPDX 2.3 outputs are now table-stakes — both wired in our catalog.
- **Behavior analysis**: Quark engine replaced by ported native rules in v4.3.0 — Lancer ports the same YAML.
- **Multi-source malware lookup**: VirusTotal + Triage + Hybrid Analysis + MetaDefender (added v4.3.0).
- **Postgres default in Docker** since v4.1.3 — Lancer compiles with both SQLite + Postgres `sqlx` feature flags.
- **SSO**: Okta-tested SSO + RBAC role mapping (Maintainer / Viewer) added v4.0.7 / v4.3.2. SAML 2.0 + OIDC paths required for enterprise parity.
- **mobsfscan sibling tool** (Java/Kotlin/Swift/Objective-C source scanner powered by semgrep + libsast) is an entirely separate binary we owe as `lancer-mobsfscan`. Outputs SARIF, SonarQube, JSON, HTML, plain text.
- **Input formats** are wider than originally catalogued: APK + AAB + XAPK + split-APK + ZIP (source) for Android; IPA + dylib + .a + .so + ZIP (source) for iOS; APPX still supported (not dropped — earlier note was wrong).
- **AAB → APK conversion** (v4.0.7) requires bundletool subprocess.
- **Deep-link triggers**, **split-APK pull from device**, **real-time scan logs over REST** all added in v4.0.7 / v4.2 / v4.3 — wired into REST + dynamic parity sections.
- **Hyperscan** was actually replaced upstream — they kept `re2` + `libsast`; Lancer's `regex-automata::meta` combined-NFA is equivalent and stays on the roadmap.
- **MASTG tool-catalog ID**: upstream is `MASTG-TOOL-0035`. Lancer-mobsf prints its own equivalent ID in `--version`.
- **mobsf.live** is the upstream-hosted cloud analyzer (free tier). We do not host a SaaS — single-binary local install only.

### Research note — 2026-05-31 (deep release-by-release walk v3.9 → v4.4.6)

Direct walk of `github.com/MobSF/Mobile-Security-Framework-MobSF/releases`. Per-version deltas not yet captured at this granularity:

- **v3.9.7 (Mar 2025).** Corellium iOS dynamic analysis platform integration with reverse SSH tunnel; Frida RPC hooks + injected-code view + spawn/attach/session API; Runtime-executable-tampering detection (in-binary integrity checks); Framework dylib analysis; **Global datatable export** to PDF / CSV / XLS from any findings table; APK/IPA library scanning (recursive .so / .dylib analysis); major report-rendering perf for >2k findings. Security CVEs: LFI, SSRF in AppLinks/Firebase checks, arbitrary file writes on Windows. Our `lancer-mobsf` global-export bar must support the same three formats.
- **v4.0.7 (Oct 2025).** **SSO + Okta SSO** + authorization framework (RBAC); **AAB → APK conversion** via bundletool subprocess (required for Dynamic Analyzer); **Deep-link trigger support** in Dynamic Analyzer (auto-invoke `adb shell am start -a android.intent.action.VIEW -d <deeplink>`); Real-time scan status/logs streamed to UI + REST; Pagination for recent scans. Security: SSRF in Firebase checks, zip slip in `ar` extraction.
- **v4.1.3 (Nov 2025).** SAST perf via `libsast` upgrade (timeout issue on huge codebases); Firebase Remote Config check; Scan search by package/app/filename via REST API; **Postgres support by default** (was SQLite-only); Python 3.12 support.
- **v4.3.0 (Jan 2026) — major release.** Django-q2 **async analysis** with REST API support; Android **SBOM analysis** (CycloneDX + SPDX, ingested from `.aab` `BUNDLE-METADATA/` if present, else recovered from manifest + DEX + library scan); Android anti-analysis bypasses (emulator-detection bypass on a corpus of common evasion patterns); Packed-APK handling (`MultiDex`, `legacy-multidex`, Themis-style); iOS PNG-uncrush support on Windows/Linux (was macOS-only); Multi-source malware SHA2 lookup: **VirusTotal + Triage + Hybrid Analysis + MetaDefender**; New Frida scripts: **intent dumper, runtime tracer, audit-webview, JavaScript-interface tracing**; Tasks list returns string status; Download endpoint improvements; **Quark engine replaced** by ported native YAML rules in `behavior/`.
- **v4.3.2 (Mar 2026).** **User-defined SSO role mapping** for Maintainer/Viewer; anti-SSRF checks improved; security fixes for partial-DoS via strict regex, privilege escalation via leaked API key, stored XSS in iOS dynamic analysis.
- **v4.4.1 (Aug 2026).** **Frida 17+ mandatory** with rewritten scripts for logging, SSL pinning bypass, cert pinning bypass; Four CVEs patched: (1) **zip-bomb DoS** on upload, (2) **stored XSS via SVG icons**, (3) **arbitrary file writes** in dynamic-analysis result handler, (4) **path traversal** in framework-asset retrieval; Strict user-email validation; Improved proxy-settings application.
- **v4.4.2 (Aug 2026).** **Python 3.13** compatibility; Removed pinned dependencies (`xmlsec`, `lxml`) for OS-package compat; Updated Android permission list (Android 15 / Baklava additions); Bumped mitmproxy + httptools + apkid versions.
- **v4.4.5 (Jan 2026).** Improved IP detection across decompiled code (was missing IPv6 + IPv4 short-form); Malware-domain check code QA; **URL extraction case-sensitivity preserved** (previously lower-cased every URL — broke case-sensitive endpoints); **Stored XSS in manifest analysis** fixed; Django + mitmproxy + httptools + apkid dependency bumps.
- **v4.4.6 (Mar 2026 — current).** **SQL Injection in SQLite DB viewer** fixed (was constructing query string from user input); RequestedAuthnContext disabled during SSO SAML requests (some IdPs reject the element entirely).

**Frida script catalog (v4.4.1 set, per-script semantics):**
- `frida-logger.js` — logs `console.log` / `console.warn` from any agent
- `ssl-pinning-bypass.js` — patches `okhttp3.CertificatePinner`, `javax.net.ssl.TrustManager`, `X509TrustManager`
- `cert-pinning-bypass-ios.js` — patches `SecTrustEvaluate` family
- `runtime-executable-tampering.js` — checks for self-signing patches at runtime
- `intent-dumper.js` (v4.3.0) — hooks `Activity.startActivity` / `startService` / `sendBroadcast`, dumps Intent payload + flags + extras
- `runtime-tracer.js` (v4.3.0) — generic method-call logger across user code
- `audit-webview.js` (v4.3.0) — hooks `WebView.loadUrl`, `addJavascriptInterface`, `setWebContentsDebuggingEnabled`
- `javascript-interface-tracer.js` (v4.3.0) — for every `@JavascriptInterface` exposed Java method, log incoming JS → Java call args
- `network-tracer.js` — hooks OkHttp / URLConnection / NSURLSession / CFNetwork, captures request/response
- `keychain-dumper-ios.js` — dumps SecItemCopyMatching results
- `realm-dumper.js` — opens local Realm DB
- `sqlite-dumper.js` — dumps SQLite DBs the app opens
- `crypto-tracer.js` — hooks `Cipher.doFinal`, `Mac.doFinal`, `MessageDigest.digest`, prints input/output
- `clipboard-dumper.js` — hooks `ClipboardManager.setPrimaryClip`/`getPrimaryClip`
- `biometric-bypass.js` — hooks `BiometricPrompt.authenticate` callback (and iOS LAContext)
- `root-detection-bypass.js` — patches all known root-check vectors
- `jailbreak-detection-bypass-ios.js` — same for iOS jailbreak checks

All Frida scripts must ship in our binary and be runnable from the dynamic-analysis UI with one click.

Sources: [MobSF releases](https://github.com/MobSF/Mobile-Security-Framework-MobSF/releases), [MobSF Changelog](https://mobsf.github.io/Mobile-Security-Framework-MobSF/changelog.html), [MASTG-TOOL-0040 MobSF iOS](https://mas.owasp.org/MASTG/tools/ios/MASTG-TOOL-0040/), [MobSF Install/Use Guide 2026](https://ringsafe.in/mobsf/).

## Bug bounty workflows

- **Initial triage**: Submit target APK to MobSF, wait 5-10 minutes for static, skim findings sorted by severity. Look for: exported activities (intent redirection), debuggable=true (free RCE on dev builds), hardcoded API keys, Firebase misconfigs, weak crypto, deep links allowing arbitrary URL load
- **Secret hunting**: MobSF's hardcoded secrets section often turns up AWS keys, Google Maps keys (paid abuse), Firebase configs
- **Exported component testing**: List of exported activities from MobSF feeds directly into `am start -n` commands or Drozer
- **Deep link enumeration**: MobSF lists every `<intent-filter><data>`; you grep for `http`/`https` schemes, then test each for open redirect or arbitrary load in WebView
- **Library version recon**: MobSF lists detected libraries with versions; cross-reference CVE database
- **Dynamic SSL bypass**: connect rooted phone, enable Frida bypass, sniff traffic
- **Mobile-then-API pivot**: most bugs aren't in the APK itself — APK reveals API endpoints, JWT secrets, internal hostnames. MobSF surfaces those, you pivot to web bug bounty workflow

## AI augmentation ideas

1. **Triage summarizer**: LLM reads the 200-finding scan, produces "top 5 bugs to investigate" with exploit hypotheses
2. **Hardcoded secret context-checker**: distinguish real secret from test/placeholder using LLM judgment on surrounding code
3. **Exported component exploit suggester**: feed activity manifest + decompiled handler code → "this activity is callable with these intent extras; here's a likely-exploitable input"
4. **Deep link fuzz seed generation**: from deep link pattern + decompiled handler → "try these URLs"
5. **Library CVE correlation**: detected libs + versions → MITRE NVD lookup → "this app uses X v1.2 which has CVE-Y, exploitable in this app because..."
6. **Custom Frida script generation**: "hook all methods that return a JWT" → LLM produces a Frida script based on the class/method inventory MobSF extracted
7. **MASVS rationale**: turn raw findings into MASVS-categorized executive summary
8. **False positive suppressor**: LLM-trained on triage history to auto-mark low-confidence findings as "likely FP"

## Implementation phases

**Phase 0 (month 0-1): infrastructure**
- Axum app scaffold matching Lancer's pattern
- SQLite schema for scans
- Upload endpoint that accepts APK/IPA, stores blob, returns scan ID
- WebSocket channel for live scan progress

**Phase 1 (month 1-4): Android static MVP**
- APK unzip
- AXML manifest parser → text XML
- Manifest analyzer (top 30 manifest rules)
- Permission analyzer with risk DB
- Cert chain parser
- jadx wrapper subprocess (vendor jadx binary)
- Rule engine reading MobSF-compatible YAML
- Port top 50 MobSF Android rules
- ELF hardening checks
- Basic HTML report
- JSON export

**Phase 2 (month 4-6): rule completeness + iOS**
- Port remaining ~200 MobSF Android rules
- IPA pipeline (plist, Mach-O, embedded.mobileprovision)
- Top 50 iOS rules
- ATS validator
- Hardcoded secret scanner (gitleaks-style rules + ML-like entropy)
- Tracker DB integration

**Phase 3 (month 6-9): polish + bb workflows**
- MASVS/MASTG scoring + reports
- PDF export (consider weasyprint subprocess)
- CLI mode (`lancer mobile scan app.apk`)
- REST API matching MobSF's so existing CI integrations work
- VirusTotal/MalwareBazaar lookup

**Phase 4 (month 9-15): dynamic — optional**
- ADB device manager
- Frida-core FFI integration
- Bundled universal-bypass Frida script library
- mitmproxy-equivalent traffic capture via shared Lancer proxy engine (you have this already)
- Activity launcher / exported tester
- Screenshot capture via adb
- File system delta

**Phase 5 (month 15-24): AI features**
- Triage summarizer
- Custom Frida script generator
- CVE correlation engine

**Never (or year 3+)**: bundled custom emulator image, iOS dynamic, ML malware classifier, MAS-Track equivalent

## Alternative: wrap instead of clone

Honestly, the highest-value play is:
1. **Embed MobSF as a subprocess/Docker** behind a Lancer "Mobile" tab — let MobSF do the scan, ingest its JSON, render in your UI, add your AI layer on top. Saves ~12 months. Most of MobSF's value is its accumulated rules; reimplementing those is busywork.
2. **Or**: ship the Rust scanner for static analysis only (real speed win, good UX win, manageable scope), and call out to MobSF for dynamic-only when user requests it. Best of both.

Going full clone makes sense only if you want a single-binary distribution story (MobSF's Python+Django+jadx+frida deploy story is painful) or you want to refactor the rule engine to be 100x faster — both legitimate motivations.

---

## GUI (Lancer-standard pattern)

`lancer-mobsf` ships as a **native GUI application** by default. The CLI surface listed in `## Granular feature catalog` is still available behind a `--cli` flag (or via the `lancer-mobsf-cli` companion binary), but the **plain `lancer-mobsf` invocation opens a native desktop window**, matching every other tool in the Lancer ecosystem. No terminal-only mode.

### Framework

Pure-Rust GUI stack — no JavaScript, no Node, single static binary:

| Crate | Role |
|-------|------|
| `eframe` | Cross-platform window + event loop wrapper around `egui` |
| `egui` | Immediate-mode UI widgets (panels, tables, forms, menus, drag-and-drop) |
| `egui_extras` | Sortable tables, image loaders, syntax highlighting, date pickers |
| `egui_plot` | Charts, graphs, timelines (histograms, activity meters, progress) |
| `rfd` | Native file/folder pickers (open file, save dialog) |
| `directories` | Per-OS config dir (`~/.config/lancer-mobsf/`, `%APPDATA%\lancer-mobsf\`, etc.) |
| `image` | Screenshot / preview rendering inside egui |
| `arboard` | Clipboard read/write for "copy result" actions |
| `muda` | Native menu bar (Linux / macOS / Windows) |
| `egui-notify` | Toast notifications |

Optional dark/light theme persisted to `lancer-mobsf-config.json` via `serde_json`.

### Window layout

Three-pane layout matching the Lancer mothership GUI:

```
┌─────────────────────────────────────────────────────────────────────┐
│  File   Tools   Settings   Help                              [≡]    │
├──────────┬────────────────────────────────────────┬─────────────────┤
│          │                                        │                 │
│  Inputs  │           Main view                    │  Detail pane    │
│  / jobs  │  (table of results / source tree /     │  (full record / │
│  / scope │   findings list / packet list / etc.)  │   bytes / src / │
│          │                                        │   remediation)  │
│          │                                        │                 │
├──────────┴────────────────────────────────────────┴─────────────────┤
│  Status: idle           Items: 0          [Open]  [Run]  [Export]   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Left sidebar (200-300px)** — inputs / queued jobs / scope / target list. Drag-and-drop accepted.
- **Center pane (flexible)** — primary result view appropriate to the tool (table for findings, tree for hierarchical data, code editor for source).
- **Right pane (300-400px, collapsible)** — full detail of the currently-selected item.
- **Top menu bar** — File (Open / Save / Export / Recent / Quit), Tools (per-tool actions), Settings (theme, fonts, integrations), Help (About / Docs).
- **Bottom status bar** — current activity, item counts, primary action buttons.

### Cross-tool integration with Lancer + the other 29 clones

Every Lancer-clone GUI exposes a small local HTTP server on a port auto-allocated at launch (`127.0.0.1:<port>`, written to `%TEMP%/lancer-mobsf.port`):

- The main Lancer GUI discovers running tools by scanning `%TEMP%/lancer-*.port` and lists them in its sidebar.
- Right-clicking any item in any tool can "Send to <other Lancer tool>" — the receiving tool fetches the payload via its own HTTP endpoint.
- A future "Lancer Hub" tray shell can launch / focus any of the 30 GUIs from one menu.
- HTTP endpoints exposed:
  - `GET  /v1/state` — current jobs / progress
  - `POST /v1/import` — accept a target / file / record from another Lancer tool
  - `GET  /v1/export?format=json|csv|sarif|markdown` — pull the current result set in a portable format

### Async work + responsiveness

- Long-running scans run on a Tokio task pool; the GUI thread only renders.
- Progress propagates via `crossbeam::channel` from worker → UI.
- A `Stop` button cancels in-flight work via a `CancellationToken`.
- All file I/O / network I/O / subprocess work goes through async channels — the egui thread never blocks.

### Build output

The existing `build.bat` / `build-windows.bat` / `build-linux.sh` already produce a single binary. With `eframe` linked, the same binary is the GUI app.

- Windows: `build\lancer-mobsf.exe` (double-click opens the GUI window).
- Linux: `build/lancer-mobsf` (also installable as a `.desktop` entry via `build-linux.sh --install`).
- macOS: `build/lancer-mobsf` (bundled into `lancer-mobsf.app` via `cargo-bundle` in the `build-mac.sh` companion).

For CI / headless / scripting, pass `--cli` to fall through to the CLI surface from `## Granular feature catalog`.

## Build Setup (Lancer-standard pattern)

This clone follows the same build pattern as the main Lancer project — single `.exe` output via `build.bat` on Windows, `.so/elf` via `build-linux.sh` on Linux.

### Project layout

```
lancer-mobsf/
├── Cargo.toml              # single-crate Rust project
├── Cargo.lock              # committed (binary, not library)
├── src/
│   └── main.rs             # entry point (scaffold)
├── build.bat               # Windows build → build/lancer-mobsf.exe
├── build-windows.bat       # Windows packaged dist build → dist/lancer-mobsf-windows-x86_64/
├── build-linux.sh          # Linux build → build/lancer-mobsf
├── .gitignore              # plan.md (local-only) + target/ + build/ + dist/
├── README.md               # public-facing (pushed to GitHub)
└── plan.md                 # this file (gitignored — local blueprint, never pushed)
```

### Build commands

**Windows (double-click `build.bat`):**
```
build.bat
```
Produces `build\lancer-mobsf.exe`. Pauses at end so the window stays open.

**Windows (packaged dist):**
```
build-windows.bat
```
Produces `dist\lancer-mobsf-windows-x86_64\bin\lancer-mobsf.exe` plus LICENSE/README — ready to zip.

**Linux / macOS:**
```bash
./build-linux.sh
```
Produces `build/lancer-mobsf`.

### Requirements
- Rust toolchain (https://rustup.rs)
- Windows: Visual C++ Build Tools 2019/2022 (needed by some crates)

### CI

The build pattern is intentionally identical across Lancer and all 19 clones, so a single Jenkins/GitHub Actions matrix can build everything by calling `build-windows.bat` or `build-linux.sh` per repo.
