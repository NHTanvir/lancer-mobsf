# CLAUDE.md

Guidance for Claude Code (and humans) working in this repository.

## What this is

`lancer-mobsf` — A Rust-native mobile security analysis tool that is part of the Lancer bug bounty toolkit. It performs static analysis of Android APKs and iOS IPAs, with AI-assisted triage, CVE correlation, threat intelligence, and custom Frida hook script generation. It also exposes a MobSF-compatible REST API and WebSocket-based real-time scan progress, acting as a drop-in replacement for MobSF v1 endpoints.

## Architecture

- `src/main.rs` — Binary entry point; CLI parsing via `clap` and server bootstrap.
- `src/api/` — Axum HTTP handlers; MobSF-compatible REST API routes.
- `src/scanner/` — Core static analysis logic for Android APKs and iOS IPAs.
- `src/report/` — HTML/JSON/PDF report generation with MASVS v2 scoring.
- `src/db/` — SQLite persistence via `sqlx`; stores scan results and metadata.
- `src/dynamic/` — ADB device listing, session management, screenshot capture, mitmproxy traffic capture.
- `src/ws/` — WebSocket endpoint (`/ws/scan/:id`) for real-time scan progress.
- `src/masvs/` — MASVS v2 scoring logic and category mappings.
- `migrations/` — SQLx migration files for the SQLite schema.
- `frida-scripts/` — AI-generated Frida hook scripts from decompiled class/method inventories.
- `rules/` — Custom static analysis rules and patterns.

## Conventions

- Error propagation uses `anyhow::Result`; no `unwrap`/`expect` on fallible I/O.
- GUI gated behind the default `gui` feature; `--no-default-features` builds headless CLI.
- Library code in `src/lib.rs`; binary entry point in `src/main.rs`.
- API keys (`ANTHROPIC_API_KEY`, `NVD_API_KEY`, `VIRUSTOTAL_API_KEY`) are read from environment; features that require them degrade gracefully when absent.
- Report formats (text, HTML, JSON, PDF) are selected via `--format`; all share a common findings data model so output is consistent across formats.

## Build / test / run

```
build.bat                   # Windows → build\lancer-mobsf.exe
./build-linux.sh            # Linux/macOS
cargo build --release       # standard release build
cargo test                  # run tests
```

## Repo notes

- `plan.md` is local-only and must NOT be committed. It is gitignored.
- `.claude/` and `target/`/`build/`/`dist/` are local-only and gitignored.
