<h1 align="center">TITAN Vigil</h1>
<p align="center"><b>Kernel ETW Blue-Team Telemetry Engine</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Rust-000000?logo=rust&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Telemetry-Kernel%20ETW-5C2D91?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Output-SIEM%20Ready-2E8B57?style=for-the-badge" />
</p>

<p align="center">
Detects untrusted processes accessing protected filesystem resources using low-latency Kernel ETW instrumentation and deterministic policy evaluation.
</p>

## Project Documentation

- `README.md`: Runtime overview, configuration, and operations
- `CONTRIBUTING.md`: Development and PR workflow

---

## Repository Layout

- `Vigil/src/main.rs`: entrypoint wiring config, logging, worker pool, ETW session lifecycle
- `Vigil/src/runtime/`: detection engine state and alert orchestration
- `Vigil/src/telemetry/`: Kernel ETW session management and trusted-handle discovery
- `Vigil/src/trust/`: signer verification and process metadata helpers
- `Vigil/src/output/`: alert schema, log sinks (JSONL/CEF/Sigma), endpoint forwarding, toast UX
- `Vigil/src/support/`: config/CLI parsing and startup diagnostics
- `tests/data_access_test/`: synthetic filesystem access generator used for validation

---

## What It Detects

The engine monitors kernel-level file I/O events and raises alerts when:

* An **untrusted or unsigned process**
* Attempts to **access a configured protected path**
* Including access via **handle duplication from trusted processes**

Typical protected targets include (configurable):

* Browser profile data (cookies, login databases)
* Application secrets stored on disk
* Token stores (e.g. LevelDB-based apps)
* Any sensitive filesystem location you define

---

## How It Works

* Starts a **Kernel ETW user trace** (process + file providers)
* Tracks process start events and caches process metadata
* Tracks file name mappings via ETW file events
* Matches accessed paths against protected rules using deterministic indexed lookups
* Evaluates process trust using:

  * Authenticode signature verification
  * Optional certificate revocation checks (`security.revocation_mode = "chain"`)
  * Explicit denylist of known compromised signer certificate thumbprints
  * Optional signer allowlist
  * Optional legacy process-name allowlist fallback
* Detects suspicious access patterns including:

  * Direct access by untrusted processes
  * Access via file objects originally opened by trusted processes
* Emits alerts through:

  * JSONL / text / CEF / Sigma-JSON log sinks
  * Optional console output
  * Windows toast notifications (rate-limited)
  * Optional endpoint forwarding over UDP/TCP (feature-flagged)
* Uses bounded crossbeam channels and worker threads for sink processing/backpressure

---

## Requirements

* Windows
* Administrative privileges (required for Kernel ETW sessions)
* Rust toolchain (for building)

---

## Configuration

Configuration is provided via a TOML file.

Key concepts:

* **Protected rules**
  Substring-based path matching for sensitive resources.

* **Allowlists**

  * Certificate signer subject fragments
  * Legacy process name suffixes

* **Security policy**

  * Signature requirement toggle
  * Revocation mode
  * Compromised cert thumbprint denylist
  * Legacy fallback policy
  * Optional operator trust API (mode: wintrust-only, api-only, prefer-api, prefer-wintrust)

* **Concurrency policy**

  * Worker thread count
  * Channel capacity for burst control

* **Endpoint alert forwarding**

  * Feature flag (`endpoint_alert.enabled`)
  * UDP/TCP endpoint packet forwarding

* **SIEM and Sigma**

  * Multi-format outputs (`jsonl`, `text`, `cef`, `sigma_json`)
  * Optional Sigma rule artifact generation on startup

* **General settings**

  * Alert suppression window
  * Quiet mode
  * JSONL vs text logging

Example (simplified):

```toml
[general]
quiet = false
suppress_ms = 1500

[security]
require_signature = true
require_signer_allowlist = true
allow_legacy_process_name_fallback = false
revocation_mode = "chain"
denylisted_cert_thumbprints = []

[concurrency]
worker_threads = 4
alert_channel_capacity = 8192

[endpoint_alert]
enabled = false
endpoint = "127.0.0.1:9000"
transport = "udp"
connect_timeout_ms = 1500
retries = 2

[siem]
enabled = true
formats = ["jsonl", "cef", "sigma_json"]
generate_sigma_rules = true
sigma_rules_file = "sigma_rules.yml"

[watch]
protected = [
  { name = "Browser Cookies", substring = "cookies" },
  { name = "Token Store", substring = "leveldb" }
]

[allowlist]
signer_subject_allow = ["microsoft", "google"]
process_name_allow = ["chrome.exe", "msedge.exe"]

[trust_api]
enabled = false
endpoint = "https://trust.example.com/verify"
api_key = "Bearer token-here"
timeout_ms = 2500
# modes: wintrust_only | api_only | prefer_api | prefer_wintrust
mode = "prefer_api"
```

---

## Running

```bash
cargo run --release -- --config config.toml
```

Verbose output:

```bash
cargo run --release -- --config config.toml --verbose
```

Logs are written to:

```
%LOCALAPPDATA%\TITAN-Vigil-CE\logs
```

When `siem.generate_sigma_rules = true`, a Sigma rules artifact is also generated in the same log directory (or the configured absolute path).

### Feature flags

- `remote_endpoint` (opt-in): build with UDP/TCP remote alert forwarding enabled. Example:  
  `cargo run --release --features remote_endpoint -- --config config.toml`
- `trust_api` (opt-in): call an operator HTTP trust API to decide signer trust, optionally replacing WinTrust. Example:  
  `cargo run --release --features trust_api -- --config config.toml`

### Testing

- Core suite: `cargo test`
- Remote endpoint suite (opt-in): `cargo test --features remote_endpoint -- output::endpoint`
- Trust API suite (opt-in): `cargo test --features trust_api -- trust::api`

---

## Alert Semantics

Each alert includes:

* Timestamp
* PID
* Process image path
* Target file path
* Protected rule name
* ETW event ID
* Alert kind (reason)
* Human-readable note

Alerts are **deduplicated and rate-limited** to avoid storms.

---

## Threat Model Fit

This tool is suited for:

* Host-based detection
* Suspicious process discovery
* Post-exploitation visibility
* Blue-team telemetry enrichment
