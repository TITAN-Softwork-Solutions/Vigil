# Security Policy

## Supported Versions

This repository is currently pre-1.0.0. Security fixes are applied to the latest `main` branch.

## Reporting a Vulnerability

Please do not open public GitHub issues for security vulnerabilities.

Report privately to: `security@titan-softwork-solutions.example`

Include:

- Affected version/commit
- Reproduction steps
- Impact assessment
- Any proof-of-concept code or logs

## Response Targets

- Initial triage acknowledgement: 3 business days
- Severity assessment: 7 business days
- Fix plan or mitigation guidance: 14 business days

## Disclosure Process

- We follow coordinated disclosure.
- Public details are released after a fix is available and users have had a reasonable patch window.

## Security Hardening Notes

This project contains defensive controls and telemetry features:

- Signature trust policy controls (allowlist, revocation mode, certificate denylist)
- Kernel ETW telemetry collection
- Multi-format SIEM outputs (JSONL, CEF, Sigma JSON)

Operational recommendations:

- Run on hardened endpoints.
- Restrict who can modify `config.toml`.
- Protect output log directories with strict ACLs.
- Use TLS/authenticated transport for any production remote ingestion pipeline.
