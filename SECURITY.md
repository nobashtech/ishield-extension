# Security Policy

## Supported versions

Security fixes are provided for the latest published iShield Extension browser-extension release.

## Reporting a vulnerability

Please do **not** open a public issue for a vulnerability that could put users at risk. Report it privately through the security contact published on the iShield Extension website or, when enabled for this repository, GitHub Private Vulnerability Reporting.

Include the affected browser/version, iShield Extension version, reproduction steps, impact, and any proof-of-concept needed to understand the issue. Do not include real user secrets or browsing data.

## Security boundaries

The browser extension is designed so that browsing/protection data stays on-device. Its only extension-originated remote connection is the fixed HTTPS endpoint used to download signed blocking-filter updates. Remote executable code, telemetry, account sync, managed-device control, and user-specific update payloads are outside the supported design. See `docs/NETWORK-BOUNDARY.md`.
