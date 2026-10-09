# iShield Extension Opera 1.0.0.1 — final audit

Prepared: October 5, 2026

## Package / manifest

- Manifest: V3
- Version: 1.0.0.1
- Private/incognito browsing: disabled (`incognito: not_allowed`)
- Required permissions: `activeTab`, `declarativeNetRequest`, `storage`, `scripting`, `alarms`
- Host access: `http://*/*`, `https://*/*`
- Optional permissions: none
- Static DNR rules: 43,020
- Default-enabled static rules: 27,183
- Regex rules: 161
- Static rulesets: 13
- Default-enabled rulesets: 8
- Exact web-accessible resources: 29
- Wildcard web-accessible resources: none

## Security/privacy validation

- Privacy boundary audit: PASS
- Signed filter-update tests: 4/4 PASS
- Network-filter privacy guard: PASS
- JavaScript syntax: 98/98 PASS
- ZIP integrity: PASS
- Chromium MV3 pack smoke: PASS
- Managed-device / central / family control runtime: absent
- Analytics / telemetry client: absent
- Account / OAuth / device or installation identifier: absent
- Remote executable code: absent
- Extension-originated backend communication: signed filter update GET only
- Imported raw rules that originate their own network requests: excluded by automated guard

## Core protection retained

- Declarative Net Request ad/tracker blocking
- Cosmetic filtering
- Packaged AdGuard/uBlock filtering and scriptlets
- Local phishing, scam and malware protection
- YouTube/Facebook cleanup support
- Fingerprint-protection controls
- Allowlist / Strict controls
- Local activity counters
- Signed filter-list updates

## Remote update boundary

Only:

`GET https://update.broxme.com/ishield/manifest.json`

The request has no iShield Extension request body or user/device identifier, omits credentials, rejects redirects and uses a no-referrer policy. The signed payload accepts one structured `network-rules` resource only; it cannot deliver JavaScript, WebAssembly or other executable extension logic.

## Remaining external/manual gates

- Deploy the Opera-specific privacy policy at `https://broxme.com/ishield/privacy/opera/` and verify it is publicly reachable before submission.
- Test the unpacked final package in current Opera on at least the platforms available to the publisher. Opera documents cross-platform review/testing expectations.
- This audit used Chromium's native MV3 packer because a native Opera binary is not installed in the audit environment.
- Final acceptance remains with Opera's store validator/reviewer and cannot be guaranteed by an offline/source audit.
