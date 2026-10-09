# iShield Extension Microsoft Edge 1.0.0.1 — final technical audit

Prepared: October 5, 2026

## Result

**PASS for local technical/store-package checks.** Microsoft Edge Add-ons certification is determined by Microsoft and cannot be guaranteed by a local audit.

## Package

- File: `iShield-Edge-1.0.0.1-store-ready.zip`
- SHA-256: `85a2585da03447ff2a2d6795d6ba6d451747d76fbb88aac92743451e56f5e475`
- ZIP entries: 154
- Compressed size: 8,610,197 bytes
- Forbidden build artifacts in ZIP: none
- Manifest version: 3
- Extension version: 1.0.0.1
- `minimum_chrome_version`: 137 (supported by Microsoft Edge's Chromium manifest format)

## Security/privacy boundary

- Managed-device, central-control and family-control runtime: absent.
- Account/OAuth/external-connect runtime: absent.
- Analytics/telemetry upload: absent.
- Extension backend user-data upload: absent.
- Remotely hosted executable extension code: absent.
- iShield Extension backend communication: signed filter-list update only.
- Filter-update request: fixed HTTPS GET, no request body, credentials omitted, referrer omitted, redirects rejected.
- Remote update accepts exactly one `network-rules` resource and compiles it locally to block-only DNR rules.
- Imported site-specific filter exceptions that could originate their own network requests were removed from the shared browser core; general blocking and packaged scriptlet engines remain.
- Automated audit now rejects future imported raw rules that initiate `fetch`, `sendBeacon`, `XMLHttpRequest`, `WebSocket`, or `EventSource` network activity.
- InPrivate runtime: disabled (`incognito: not_allowed`).

## Core protection retained

- Manifest V3 DNR ad/tracker blocking.
- Production AdGuard/uBlock-derived packaged filtering and scriptlets.
- Cosmetic page cleanup.
- Phishing, scam and malware protection.
- Fingerprint-protection controls.
- YouTube and Facebook cleanup.
- Allowlist and Strict controls.
- Local activity/counters and breakage recovery.
- Signed filter-list updates.

## Permissions

- Required: `activeTab, declarativeNetRequest, storage, scripting, alarms`
- Optional: none
- Host access: `http://*/*, https://*/*`
- Each permission has a current feature-level justification in `PERMISSION-JUSTIFICATIONS.md`.

## Static DNR rules

- Rulesets: 13
- Enabled by default: 8
- Total static rules: 43,020
- Enabled-by-default static rules: 27,183
- Regex rules: 161

| Ruleset | Default | Rules | Regex | Actions |
|---|---:|---:|---:|---|
| ishield_core | on | 8 | 0 | block |
| ishield_strong | on | 9 | 0 | block |
| ishield_maximum | off | 6 | 0 | block |
| ishield_production_base | on | 13,106 | 142 | allow, allowAllRequests, block, modifyHeaders, redirect |
| ishield_production_tracking | on | 8,996 | 14 | allow, allowAllRequests, block, modifyHeaders, redirect |
| ishield_production_ublock | on | 4,623 | 0 | allow, block |
| ishield_production_pgl | on | 4 | 0 | block |
| ishield_production_urlhaus | on | 4 | 0 | block |
| ishield_production_badware | on | 433 | 0 | allow, block |
| ishield_production_easylist | off | 3,747 | 0 | allow, block |
| ishield_production_easyprivacy | off | 9,052 | 0 | allow, block |
| ishield_production_mobile | off | 581 | 5 | allow, allowAllRequests, block, redirect |
| ishield_production_urltracking | off | 2,451 | 0 | modifyHeaders, redirect |

## Web-accessible resources

- Explicit resources: 29
- Wildcard resource paths: none
- Missing declared resources: none

## Automated checks

- Privacy-boundary audit: PASS.
- Signed filter-update tests: 4/4 PASS.
- JavaScript syntax: 98/98 shipped Edge `.js` files PASS.
- ZIP decompression/integrity: PASS.
- Manifest JSON parse: PASS.
- Chromium/Edge-compatible Manifest V3 native pack smoke: PASS.
- Packer-generated `.pem` and `.crx` smoke-test artifacts deleted and not shipped.

## Public-site gates before submission

- Deploy and verify `https://broxme.com/ishield/privacy/edge/` using `ishield-privacy-edge.html` from this kit.
- Verify `https://broxme.com/ishield/` is publicly reachable and consistent with the listing.
- Do not submit until the privacy URL is accessible without login and reflects this exact release.
