# iShield Extension Chrome 1.0.0.1 — final technical audit

Prepared: October 5, 2026

## Result

**PASS for local technical/store-package checks.** Chrome Web Store approval itself is determined by Google and cannot be guaranteed.

## Package

- File: `iShield-Chrome-1.0.0.1-store-ready.zip`
- SHA-256: `85a2585da03447ff2a2d6795d6ba6d451747d76fbb88aac92743451e56f5e475`
- ZIP entries: 154
- Compressed size: 8,610,197 bytes
- Forbidden build artifacts in ZIP: none
- Manifest version in ZIP: 3
- Extension version in ZIP: 1.0.0.1

## Security/privacy boundary

- Managed-device, central-control and family-control runtime: absent.
- Account/OAuth/external-connect runtime: absent.
- Analytics/telemetry upload: absent.
- Extension user-data upload: absent.
- Remotely hosted executable extension code: absent.
- Only approved extension-originated remote channel: signed filter-list update.
- Filter-update request: fixed HTTPS GET, no request body, credentials omitted, referrer omitted, redirects rejected.
- Remote update accepts exactly one `network-rules` resource and compiles it locally to block-only DNR rules.
- Private/incognito runtime: disabled (`incognito: not_allowed`).

## Permissions

- Required: `activeTab, declarativeNetRequest, storage, scripting, alarms`
- Optional: `none`
- Host access: `http://*/*, https://*/*`
- Each required permission has a current feature-level justification in `PERMISSION-JUSTIFICATIONS.md`.

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
- Wildcard resource paths: none.
- Every declared resource exists in the package.
- Unused redirect resources found during cleanup were removed.

## Production cleanup

- Legacy managed/central/family control code removed.
- Non-production custom test/lab scriptlet layer removed.
- First-party `__ISHIELD_TEST_HOOKS__` runtime hooks removed.
- Production AdGuard/uBlock-derived packaged filtering/scriptlet engines retained because they provide actual protection functionality.
- Imported site-specific filter exceptions that could originate their own network requests were removed; normal production filtering/scriptlets remain.
- Privacy audit now rejects future imported raw filter rules that initiate their own network requests.
- Stale wildcard web-accessible-resource exposure removed.

## Automated checks

- `npm test`: PASS.
- Privacy-boundary audit: PASS.
- Signed filter-update tests: 4/4 PASS.
- JavaScript syntax check for every shipped `.js` file: PASS.
- ZIP decompression/integrity test: PASS.
- Chromium native `--pack-extension` acceptance test: PASS.
- Packer-generated private key/CRX test artifacts were deleted and are not shipped.

## Public-site gate before submission

- `https://broxme.com/ishield/privacy/` must publicly serve the iShield-specific privacy policy supplied in this kit.
- `https://broxme.com/ishield/` should be reachable and consistent with the store listing.
- These URLs could not be independently verified from the current web environment, so verify them in a normal browser before clicking **Submit for review**.

