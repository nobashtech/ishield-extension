# iShield Extension

**Official product name:** iShield Extension  
**Repository:** `ishield-extension`  
**Maintainer:** Nobash LLC  
**Current source manifest version:** `1.0.0.1`

This is the browser-extension source tree for Chrome, Edge, Firefox, and Opera. Brave uses the Chrome build. This repository does not contain the historical desktop or mobile apps.

Read [GitHub publishing instructions](docs/PUBLISH-TO-GITHUB.md) and [store update notes](docs/RENAMING-AND-STORE-UPDATES.md) before releasing a newly named version.

iShield Extension is a browser-first ad, tracker, phishing, scam and malware protection extension.

This repository is intentionally limited to the browser product. Legacy central management, managed-device enrollment, family/device control, enterprise dashboard, mobile/native targets and historical phase artifacts are not included.

## Privacy boundary

All browsing and protection processing is local to the browser. iShield Extension does not upload browsing history, visited URLs, page content, search terms, form data, account data, device IDs, installation IDs, telemetry or analytics.

The only extension-originated network request is a generic HTTPS `GET` to:

`https://update.broxme.com/ishield/manifest.json`

That request downloads a signed filter-list manifest. The updater accepts only one structured `network-rules` resource. It cannot download JavaScript, executable code, policy assignments, device configuration, reputation lookups, compatibility instructions, analytics instructions or user-specific data.

Imported site-specific filter rules that actively initiate their own network requests are excluded from store builds. The privacy audit fails if such a raw rule is reintroduced. Packaged filtering/scriptlet logic that blocks or locally modifies page behavior remains.

## Browser source trees

- `extensions/chrome` — Google Chrome Manifest V3
- `extensions/edge` — Microsoft Edge Manifest V3
- `extensions/opera` — Opera Manifest V3
- `extensions/firefox` — Mozilla Firefox Manifest V3

The browser trees are intentionally separate so each store can be prepared and reviewed independently. All four manifests set `incognito: not_allowed` so private browsing is outside the extension runtime and storage boundary.


## Supported desktop browsers

- Google Chrome — dedicated Manifest V3 store tree
- Microsoft Edge — dedicated Manifest V3 store tree
- Mozilla Firefox — dedicated Manifest V3 AMO tree
- Opera — dedicated Manifest V3 store tree
- Brave — uses the canonical Chrome Manifest V3 build; there is no separate iShield Extension Brave code fork

Brave officially supports Chrome Web Store extensions. See `docs/BRAVE-COMPATIBILITY.md`.

## Public repository and releases

Public-source hygiene and release requirements are documented in `SECURITY.md`, `CONTRIBUTING.md`, `docs/GITHUB-RELEASE.md`, and `.github/workflows/ci.yml`. Private filter-signing keys must never be committed. Release assets should be accompanied by SHA-256 checksums.

## Build

```bash
npm run audit
npm run build
```

Development packages are written to `dist/`. Store-specific final packaging should be done only after the individual store review checklist is completed.

## Filter updates

Filter updates are Ed25519-signed and fail closed. The private signing key is never included in the extension or repository.

```bash
node scripts/ishield_update_keys.mjs
node scripts/publish_filters.mjs
```

The update format is deliberately narrow: full `network-rules` filter data only.
