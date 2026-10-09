# Notes for AMO Reviewers — iShield Extension 1.0.0.1

## Primary purpose
A browser protection/content-blocking extension providing ad/tracker blocking, cosmetic filtering, phishing/scam/malware protection, fingerprinting protection and related anti-breakage controls.

## Privacy / network behavior
There is no account, login, telemetry, analytics, advertising identifier, installation identifier, managed-device enrollment, family control or cloud policy system.

The extension processes URLs/request information and limited page content locally as required for its protection features. That information is not uploaded.

The extension's only first-party remote client is its filter updater. It accepts exactly this endpoint:

`https://update.broxme.com/ishield/manifest.json`

The request is a generic HTTPS GET with `credentials: "omit"`, `redirect: "error"` and `referrerPolicy: "no-referrer"`. The extension adds no request body, query string, install/device identifier or browsing information. The downloaded manifest must pass strict JSON parsing, Ed25519 signature verification, sequence/expiry checks, response-size limits and rule-budget checks.

Only one remote resource kind is accepted: `network-rules`. Remote JavaScript, WebAssembly, scriptlets, policy logic, reputation lookups and other executable/behavioral resources are rejected. All executable code is included in the submitted add-on package.

## Firefox data declaration
`browser_specific_settings.gecko.data_collection_permissions.required` is set to `["none"]`. iShield Extension does not collect or transmit personal data or technical/interaction data for storage or processing outside the extension. The generic filter-update request contains no extension-collected/user-specific data.

## Generated / bundled code
The package includes generated AdGuard content-engine bundles and packaged filtering/scriptlet code. A source archive is supplied with exact build instructions and a lockfile. Build dependencies are retrieved from the official npm registry using `npm ci`.

Rebuild command:

```sh
npm ci
npm run build-for-amo
```

Expected add-on output:

`dist/iShield-Firefox-1.0.0.1-amo.zip`

## Third-party build dependencies
Exact versions are pinned in `package.json` and `package-lock.json`:

- `@adguard/dnr-rulesets` 5.0.20260907123943 — https://www.npmjs.com/package/@adguard/dnr-rulesets/v/5.0.20260907123943
- `@adguard/tswebextension` 5.0.3 — https://www.npmjs.com/package/@adguard/tswebextension/v/5.0.3
- `@adguard/tsurlfilter` 6.0.3 — https://www.npmjs.com/package/@adguard/tsurlfilter/v/6.0.3
- `@adguard/extended-css` 2.2.0 — https://www.npmjs.com/package/@adguard/extended-css/v/2.2.0
- `@adguard/scriptlets` 2.5.1 (transitive, lockfile-pinned) — https://www.npmjs.com/package/@adguard/scriptlets/v/2.5.1
- `esbuild` 0.28.1 — https://www.npmjs.com/package/esbuild/v/0.28.1

Additional filter-list provenance and exact pinned upstream revisions are documented in `THIRD-PARTY-NOTICES.md` and the packaged `rules/*/ATTRIBUTION.json` files.

## Testing notes
No account or credentials are required. Install the extension, open several ordinary HTTP/HTTPS sites, use the toolbar popup to change protection mode or allowlist the current site, and verify blocking/cosmetic filtering. Filter-update behavior can be reviewed in `src/update-client.js`, `src/signed-update.js`, `src/update-runtime.js` and `src/trust-store.js`.

### Declarative rule data / redirect resources
The production DNR JSON files are submitted as readable declarative data, byte-for-byte in the source archive, with provider/build/commit provenance in `rules/production/ATTRIBUTION.json`. The review build does not fetch mutable filter data from GitHub. Redirect stand-in assets are also checked in exactly as distributed and are attributed to the pinned AdGuard TSWebExtension/Scriptlets releases. Generated executable AdGuard integration JavaScript is the part rebuilt by `build_adguard_firefox.mjs`.
