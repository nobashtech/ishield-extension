# Reproducing the Firefox AMO Package

## Requirements
- Node.js 22.12 or newer
- npm (the version bundled with a supported Node.js 22 release is suitable)
- Python 3.10 or newer
- Internet access to the official npm registry for the first dependency install
- No private package registry is required

## Build
From the root of the submitted source archive:

```sh
npm ci
npm run build-for-amo
```

The build performs these steps:
1. verifies that imported content-filter rules do not contain the locally excluded network-originating site exceptions;
2. rebuilds generated Firefox AdGuard engine/content/scriptlet bundles from readable source and lockfile-pinned dependencies;
3. reruns the filter guard;
4. runs the privacy/network-boundary audit;
5. runs signed filter-update tests;
6. creates the deterministic Firefox AMO ZIP.

Expected output:

```text
dist/iShield-Firefox-1.0.0.1-amo.zip
```

The package is deterministic: `scripts/package_firefox_amo.py` writes a fixed ZIP timestamp and a sorted file order.

## Useful validation commands

```sh
npm run guard:filters
npm run audit
npm run test:update
python3 scripts/firefox_preflight.py
```

## Source layout
- `extensions/firefox/` — Firefox extension source/package tree
- `extensions/shared/adguard/` — readable AdGuard integration source and pinned filter inputs
- `scripts/build_adguard_firefox.mjs` — Firefox generated-bundle build
- `scripts/package_firefox_amo.py` — deterministic package builder
- `scripts/prune_network_filter_exceptions.py` — privacy-boundary guard
- `scripts/audit_privacy.mjs` — browser privacy/network boundary audit
- `tests/filter-update.test.mjs` — signed update tests
- `package.json` / `package-lock.json` — exact build dependencies
- `THIRD-PARTY-NOTICES.md` and `licenses/` — licenses and provenance

## Checked-in declarative filter data and redirect assets
The large `rules/production/*.json` files are declarative DNR data, not executable JavaScript. They are intentionally kept in the source archive in the same readable form that ships in the add-on, together with `ATTRIBUTION.json` provenance, exact upstream revision/build information, and the compaction helper source at `scripts/lib/dnr-compact.mjs`.

The AMO rebuild does not re-download uBlock filter data from GitHub. This is intentional: the review build only obtains dependencies through the official npm package manager, while the exact third-party declarative data under review is already checked into the submitted source archive. The packaged redirect stubs are likewise included byte-for-byte with their AdGuard Scriptlets/TSWebExtension version provenance.

The generated executable JavaScript bundles that require a source build are rebuilt by `scripts/build_adguard_firefox.mjs` from readable first-party integration source plus lockfile-pinned public npm releases.
