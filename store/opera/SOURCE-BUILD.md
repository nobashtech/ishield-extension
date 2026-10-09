# iShield Extension Opera reviewer source / build notes

The submitted Opera package contains first-party source plus generated, non-minified filtering bundles derived at build time from pinned npm dependencies and pinned filter inputs.

## Environment

- Node.js 22.12 or newer
- Python 3.11 or newer
- npm with access to the public npm registry

## Rebuild / verify

From the source archive root:

```bash
npm ci
npm run guard:filters
npm run build:generated
npm run guard:filters
npm run audit
npm run test:update
python3 scripts/build_packages.py
```

The Opera development package is then written to:

```text
dist/ishield-opera-clean-dev.zip
```

`package-lock.json` pins npm dependency resolution. `scripts/build_adguard_content.mjs` rebuilds the packaged AdGuard-derived filtering bundles with `minify: false`. The input filter files are included under `extensions/shared/adguard/filters/` with attribution metadata.

The store package does not download executable code at runtime. Remote updates are signed structured `network-rules` only.
