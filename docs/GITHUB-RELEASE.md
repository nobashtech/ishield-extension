# GitHub public release

## Repository contents

The public repository contains first-party source, browser trees, reproducible build tooling, store-review documentation, exact distributed third-party artifacts, attribution metadata, and applicable license notices. Private signing keys are never committed.

## Release assets

For version 1.0.0.1, publish the reviewed browser artifacts plus `SHA256SUMS.txt` and the clean source archive. Brave uses the Chrome artifact; an identical Brave-named copy is optional for manual testing only.

Recommended assets:

- `iShield-Chrome-1.0.0.1-store-ready.zip`
- `iShield-Edge-1.0.0.1-store-ready.zip`
- `iShield-Firefox-1.0.0.1-amo.zip`
- `iShield-Firefox-1.0.0.1-source.zip`
- `iShield-Opera-1.0.0.1-store-ready.zip`
- `iShield-Opera-1.0.0.1-source.zip`
- `iShield-Brave-1.0.0.1-compatible.zip` (optional; identical to Chrome)
- `iShield-browser-clean-source.zip`
- `SHA256SUMS.txt`

Tag the release as `v1.0.0.1`. GitHub also generates source-code ZIP/TAR archives automatically from the tag.

## Pre-release gate

```bash
npm ci
npm run ci
```

Then test the actual packaged builds in their target browsers and compare each release asset against `SHA256SUMS.txt`.
