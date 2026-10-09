# Contributing to iShield Extension

Thanks for helping improve iShield. Changes should preserve the extension's local-first privacy and store-policy boundaries.

## Development requirements

- Node.js 22.12 or newer
- Python 3
- `npm ci` for pinned build dependencies

## Before opening a pull request

Run:

```bash
npm ci
npm run ci
```

If generated AdGuard assets are intentionally changed, also run the relevant generator and commit the matching source/attribution changes.

## Privacy and security rules

Pull requests must not introduce telemetry, analytics, accounts, device/install identifiers, browsing-data upload, remote executable code, hidden network clients, external script loading, managed-device control, or new permissions without an explicit architecture review. The signed remote-update channel is limited to filter/network-rule data.

## Third-party code and filter data

Do not add third-party code or lists without recording the source, exact version/commit when available, license, and required notices in `THIRD-PARTY-NOTICES.md` and the relevant attribution metadata.
