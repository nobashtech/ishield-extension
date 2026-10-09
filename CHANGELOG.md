# Changelog

## 1.0.0.1 — Facebook feed detection hotfix

- Detect current Facebook feed units that are direct children of `role=feed`.
- Add a guarded structural fallback for current feed variants that omit older `FeedUnit`/article markers.
- Continue requiring explicit ad-disclosure metadata near the post header before hiding a card.
- Preserve the 1.0.0.1 production-safe `TESTING` fix.

## 1.0.0.1 — Facebook feed hotfix

- Fixed a production `ReferenceError` in `content/facebook-ads.js` caused by an undeclared `TESTING` flag.
- Restored Facebook feed ad cleanup when the production content script loads.
- Kept the test-only internals hook available only when `globalThis.__ISHIELD_TESTING__ === true`.

All notable public-release changes to iShield Extension are documented here.

## 1.0.0.0 — 2026-10-05

- Initial clean browser-extension release baseline.
- Manifest V3 builds for Chrome, Edge, Opera, and Firefox.
- Chrome build is also the canonical Brave-compatible build.
- Local ad/tracker blocking, cosmetic filtering, packaged scriptlets, phishing/scam/malware protection, fingerprint protection, allowlists, protection modes, and local activity counters.
- Signed remote filter updates restricted to structured network rules only.
- Removed legacy managed-device, central/family control, telemetry, analytics, account/OAuth, device/install ID, cloud-policy, and remote executable-code paths.
- Added per-store privacy/reviewer documentation and release-time privacy guards.
