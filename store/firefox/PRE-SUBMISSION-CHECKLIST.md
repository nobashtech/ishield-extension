# Firefox AMO Pre-Submission Checklist

## Required before clicking Submit
- [ ] Deploy `ishield-privacy-firefox.html` at `https://broxme.com/ishield/privacy/firefox/` and verify it is publicly reachable without login.
- [ ] Verify `https://broxme.com/ishield/` is publicly reachable.
- [ ] Verify `https://update.broxme.com/ishield/manifest.json` returns only the intended signed filter manifest over HTTPS.
- [ ] Ensure the update endpoint does not require cookies, auth, unique tokens, query tracking or user-specific parameters.
- [ ] Upload `iShield-Firefox-1.0.0.1-amo.zip` as the add-on package.
- [ ] Answer Yes when AMO asks whether source code is required for generated/bundled code, and upload `iShield-Firefox-1.0.0.1-source.zip`.
- [ ] Paste the contents of `REVIEWER-NOTES.md` into Notes for Reviewers.
- [ ] Use the listing text from `AMO-LISTING.md`.
- [ ] Confirm the manifest data declaration is `required: ["none"]`.
- [ ] Confirm no additional data collection/transmission boxes are selected in AMO that contradict the manifest.
- [ ] Review validator warnings before final submission; do not ignore a remote-code, permission, CSP, source-reproducibility or data-disclosure warning.

## Local release gates already prepared
- Manifest V3
- Gecko ID present
- Firefox minimum version 140
- Private browsing disabled
- 13 static rulesets, 8 enabled
- 43,020 static DNR rules, 27,183 enabled by default
- Managed dynamic-rule budget 4,960 / 5,000
- 29 exact web-accessible resources; no wildcard resource paths
- No managed-device/family/central-control runtime
- No telemetry or analytics client
- Remote network surface limited to signed filter updates
- Remote executable code rejected
- [ ] Treat AMO's upload validator as a hard gate because native Firefox/web-ext validation was not available in the preparation environment.
