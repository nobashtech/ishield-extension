# Chrome Web Store pre-submission checklist

## Code/package

- [x] Manifest V3
- [x] Restrictive extension-page CSP
- [x] No managed-device, central-control, family-control, OAuth, or externally_connectable runtime
- [x] No extension analytics or telemetry upload
- [x] No remote executable extension code
- [x] Remote channel restricted to signed blocking-filter data
- [x] No POST/PUT/PATCH/DELETE extension update request
- [x] Incognito/private mode disabled
- [x] Permissions audited against current functionality
- [x] Test-only custom scriptlet layer removed
- [x] Test hooks removed from production first-party content scripts
- [x] Imported raw filter rules that actively initiated network requests removed
- [x] Unused web-accessible redirect resources removed
- [x] Remaining web-accessible resources explicitly allowlisted (no wildcard resource path)
- [x] Licenses and third-party notices included
- [x] Automated privacy/update tests passing

## Store/dashboard — must be completed before clicking Submit for review

- [ ] Deploy and verify https://broxme.com/ishield/privacy/ publicly
- [ ] Verify https://broxme.com/ishield/ publicly
- [ ] Upload final store ZIP from this submission kit
- [ ] Complete single-purpose field using PRIVACY-PRACTICES.md
- [ ] Paste each permission justification from PERMISSION-JUSTIFICATIONS.md
- [ ] Remote code: select No
- [ ] Complete user-data fields consistently with PRIVACY-PRACTICES.md
- [ ] Add the iShield Extension privacy-policy URL
- [ ] Add accurate category, language, support contact, and distribution settings
- [ ] Upload required icon/screenshots/promotional assets with no misleading claims
- [ ] Paste reviewer notes if the dashboard provides a reviewer-notes/support field
- [ ] Re-open the uploaded ZIP in the dashboard and confirm version 1.0.0.1

Store approval is determined by Google and cannot be guaranteed by a local audit.
