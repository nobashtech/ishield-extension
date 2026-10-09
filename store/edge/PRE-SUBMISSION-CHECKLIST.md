# Microsoft Edge Add-ons pre-submission checklist

## Code/package

- [x] Manifest V3
- [x] Restrictive extension-page CSP
- [x] No managed-device, central-control, family-control, OAuth, or externally-connectable runtime
- [x] No extension analytics or telemetry upload
- [x] No remote executable extension code
- [x] Remote channel restricted to signed blocking-filter data
- [x] No POST/PUT/PATCH/DELETE backend update request
- [x] InPrivate mode disabled
- [x] Permissions audited against current functionality
- [x] Non-production custom test/lab scriptlet layer absent
- [x] Production AdGuard/uBlock filtering/scriptlets retained
- [x] Imported raw filter rules that actively initiated network requests removed
- [x] Web-accessible redirect resources explicitly allowlisted
- [x] Licenses and third-party notices included
- [x] Automated privacy/update tests passing
- [x] JavaScript syntax validation passing
- [x] Chromium/Edge-compatible package acceptance smoke test passing

## Partner Center — must be completed before Submit

- [ ] Deploy and verify https://broxme.com/ishield/privacy/edge/ publicly
- [ ] Verify https://broxme.com/ishield/ publicly
- [ ] Upload final Edge ZIP from this submission kit
- [ ] Use the single-purpose text from PRIVACY-PRACTICES.md
- [ ] Paste each permission justification from PERMISSION-JUSTIFICATIONS.md
- [ ] Remote code: select **No, I am not using remote code**
- [ ] Complete data-usage disclosures consistently with PRIVACY-PRACTICES.md
- [ ] Add the Edge-specific iShield Extension privacy-policy URL
- [ ] Add accurate category, language, support contact, markets/distribution, and age rating
- [ ] Upload clear screenshots/assets that reflect the real extension UI
- [ ] Do not reference competing browsers in Edge store listing metadata/screenshots
- [ ] Add reviewer notes where Partner Center allows them
- [ ] Re-open uploaded package and confirm version 1.0.0.1

Certification is determined by Microsoft and cannot be guaranteed by a local audit.
