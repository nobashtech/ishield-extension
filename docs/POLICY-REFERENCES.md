# Browser-store policy references

Checked: October 5, 2026.

These links are reference material for the per-store submission work. Store policies can change, so they must be re-checked immediately before each submission.

## Google Chrome Web Store

- Program Policies: https://developer.chrome.com/docs/webstore/program-policies/
- Manifest V3 requirements: https://developer.chrome.com/docs/webstore/program-policies/mv3-requirements
- Chrome extension privacy guidance: https://developer.chrome.com/docs/extensions/develop/security-privacy/user-privacy

Baseline used by iShield Extension: Manifest V3, packaged executable logic, no remote executable code, minimum permissions for the stated protection purpose, accurate privacy disclosures, and signed remote filter data interpreted only by packaged code.

## Microsoft Edge Add-ons

- Developer policies: https://learn.microsoft.com/en-us/legal/microsoft-edge/extensions/developer-policies
- Publishing/privacy declarations: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension

Baseline used by iShield Extension: single protection purpose, minimum required permissions, Manifest V3 without remote executable code, necessary DNR filter updates only, and accurate privacy/data declarations.

## Mozilla Firefox / AMO

- Add-on Policies: https://extensionworkshop.com/documentation/publish/add-on-policies/
- Firefox built-in data consent: https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/
- `browser_specific_settings`: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings
- Private/incognito manifest behavior: https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/incognito

Baseline used by iShield Extension: Firefox 140+, fixed Gecko ID, accurate `data_collection_permissions`, no extension user-data transmission, no remote executable code, and private browsing disabled in the manifest.


## Opera Add-ons

- Acceptance criteria: https://help.opera.com/en/extensions/acceptance-criteria/
- Publishing guidelines: https://help.opera.com/en/extensions/publishing-guidelines/
- Permissions declarations: https://help.opera.com/en/extensions/declare-permissions/
- MV2/MV3 transition announcement (September 10, 2025): https://blogs.opera.com/news/2025/09/mv2-extensions-opera/

Baseline used by iShield Extension: Manifest V3 for a new submission, one protection purpose, no external JavaScript, no private-data upload, minimum necessary permissions, reviewer-readable source, and signed filter data only.
