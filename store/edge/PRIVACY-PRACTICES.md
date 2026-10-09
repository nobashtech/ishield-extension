# Microsoft Edge Add-ons — Privacy answers

These answers are for the current Edge package and must remain consistent with the public Edge-specific iShield Extension privacy policy.

## Single purpose

Use:

> iShield Extension protects web browsing in Microsoft Edge by blocking ads and trackers, cleaning intrusive page elements, and warning about phishing, scam, and malware risks. Protection is processed locally in the browser. iShield Extension's own backend communication is limited to downloading signed blocking-filter updates.

## Remote code

Select: **No, I am not using remote code.**

If a reviewer asks:

> All JavaScript and executable extension logic is packaged with the submitted Manifest V3 extension. iShield Extension's fixed HTTPS update endpoint provides only Ed25519-signed filter data. The updater accepts exactly one `network-rules` resource with a narrow host/scope/resourceTypes schema. Packaged code validates it and compiles it into block-only Declarative Net Request rules. The update server cannot provide JavaScript, WebAssembly, arbitrary executable code, remote feature logic, or remote policy logic.

## Data usage

Be conservative and transparent:

- **Browsing activity / web history:** iShield Extension necessarily accesses the current page URL/hostname and request context locally to provide its user-facing protection features. It does not upload or build a remote history of visited sites.
- **Website content:** iShield Extension locally inspects limited page/DOM signals for cosmetic filtering and phishing/scam/breakage protection. Page content is not uploaded by iShield.
- **Settings and local protection records:** stored locally in Edge extension storage. They are not cloud-synced.

Do not state that the extension never accesses browsing information. The correct statement is that required browsing information is processed locally for protection and is not sent to Broxme or an analytics/data service.

The current code does not require collection/transmission of personally identifiable information, health information, financial/payment information, authentication information, personal communications, precise location, advertising identifiers, or device/installation identifiers.

## Remote filter updates

The extension's backend communication is limited to a generic HTTPS GET to:

https://update.broxme.com/ishield/manifest.json

The request has no user-specific body, omits credentials and referrer, and rejects redirects. The accepted payload is signed structured filter data only. Imported site-specific filter exceptions that could originate their own network requests were removed from the Edge release; normal packaged filtering/scriptlet protection remains.

## Privacy policy URL

https://broxme.com/ishield/privacy/edge/

This URL must be publicly reachable and show the Edge-specific policy before submission.
