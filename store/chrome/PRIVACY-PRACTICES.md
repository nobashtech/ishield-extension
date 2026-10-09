# Chrome Web Store — Privacy practices answers

These answers are written for the current Chrome package and must stay consistent with the public iShield Extension privacy policy.

## Single purpose

Use:

> iShield Extension protects web browsing by blocking ads and trackers, cleaning intrusive page elements, and warning about phishing, scam, and malware risks. Protection is processed locally in the browser. The only extension-originated remote request downloads signed blocking-filter updates.

## Remote code

Select: **No, I am not using remote code.**

Explanation if a reviewer asks:

> All JavaScript and executable extension logic is packaged with the submitted extension. iShield Extension's fixed HTTPS update endpoint provides only Ed25519-signed filter data. The updater accepts exactly one `network-rules` resource with a narrow host/scope/resourceTypes schema. Packaged code validates it and compiles it into block-only Declarative Net Request rules. The update server cannot provide JavaScript, WebAssembly, arbitrary code, policy logic, or feature logic.

## User-data disclosure

Conservative disclosure for Chrome's user-data categories:

- **Web history / browsing activity:** disclose because iShield Extension necessarily accesses the current page URL/hostname and browser request context locally to provide its user-facing protection features. iShield Extension does not upload or build a remote history of visited sites.
- **Website content:** disclose because iShield Extension locally inspects limited page content/DOM signals for cosmetic filtering and phishing/scam/breakage protection. Page content is not uploaded by iShield.

Do **not** claim that iShield Extension never handles browsing information. The accurate statement is that necessary browsing information is handled locally for protection and is not transmitted off-device by iShield.

Current code does not require disclosure of personally identifiable information, health information, financial/payment information, authentication information, personal communications, precise location, or advertising identifiers because iShield Extension neither requests nor transmits those categories.

## Limited Use certifications

Certify only while the submitted code continues to match this release:

- user data is used only for iShield Extension's disclosed browser-protection purpose;
- browsing activity and website content are accessed only as required for those user-facing protection features;
- user data is not sold;
- user data is not transferred to advertisers, data brokers, or unrelated third parties;
- user data is not used for personalized advertising, profiling, creditworthiness, or lending;
- iShield Extension does not upload analytics or telemetry.

## Privacy policy URL

https://broxme.com/ishield/privacy/

The public URL must be live and must show the iShield-specific policy before the store submission is sent for review.
