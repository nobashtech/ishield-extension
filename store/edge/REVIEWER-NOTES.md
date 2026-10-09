# iShield Extension — reviewer notes for Microsoft Edge Add-ons

Thank you for reviewing iShield.

## Single purpose

iShield Extension is a browser protection extension for Microsoft Edge. It blocks ads and trackers, performs cosmetic/page cleanup, and provides local phishing, scam, malware, fingerprinting, and breakage protection.

## Network/privacy boundary

iShield Extension does not require an account and does not upload browsing history, visited URLs, page content, search terms, form data, passwords, device identifiers, installation identifiers, analytics, or telemetry to Broxme or another backend service.

Its own backend communication is limited to a generic HTTPS GET to:

https://update.broxme.com/ishield/manifest.json

The request is used only for signed blocking-filter updates. It has no request body, omits credentials and referrer, and rejects redirects.

## Filter updates are structured data, not remote code

All executable extension JavaScript is packaged in this submission.

The update channel is deliberately narrow:

- Ed25519 signature verification is required;
- SHA-256 integrity verification is required;
- expiry/validity and monotonic sequence checks are required;
- exactly one resource is accepted: `network-rules`;
- accepted fields are limited to host, scope, and resourceTypes;
- only exact-host or host-and-subdomain matching is accepted;
- packaged code compiles the data into block-only Declarative Net Request rules;
- remote JavaScript, WebAssembly, server-supplied regex logic, remote feature flags, policy assignments, reputation lookups, and executable logic are rejected.

For exact-host rules, any DNR regular expression is generated locally by packaged extension code from the validated hostname; a remote regex is not accepted.

## Packaged filtering/scriptlets

Some bundled AdGuard/uBlock-derived resources include packaged scriptlet logic used for anti-adblock and page cleanup. They are included in the submitted extension package and are reviewable locally. They are not downloaded or replaced through the remote filter-update channel.

For this Edge release, imported raw filter rules that themselves initiated network requests were removed. Packaged scriptlets that block, modify, or observe page behavior remain because they provide the extension's disclosed protection functionality.

## Permissions

- `declarativeNetRequest`: core network filtering.
- `scripting`: registers/manages packaged page-protection scripts and CSS.
- `storage`: local settings/protection state only.
- `alarms`: periodic signed filter-update check.
- `activeTab`: user-initiated current-tab matched-rule statistics without requesting `declarativeNetRequestFeedback`.
- `http://*/*` and `https://*/*`: necessary for all-site ad/tracker and page protection.

## InPrivate browsing

The manifest sets `incognito: not_allowed`.
