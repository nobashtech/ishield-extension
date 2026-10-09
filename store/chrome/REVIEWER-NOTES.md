# iShield Extension — reviewer notes for Chrome Web Store

Thank you for reviewing iShield.

## What the extension does

iShield Extension is a single-purpose browser protection extension. It blocks ads and trackers, performs cosmetic/page cleanup, and provides local phishing, scam, malware, fingerprinting, and breakage protection.

## Network/privacy boundary

The extension does not require an account and does not upload browsing history, visited URLs, page content, search terms, form data, passwords, device identifiers, installation identifiers, analytics, or telemetry.

The only extension-originated remote request is a generic HTTPS GET to:

https://update.broxme.com/ishield/manifest.json

This request is used only for signed blocking-filter updates. It uses no request body, omits credentials, sends no referrer, and rejects redirects.

## Filter updates are not remote executable code

All executable extension JavaScript is packaged in this submission.

The remote update channel is deliberately narrow:

- Ed25519 signature verification is required;
- SHA-256 integrity verification is required;
- expiry/validity and monotonic sequence checks are required;
- exactly one resource is accepted: `network-rules`;
- accepted rule fields are limited to host, scope, and resourceTypes;
- only exact-host or host-and-subdomain matching is accepted;
- packaged code compiles the data into block-only Declarative Net Request rules;
- remote JavaScript, WebAssembly, regex logic supplied by the server, arbitrary feature flags, policy assignments, reputation lookups, and executable logic are not accepted.

For exact-host rules, any required DNR regular expression is generated locally by packaged extension code from the validated hostname; a remote regex is not accepted.

## Packaged filter scriptlets

Some bundled AdGuard/uBlock-derived filtering resources include packaged scriptlet logic used for anti-adblock and page cleanup. These files are included in the submitted extension package and are reviewable locally. They are not downloaded or replaced through the remote filter-update channel.

For this release, imported raw filter rules that actively initiated their own network requests were removed. Normal packaged scriptlets that block, modify, or observe page behavior remain.

## Permissions

- `declarativeNetRequest`: core network filtering.
- `scripting`: registers/manages packaged page-protection scripts and CSS.
- `storage`: local settings/protection state only.
- `alarms`: periodic signed filter-update check.
- `activeTab`: user-initiated current-tab matched-rule statistics without requesting `declarativeNetRequestFeedback` in the store build.
- `http://*/*` and `https://*/*`: necessary for all-site ad/tracker and page protection.

## Private browsing

The manifest sets `incognito: not_allowed`.
