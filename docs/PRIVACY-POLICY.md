# iShield Extension Privacy Policy

**Effective date:** October 5, 2026

This policy applies specifically to the iShield Extension browser extension for Google Chrome, Microsoft Edge and Mozilla Firefox. The public policy URL for store listings and in-extension links is `https://broxme.com/ishield/privacy/`.

## Privacy by design

iShield Extension is a browser protection extension. It blocks ads and trackers, applies page-cleanup filters, detects suspicious pages, and provides local protection controls and statistics. These features require the extension to access limited browsing information on the user's device, such as the current page URL, hostname, page content needed for protection checks, and network-request metadata exposed by browser extension APIs.

iShield Extension processes this information locally. It does not require an account and does not include advertising analytics, telemetry, managed-device enrollment, cloud policy synchronization, remote browsing-history sync, or user profiling.

## Data iShield Extension does not transmit off the device

iShield Extension does not send to Broxme, Nobash, advertisers, analytics providers, data brokers, or other third parties:

- browsing history or lists of websites visited;
- visited URLs, page contents, or search terms;
- form entries, passwords, authentication information, or personal communications;
- financial or health information;
- precise location;
- device identifiers or installation identifiers;
- extension usage analytics or telemetry;
- advertising identifiers;
- user-created allowlists, Strict rules, or local activity records.

## Local processing and local storage

iShield Extension locally handles web browsing activity and website content only to provide its user-facing protection features. Depending on the features the user enables, iShield Extension may process or store the following in browser extension storage on the user's device:

- the current tab URL/hostname and page content required for ad/tracker filtering and phishing, scam, malware, and breakage checks;
- protection settings and filter-list preferences;
- user-created allowlist and Strict rules, including site hostnames the user explicitly chooses to allow or control;
- local protection counters and timestamps;
- bounded local activity events containing category, source, count, and time;
- local breakage-recovery exceptions, including the affected site hostname;
- the last successfully verified signed filter update and its update status.

For phishing, scam, and malware warning flows, iShield Extension may temporarily keep the exact challenged URL in browser session storage so the user can choose whether to go back or continue. This temporary value is not uploaded, is not used to build a remote browsing profile, and expires or is cleared with the browser/extension session. Persistent activity records do not retain full visited URLs or a website-history list.

Users can clear iShield Extension's local data from the extension controls or by removing the extension.

## Private browsing

iShield Extension is packaged with private/incognito browsing disabled (`incognito: not_allowed`). It does not run content protection, local activity recording, or filter-update logic in private/incognito browser sessions.

## Filter-list updates

iShield Extension periodically makes a generic HTTPS `GET` request to:

`https://update.broxme.com/ishield/manifest.json`

The purpose of this request is only to download updated blocking/filter rules. iShield Extension does not attach browsing history, visited URLs, page content, search terms, a device ID, an installation ID, an account identifier, telemetry, analytics, or any user-specific request body to this request. Credentials are omitted, no referrer is sent, and redirects are rejected.

The update is accepted only when it is signed by iShield Extension's trusted Ed25519 signing key, is within its validity window, has a newer sequence number, passes its SHA-256 integrity check, and contains exactly one supported resource type: `network-rules`. Remote rules are restricted to block-only host/resource-type filters that are compiled by code packaged with the extension.

Filter updates are data, not remotely hosted executable code. iShield Extension does not download or execute JavaScript, WebAssembly, or other executable extension logic from the update server.

As with any normal HTTPS connection, the server and network providers may technically receive ordinary connection metadata needed to deliver the response, such as the requesting IP address and standard HTTP/TLS metadata. iShield Extension does not add a user-specific identifier to the request. The iShield Extension filter-update service should be operated without user profiling and with access-log retention minimized or disabled where operationally possible.

## Sharing and sale of data

iShield Extension does not sell user data. iShield Extension does not share extension user data with advertisers, data brokers, analytics providers, or other third parties. Browsing information handled for protection remains on the user's device.

## Permissions

iShield Extension requests browser permissions only for its user-facing protection features. Broad HTTP/HTTPS site access is required for an ad/tracker blocker and page-protection extension to apply filtering across websites. `declarativeNetRequest` is used for network filtering, `scripting` for packaged content-protection scripts, `storage` for local settings and protection state, `alarms` for periodic signed filter-update checks, and `activeTab` for user-initiated current-tab protection statistics. iShield Extension does not request the optional `declarativeNetRequestFeedback` permission in store builds.

## Remote code

iShield Extension does not use remotely hosted executable code. All JavaScript that controls extension behavior is packaged with the extension submitted to the browser store. Remote filter data is narrowly validated and converted to Declarative Net Request block rules by packaged code.

## Chrome Web Store Limited Use

iShield Extension's access to browsing activity and website content is limited to providing and improving the extension's disclosed browser-protection features. iShield Extension does not use this information for advertising, profiling, creditworthiness, unrelated purposes, or sale to third parties. iShield Extension's use of information received through Chrome extension APIs complies with the Chrome Web Store User Data Policy, including the Limited Use requirements.

## Children's data

iShield Extension does not provide cloud family management, child profiles, or managed-device features and does not knowingly collect children's personal information through an iShield Extension server.

## Changes to this policy

If iShield Extension's data practices change in a future version, this policy and the applicable browser-store disclosures will be updated before the changed behavior is released.

## Contact

For privacy questions about iShield Extension, use the support/contact information published on the official iShield Extension website at `https://broxme.com/ishield/`.
