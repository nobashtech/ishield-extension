# iShield Extension Network Boundary

## Allowed extension-originated remote request

- Method: `GET`
- URL: `https://update.broxme.com/ishield/manifest.json`
- Purpose: signed blocking-filter updates only
- Credentials: omitted
- Redirects: rejected
- Referrer policy: no-referrer
- Request body: none
- User-specific headers: none

## Allowed remote payload

The signed envelope must contain exactly one full resource:

- `kind: network-rules`

Each rule may contain only:

- `host`
- `scope` (`exact` or `host-and-subdomains`)
- `resourceTypes`

All runtime logic that interprets these fields ships inside the extension package.

## Explicitly prohibited

- managed-device enrollment or sync;
- central or enterprise policy sync;
- family/child profiles or remote control;
- telemetry or analytics;
- browsing-history upload;
- URL/page-content upload;
- remote reputation lookups;
- remote malware lookups;
- remote compatibility/policy/privacy configuration;
- POST, PUT, PATCH or DELETE calls;
- remotely hosted JavaScript or executable code;
- arbitrary update hosts or redirects.

## Private/incognito boundary

The extension manifest sets `incognito: not_allowed` for Chrome, Edge and Firefox. Private/incognito tabs and windows are outside the extension runtime boundary.

## Cross-browser dynamic-rule budget

Firefox exposes a 5,000-rule dynamic DNR limit. iShield Extension reserves capacity for local allowlist and Strict rules and therefore caps the signed filter update at 1,400 compiled dynamic rules. The source filter payload may contain up to 10,000 host entries because host-and-subdomain entries are grouped into `requestDomains` rules before installation. The publisher dry-runs the real compiler before release.

## Imported page-filter boundary

Store builds retain packaged ad-blocking and anti-adblock scriptlets, but imported raw filter rules that actively initiate their own `fetch`, `sendBeacon`, `XMLHttpRequest`, `WebSocket`, or `EventSource` network activity are excluded. The automated privacy audit enforces this boundary.
