# iShield Extension — Opera reviewer notes

## Purpose

iShield Extension has one purpose: protect web browsing by blocking ads/trackers and locally detecting or warning about phishing, scam and malware risks.

## Network behavior

The extension's own backend communication is limited to:

`GET https://update.broxme.com/ishield/manifest.json`

This request has no request body, omits credentials, rejects redirects and uses a no-referrer policy. It is used only to obtain a signed filter manifest/resource.

The signed remote payload accepts exactly one `network-rules` resource. It cannot provide JavaScript, WebAssembly, feature logic, account policy, device policy, reputation lookups or other executable extension logic.

## User data

iShield Extension locally processes current page/URL information as needed to perform filtering and protection. It does not upload browsing history, visited URLs, page content, search terms, form data, passwords, account data, device identifiers, installation identifiers, analytics or telemetry.

## Packaged scriptlets / third-party code

AdGuard/uBlock-derived filtering assets and scriptlets are packaged in the submitted extension. They are not downloaded as executable code at runtime. Third-party notices and licenses are included. Build-time dependencies are pinned in the source package.

Imported raw rules that would originate their own `fetch`, `sendBeacon`, `XMLHttpRequest`, `WebSocket` or `EventSource` network activity are excluded from store builds by an automated privacy guard.

## Private browsing

The manifest sets `incognito: not_allowed`.

## Reviewer source

A reviewer source archive is provided with the submission kit. It contains the readable project source, pinned dependency metadata and build/audit scripts for generated filtering assets.
