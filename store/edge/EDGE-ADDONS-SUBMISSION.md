# iShield Extension — Microsoft Edge Add-ons submission sheet

Version: 1.0.0.1
Prepared: October 5, 2026
Privacy policy: https://broxme.com/ishield/privacy/edge/
Homepage: https://broxme.com/ishield/

## Product name

iShield Extension

## Short description

Fast ad and tracker blocker with phishing, scam and malware protection. Filtering runs locally in Microsoft Edge, with no account or analytics tracking.

## Single purpose

iShield Extension protects web browsing in Microsoft Edge by blocking ads and trackers, cleaning intrusive page elements, and warning about phishing, scam, and malware risks. Protection is processed locally in the browser. iShield Extension's own backend communication is limited to downloading signed blocking-filter updates.

## Detailed store description

iShield Extension is a privacy-focused browser protection extension for Microsoft Edge, built for faster, cleaner, and safer everyday browsing.

Core protection includes:

- ad and tracker blocking using Manifest V3 Declarative Net Request rules;
- cosmetic page cleanup for intrusive ad elements;
- packaged anti-adblock and site-specific filtering scriptlets where required by filter lists;
- phishing, scam, and malware warning checks processed locally in Microsoft Edge;
- YouTube and Facebook cleanup support;
- fingerprint-protection controls;
- allowlist and Strict controls for sites you choose;
- local protection activity and blocked-item statistics;
- signed filter-list updates to keep blocking rules current.

iShield Extension does not require an account. It does not upload browsing history, visited URLs, page content, search terms, form data, passwords, device identifiers, installation identifiers, analytics, or telemetry to Broxme or another backend service.

The extension periodically makes a generic HTTPS GET request to https://update.broxme.com/ishield/manifest.json only to obtain signed filter-list data. The update channel cannot deliver JavaScript, WebAssembly, or other executable extension logic. All executable extension code is packaged in the Microsoft Edge Add-ons submission.

Private/InPrivate browsing is disabled for iShield.

Privacy policy: https://broxme.com/ishield/privacy/edge/
