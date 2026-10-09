# iShield Extension — Opera Add-ons submission sheet

Version: 1.0.0.1  
Prepared: October 5, 2026  
Privacy policy: https://broxme.com/ishield/privacy/opera/  
Homepage: https://broxme.com/ishield/

## Product name

iShield Extension

## Category

Productivity

## Summary

Fast ad and tracker blocking with local phishing, scam and malware protection for a cleaner, safer web.

## Single purpose

iShield Extension protects browsing in Opera by blocking ads and trackers, cleaning intrusive page elements, and warning about phishing, scam, and malware risks. Protection is processed locally in the browser. The only extension-originated remote request downloads signed blocking-filter updates.

## Detailed description

iShield Extension is a privacy-focused browser protection extension for Opera, built for faster, cleaner and safer everyday browsing.

Core protection includes:

- ad and tracker blocking using Manifest V3 Declarative Net Request rules;
- cosmetic page cleanup for intrusive ad elements;
- packaged anti-adblock and site-specific filtering scriptlets where required by filter lists;
- phishing, scam and malware warning checks processed locally in Opera;
- YouTube and Facebook cleanup support;
- fingerprint-protection controls;
- allowlist and Strict controls for sites you choose;
- local protection activity and blocked-item statistics;
- signed filter-list updates to keep blocking rules current.

iShield Extension does not require an account and does not upload browsing history, visited URLs, page content, search terms, form data, passwords, device identifiers, installation identifiers, analytics, or telemetry.

The extension periodically makes a generic HTTPS GET request to `https://update.broxme.com/ishield/manifest.json` only to obtain signed filter-list data. The update channel cannot deliver JavaScript, WebAssembly, or other executable extension logic. All executable extension code is packaged with the submitted extension.

Private browsing is disabled for iShield.

Privacy policy: https://broxme.com/ishield/privacy/opera/
