# iShield Extension — Opera permission justifications

## activeTab

Used after the user opens the iShield Extension toolbar popup to read the current tab's local matched-rule/blocking status. It is not used to upload the tab URL.

## declarativeNetRequest

Core permission for blocking ads, trackers and known malicious network requests with browser-managed Manifest V3 rules.

## storage

Stores protection mode, allowlist/Strict choices, filter-update state and local activity counters on the user's device.

## scripting

Runs packaged, fixed local filtering/cleanup scripts required for cosmetic filtering and anti-adblock handling. No remotely downloaded JavaScript or executable code is injected.

## alarms

Schedules periodic checks for signed blocking-filter updates and local maintenance.

## http://*/* and https://*/* host access

Required because an ad/tracker/security blocker must evaluate and clean web pages across the sites the user visits. Page/URL information is processed locally and is not uploaded by iShield.

## Permissions intentionally not requested

No cookies, history, identity, management, nativeMessaging, downloads, geolocation, proxy, webRequest, or webRequestBlocking permission is requested.
