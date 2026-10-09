# Firefox Permission Justifications

## `declarativeNetRequest`
Core permission. iShield Extension uses Firefox DNR rules to block or redirect advertising, tracking, phishing, scam and malware requests. The extension ships static rules and may install a bounded set of locally verified dynamic rules from its signed filter-update channel.

## `http://*/*` and `https://*/*`
Core host access. A content blocker must protect users across ordinary websites. iShield Extension uses this access for local page-level cosmetic filtering, phishing/scam/malware checks, anti-breakage logic and packaged scriptlets. Website URLs and page content used by these protections are processed locally and are not uploaded.

## `scripting`
Required to run packaged cosmetic-filtering and protection scripts on supported pages. All executable code is included in the add-on package. iShield Extension does not download executable code.

## `storage`
Stores extension settings, allowlists, protection modes, local blocking counters and signed-filter update state locally in Firefox extension storage. It is not used for a cloud account or telemetry.

## `alarms`
Schedules periodic signed filter-update checks and local maintenance work while keeping the background runtime event-driven.

## `activeTab`
Used after the user opens or interacts with the toolbar popup to read the current tab and obtain local per-tab protection/matched-rule status. iShield Extension does not request `declarativeNetRequestFeedback`, because the narrower user-gesture path is sufficient for this use.

## Permissions intentionally not requested
No `cookies`, `history`, `bookmarks`, `identity`, `nativeMessaging`, `management`, `geolocation`, `downloads`, `proxy`, `webRequest`, `webRequestBlocking`, or `declarativeNetRequestFeedback` permissions are requested.
