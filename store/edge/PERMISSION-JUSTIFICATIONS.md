# Microsoft Edge Add-ons — permission justifications

Use these explanations in Partner Center's Privacy > Permission justification fields.

## activeTab

Used after the user opens or interacts with iShield Extension on the current tab so the extension can obtain current-tab Declarative Net Request match information and show local protection statistics. This avoids requesting the broader `declarativeNetRequestFeedback` permission for normal store builds.

## declarativeNetRequest

Core to iShield Extension's single purpose. It applies packaged and locally compiled rules to block ads, trackers, malicious hosts, and other unwanted network requests. It also supports packaged allow, redirect, and header rules required by the bundled filter lists. Signed remote filter updates are necessary to keep blocking coverage current; the remote data is narrowly validated and compiled locally into block-only rules by code shipped in the extension.

## storage

Stores iShield Extension settings and protection state locally in Microsoft Edge extension storage, including filter preferences, allowlist/Strict choices, local protection counters, breakage-recovery state, and the last verified filter-update state. iShield Extension does not cloud-sync this data.

## scripting

Registers and manages JavaScript/CSS packaged with iShield Extension for user-facing page protection, including cosmetic filtering, site cleanup, anti-adblock/filter scriptlets, YouTube/Facebook cleanup, and fingerprint protection. It is not used to download or execute remote JavaScript.

## alarms

Schedules periodic checks for signed filter-list updates. The alarm triggers a generic HTTPS GET to the fixed iShield Extension filter-update endpoint. It does not upload browsing or user data.

## Host access: http://*/* and https://*/*

Broad HTTP/HTTPS site access is necessary for iShield Extension's disclosed single purpose as an all-site ad/tracker blocker and page-protection extension. It allows packaged content protection and filtering to work on ordinary websites the user visits. iShield Extension does not request access to browser-internal pages, and InPrivate use is disabled.
