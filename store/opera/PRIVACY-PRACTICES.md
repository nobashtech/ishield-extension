# iShield Extension — Opera privacy disclosure answers

## Does iShield Extension collect or transmit private browsing data?

No. iShield Extension processes information such as the current URL/hostname and limited page content locally when required to block ads/trackers, apply cosmetic filtering, or display security warnings. iShield Extension does not upload this information to Broxme or another backend service.

## Does iShield Extension use analytics or telemetry?

No.

## Does iShield Extension create an account or identifier?

No. There is no iShield Extension account, device ID, installation ID, advertising ID, or remote user profile.

## What remote connection does iShield Extension make?

A periodic generic HTTPS GET to `https://update.broxme.com/ishield/manifest.json` for signed filter-list updates only. It has no request body, sends no iShield Extension user/device identifier, omits credentials, rejects redirects, and uses `no-referrer`.

## Does the update channel deliver executable code?

No. The signed update schema accepts only structured `network-rules` data. Executable extension logic ships inside the store package.

## Does iShield Extension sell or share user data?

No.
