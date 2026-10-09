# Store policy baseline

This repository is the clean technical baseline. Final store submissions will be prepared separately for Chrome Web Store, Microsoft Edge Add-ons, Opera Add-ons and Firefox AMO.

## Chrome / Edge

- Manifest V3.
- No remotely hosted executable code.
- Remote content-filter updates are structured filter data only and are applied as dynamic Declarative Net Request rules by packaged code.
- Permissions are limited to the features visible in the extension.
- No account, analytics, telemetry, central management or user-data upload.
- Privacy/store disclosures must state the generic signed filter-update request accurately.

## Opera

- Manifest V3 for new Opera Add-ons submissions.
- One clearly stated browser-protection purpose.
- No external JavaScript or remote executable code.
- No private browsing-data upload.
- Minimum necessary permissions and reviewer-readable source.
- Signed remote filter data only, interpreted by packaged code.

## Firefox

- Manifest V3 with a fixed Gecko extension ID.
- `data_collection_permissions.required` is `none` because iShield Extension does not collect and transmit extension user data for storage or processing outside the extension.
- The generic signed filter update contains no user data and carries no iShield-generated identifier.
- No remote executable code.

Store acceptance can never be guaranteed by source code alone; final approval remains with each store reviewer. The purpose of this baseline is to remove known policy conflicts and make extension behavior directly reviewable.
