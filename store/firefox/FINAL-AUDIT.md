# Firefox AMO Final Audit — iShield Extension 1.0.0.1

## Code/privacy boundary
PASS — managed-device, central-control and family-control runtime removed.

PASS — no telemetry, analytics, account, OAuth, device ID or installation ID client.

PASS — the only first-party remote client is the signed filter updater at `https://update.broxme.com/ishield/manifest.json`.

PASS — update request is GET-only with credentials omitted, redirects rejected and referrer suppressed.

PASS — updater accepts exactly one signed `network-rules` resource and does not accept remote executable code.

PASS — imported site-specific filter exceptions that could originate network requests were excluded while the general blocking/cosmetic/scriptlet engines remain.

## Firefox manifest / DNR
PASS — Manifest V3.

PASS — Gecko ID `ishield@nobash.com`.

PASS — `strict_min_version` 140.0.

PASS — `data_collection_permissions.required = ["none"]`.

PASS — private browsing disabled.

PASS — 13 static rulesets / 8 enabled-by-default rulesets.

PASS — 43,020 static rules; 27,183 enabled by default; 161 regex rules total; highest regex count in one static ruleset: 142.

PASS — managed dynamic-rule budget: 4,960 / 5,000.

PASS — 29 exact web-accessible resources, no wildcard resource paths.

## Integrity / syntax
PASS — all extension JSON files parsed successfully in preflight.

PASS — secret/private-key scan clear.

PASS — 98 JavaScript files passed `node --check` before packaging.

PASS — signed update test suite: 4/4.

PASS — privacy/network-boundary audit.

## Source reproducibility
Prepared — source archive includes readable source, exact lockfile-pinned public npm dependencies, build scripts and deterministic package script.

Environment limitation during this preparation: the working container's pre-existing `node_modules` directory was incomplete and lacked the `esbuild` module files, so a clean `npm ci` + `npm run build-for-amo` could not be completed locally without npm registry access. The submitted source recipe is designed for AMO/reviewer clean-room reproduction using the official npm registry. This limitation is disclosed rather than hidden.

## External pre-submission dependencies
The Firefox-specific privacy policy must be deployed and publicly reachable before submission.

The live filter-update endpoint must match the documented privacy boundary and must not add user-specific request requirements.

AMO's validator and reviewer remain the final external approval gates.

## Native Firefox / AMO validator limitation
The preparation environment does not include a Firefox binary or the `web-ext` CLI, so a native Firefox launch test and AMO's server-side validator were not run here. The package is prepared for AMO upload, where Mozilla's validator and signing/review pipeline should be treated as the final external compatibility check.
