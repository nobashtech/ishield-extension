# Brave compatibility

iShield Extension does not maintain a separate Brave code fork. Brave desktop supports Chrome Web Store extensions and Manifest V3 Chrome extensions, so the canonical Chrome build is the Brave-compatible build.

## Recommended installation

Install iShield Extension from its Chrome Web Store listing while using Brave. Brave presents the install action as **Add to Brave**.

## GitHub/manual package

For development or compatibility testing, the GitHub release may include `iShield-Brave-<version>-compatible.zip`. It is intentionally byte-for-byte identical to the corresponding Chrome release ZIP. This is not a separate Brave Store package and does not have a separate update channel.

## Privacy and permissions

The Brave-compatible build has the same Manifest V3 permissions, local processing model, and signed filter-update boundary as the Chrome build. See `store/chrome/` and `docs/NETWORK-BOUNDARY.md`.
