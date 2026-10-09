# iShield Extension — product rename

The public product name is **iShield Extension** and the GitHub repository slug is `ishield-extension`.

The Chrome, Edge, Firefox and Opera extension manifests use `name: iShield Extension`, `short_name: iShield`, and an `iShield Extension` toolbar tooltip. The compact popup and standalone warning pages also use the new public name.

**Intentionally unchanged**

- Internal code paths, modules and runtime storage keys continue to use `ishield`/`iShield` for compatibility.
- The filter manifest URL is `https://update.broxme.com/ishield/manifest.json`.
- The Firefox `browser_specific_settings.gecko.id` value is unchanged.
- Existing version remains `1.0.0.1` in this source snapshot; source branding alone is not a store update.
- Signing keys, extension identity and data-processing boundaries are not changed by this rename.

**Publishing an update to existing users**

1. Update the store developer-dashboard listing title to **iShield Extension** where applicable; the repository does not modify a live listing.
2. Bump the `version` to a valid version greater than the currently published build in each browser's manifest before uploading.
3. Build and test the separately packaged browser artifacts, then submit to the same existing store entry/publisher identity. Do not create a new extension listing to perform a rename.
4. Verify installed-extension update behavior and the privacy/permission disclosures in a real browser.

No store listing has been edited by this source package.
