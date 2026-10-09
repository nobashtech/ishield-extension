# Microsoft Edge Add-ons — policy references used for this release

Prepared: October 5, 2026

Official Microsoft references reviewed for this release:

- Publish a Microsoft Edge extension: https://learn.microsoft.com/en-us/microsoft-edge/extensions/publish/publish-extension
- Developer policies for Microsoft Edge Add-ons: https://learn.microsoft.com/en-us/legal/microsoft-edge/extensions/developer-policies
- Manifest V3 format for Microsoft Edge extensions: https://learn.microsoft.com/en-us/microsoft-edge/extensions/getting-started/manifest-format

Release decisions based on these policies:

- Manifest V3 is used.
- Only permissions required by current functionality are requested.
- Remote executable code is not used.
- Remote DNR/filter data is limited to the filter-update purpose and is validated by packaged code.
- Data practices and permission use are described accurately in Partner Center materials.
- The Edge privacy policy is product-specific and Edge-focused.
- Store listing metadata should not reference competing browsers.
