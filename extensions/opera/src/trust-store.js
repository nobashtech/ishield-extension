'use strict';

// Updates are accepted only if they are signed by a key listed here; an empty trust store fails
// closed (no remote update can be applied). The PRIVATE half of this key is never in the
// repository: it is created outside it by scripts/ishield_update_keys.mjs
// (~/.ishield/update-signing-key.pem). Never commit a private signing key. To rotate: generate a
// new key, add it here, release, then remove the old one.
export const UPDATE_TRUST_STORE = Object.freeze({ 'broxme-update-1': 'DWyh7gqZPyO_tijjTMVHz-NnGbo4z4Cakhr8ctGwGdU' });
// Filters published at https://update.broxme.com/ishield/ (see scripts/publish_filters.mjs).
export const UPDATE_CHANNEL = Object.freeze({ enabled: true, manifestUrl: 'https://update.broxme.com/ishield/manifest.json' });
