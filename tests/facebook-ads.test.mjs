import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

function loadInternals(browser = 'chrome') {
  const source = fs.readFileSync(new URL(`../extensions/${browser}/content/facebook-ads.js`, import.meta.url), 'utf8');
  const context = {
    globalThis: null,
    browser: {},
    chrome: {},
    location: { hostname: 'www.facebook.com' },
    __ISHIELD_TESTING__: true,
    Node: { ELEMENT_NODE: 1 },
    Set,
    WeakSet,
    Object,
    Array,
    String,
    Number,
    Boolean,
    RegExp,
    Math,
    Date,
    JSON,
    console,
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(source, context, { filename: 'facebook-ads.js' });
  return context.__ISHIELD_FACEBOOK_INTERNALS__;
}

test('current Facebook disclosure labels are recognized', () => {
  const api = loadInternals();
  assert.equal(api.normalizedLooksSponsored('Ad'), true);
  assert.equal(api.normalizedLooksSponsored('Sponsored'), true);
  assert.equal(api.normalizedLooksSponsored('বিজ্ঞাপন'), true);
  assert.equal(api.normalizedLooksSponsored('Add friend'), false);
});

test('direct role=feed child is recovered as the feed unit', () => {
  const api = loadInternals();
  const feed = { parentElement: null };
  const unit = { parentElement: feed };
  const inner = {
    nodeType: 1,
    parentElement: unit,
    closest(selector) { return selector === '[role="feed"]' ? feed : null; },
  };
  assert.equal(api.directFeedUnit(inner), unit);
});

test('all browser copies contain the current feed structural fallback', () => {
  for (const browser of ['chrome','edge','opera','firefox']) {
    const source = fs.readFileSync(new URL(`../extensions/${browser}/content/facebook-ads.js`, import.meta.url), 'utf8');
    assert.match(source, /\[role="feed"\] > div/);
    assert.match(source, /function directFeedUnit/);
    assert.match(source, /function geometricDisclosureCard/);
  }
});
