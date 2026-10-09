// iShield YouTube ad defence. Runs in the page's own world at document_start on youtube.com, before YouTube's scripts.
//
//  1. Removes the ad instructions (adPlacements, playerAds, adSlots) from the player data YouTube's own code receives:
//     the inline ytInitialPlayerResponse, JSON.parse results and Response.json() results. This is what stops most
//     pre-roll and mid-roll ads from being requested at all.
//  2. If an ad still starts (for example one stitched into the video stream), it is muted, played at 16x and its Skip
//     button is pressed. It never seeks: a wrong guess would otherwise jump over the real video.
//  3. The ad containers on the page are hidden by youtube-ads.css.
// Everything here is defensive: nothing may throw into the page, and unknown shapes are left alone.
(() => {
  'use strict';
  const root = globalThis;
  if (root.__ishieldYoutubeAds) return;
  const AD_KEYS = Object.freeze(['adPlacements', 'playerAds', 'adSlots', 'adBreakHeartbeatParams']);
  const MAX_DEPTH = 3;
  const MAX_ARRAY_ITEMS = 8;
  const AD_CLASSES = Object.freeze(['ad-showing', 'ad-interrupting']);
  const SKIP_SELECTOR = '.ytp-skip-ad-button, .ytp-ad-skip-button, .ytp-ad-skip-button-modern, [class*="ytp-ad-skip-button"]';
  const CLOSE_SELECTOR = '.ytp-ad-overlay-close-button';
  const AD_PLAYBACK_RATE = 16;

  const isObject = (value) => value !== null && typeof value === 'object';
  // Only real player responses are touched, so an unrelated object that happens to have an "adSlots" key is safe.
  const isPlayerResponse = (value) => isObject(value) && (isObject(value.playabilityStatus) || isObject(value.streamingData) || isObject(value.videoDetails));

  function strip(value, depth = 0) {
    if (!isObject(value) || depth > MAX_DEPTH) return value;
    try {
      if (Array.isArray(value)) {
        for (let index = 0; index < value.length && index < MAX_ARRAY_ITEMS; index += 1) strip(value[index], depth + 1);
        return value;
      }
      if (isPlayerResponse(value)) for (const key of AD_KEYS) if (key in value) delete value[key];
      if (isObject(value.playerResponse)) strip(value.playerResponse, depth + 1);
      if (isObject(value.response)) strip(value.response, depth + 1);
    } catch { /* leave hostile or frozen objects alone */ }
    return value;
  }

  function hookInitialPlayerResponse() {
    try {
      let stored = root.ytInitialPlayerResponse;
      Object.defineProperty(root, 'ytInitialPlayerResponse', {
        configurable: true,
        enumerable: true,
        get() { return stored; },
        set(value) { stored = strip(value); },
      });
      if (stored !== undefined) stored = strip(stored);
    } catch { /* another script already locked it */ }
  }

  function hookJsonParse() {
    try {
      const original = root.JSON.parse;
      root.JSON.parse = new Proxy(original, {
        apply(target, thisArg, args) {
          const result = Reflect.apply(target, thisArg, args);
          return isObject(result) ? strip(result) : result;
        },
      });
    } catch { /* unsupported */ }
  }

  function hookResponseJson() {
    try {
      const proto = root.Response?.prototype;
      const original = proto?.json;
      if (typeof original !== 'function') return;
      proto.json = new Proxy(original, {
        apply(target, thisArg, args) {
          const pending = Reflect.apply(target, thisArg, args);
          return pending.then((data) => (isObject(data) ? strip(data) : data));
        },
      });
    } catch { /* unsupported */ }
  }

  // ---- ad that starts anyway -------------------------------------------------------------------------------------
  let saved = null;

  function tick() {
    try {
      const doc = root.document;
      const player = doc?.querySelector?.('.html5-video-player');
      const video = player?.querySelector?.('video');
      if (!player || !video) return;
      const inAd = AD_CLASSES.some((name) => player.classList.contains(name));
      if (inAd) {
        if (saved === null) saved = { muted: video.muted, rate: video.playbackRate };
        video.muted = true;
        if (video.playbackRate !== AD_PLAYBACK_RATE) video.playbackRate = AD_PLAYBACK_RATE;
        for (const selector of [SKIP_SELECTOR, CLOSE_SELECTOR]) {
          const button = doc.querySelector(selector);
          if (button && typeof button.click === 'function') button.click();
        }
      } else if (saved !== null) {
        video.muted = saved.muted;
        video.playbackRate = saved.rate;
        saved = null;
      }
    } catch { /* never disturb the page */ }
  }

  function startWatching() {
    try { root.setInterval(tick, 250); } catch { /* no timers */ }
  }

  root.__ishieldYoutubeAds = true;
  hookInitialPlayerResponse();
  hookJsonParse();
  hookResponseJson();
  startWatching();
  if (root.__ISHIELD_YOUTUBE_TEST__ === true) root.__ISHIELD_YOUTUBE_INTERNALS__ = Object.freeze({ strip, tick, isPlayerResponse, AD_KEYS });
})();
