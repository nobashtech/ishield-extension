'use strict';

// Facebook serves ads inside the same virtualised feed as ordinary posts. Class names are
// intentionally not used here: they are obfuscated and change often. Detection is limited to
// ad-disclosure metadata near the top of a card (including accessible labels and Facebook's
// visually ordered/scrambled "Sponsored" glyphs) so ordinary post text is never keyword-scanned.
(() => {
  const API = globalThis.browser ?? globalThis.chrome;
  const host = globalThis.location?.hostname;
  if (host !== 'facebook.com' && !host?.endsWith('.facebook.com')) return;

  // Test hooks must be explicitly enabled. Production builds must never depend on
  // an undeclared TESTING global because a ReferenceError here disables Facebook cleanup.
  const TESTING = globalThis.__ISHIELD_TESTING__ === true;

  const STATE_KEY = 'ishield.state.v1';
  const MARK = 'data-ishield-facebook-ad';
  const ROOTS = '[data-pagelet^="FeedUnit"], [role="feed"] > div, [role="feed"] [role="article"], [role="main"] [role="article"], [role="main"] [aria-posinset], [role="main"] [aria-describedby]';
  const HEADINGS = 'h2, h3, h4, [role="heading"]';
  const BODY = '[data-ad-preview="message"], [data-ad-comet-preview="message"], [data-testid*="comment"], [role="textbox"], [role="dialog"]';
  const INVISIBLE_RE = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/gu;
  const RAW_LABELS = Object.freeze([
    'ad', 'ads', 'advertisement', 'sponsored', 'sponsored content',
    'বিজ্ঞাপন', 'স্পনসরড', 'স্পন্সরড',
    'patrocinado', 'publicidad', 'publicidade',
    'sponsorisé', 'gesponsert', 'anzeige', 'sponsorizzato', 'pubblicità',
    'gesponsord', 'advertentie', 'sponsorowane', 'reklama',
    'प्रायोजित', 'विज्ञापन', 'ممّول', 'ممول', 'إعلان', 'اشتہار',
    'sponsorlu', 'reklam', 'bersponsor', 'disponsori', 'iklan',
    'реклама', '広告', '광고', '广告', '廣告', '赞助内容', '贊助內容',
  ]);

  const hidden = new Set();
  const queue = new Set();
  let observer = null;
  let style = null;
  let enabled = false;
  let scheduled = false;
  let generation = 0;
  const counted = globalThis.__ishieldCosmeticCounted ??= new WeakSet();

  function stripInvisible(text) {
    let value = String(text ?? '').replace(INVISIBLE_RE, '');
    try { value = value.normalize('NFKC'); } catch { /* Older engines still work without Unicode normalisation. */ }
    return value;
  }

  function normalize(text) {
    return stripInvisible(text).replace(/[^\p{L}\p{M}\p{N}]/gu, '').toLowerCase();
  }

  const LABELS = new Set(RAW_LABELS.map(normalize));
  const LONG_LABELS = [...LABELS].filter((value) => value.length >= 4);

  function normalizedLooksSponsored(value, allowContains = false) {
    const text = normalize(value);
    if (!text) return false;
    if (LABELS.has(text)) return true;
    if (!allowContains) return false;
    return LONG_LABELS.some((token) => text.includes(token));
  }

  // Accessibility labels are especially useful on current Facebook builds, e.g.
  // "Open menu for sponsored content". Short tokens such as "ad" are exact-only
  // to avoid false positives such as "Add friend".
  function accessibleLooksSponsored(value) {
    return normalizedLooksSponsored(value, true);
  }

  function renderedLeafText(element) {
    if (!element || element.getAttribute?.('aria-hidden') === 'true') return '';
    const raw = stripInvisible(element.textContent).trim();
    if (!raw || raw.length > 8) return '';
    const getStyle = globalThis.getComputedStyle;
    const computed = typeof getStyle === 'function' ? getStyle(element) : null;
    if (computed) {
      const opacity = Number.parseFloat(computed.opacity ?? '1');
      const fontSize = Number.parseFloat(computed.fontSize ?? '16');
      if (computed.display === 'none' || computed.visibility === 'hidden' || opacity <= 0.01 || fontSize <= 0.1) return '';
    }
    const rect = element.getBoundingClientRect?.();
    if (rect && (rect.width <= 0.25 || rect.height <= 0.25)) return '';
    return raw;
  }

  // Facebook can split the disclosure into one-character spans, add invisible Unicode,
  // add decoy spans, and use CSS flex order instead of DOM order. Reconstruct only small
  // metadata groups; never run this over the whole post body.
  function orderedVisibleLabel(root) {
    if (!root?.querySelectorAll) return '';
    const nodes = Array.from(root.querySelectorAll('span')).slice(0, 64);
    if (nodes.length < 2 || nodes.length > 48) return '';
    const leaves = [];
    let domIndex = 0;
    for (const node of nodes) {
      domIndex += 1;
      if (node.querySelector?.('span')) continue;
      const text = renderedLeafText(node);
      if (!text) continue;
      const computed = typeof globalThis.getComputedStyle === 'function' ? globalThis.getComputedStyle(node) : null;
      const rawOrder = computed?.order;
      const parsedOrder = rawOrder === 'auto' || rawOrder == null ? 0 : Number.parseFloat(rawOrder);
      const rect = node.getBoundingClientRect?.() ?? { left: 0, top: 0 };
      leaves.push({
        text,
        order: Number.isFinite(parsedOrder) ? parsedOrder : 0,
        left: Number.isFinite(rect.left) ? rect.left : 0,
        top: Number.isFinite(rect.top) ? rect.top : 0,
        domIndex,
      });
      if (leaves.length >= 32) break;
    }
    if (leaves.length < 2) return '';
    const hasExplicitOrder = leaves.some((item) => item.order !== 0);
    leaves.sort((a, b) => {
      if (hasExplicitOrder && a.order !== b.order) return a.order - b.order;
      if (Math.abs(a.top - b.top) > 3) return a.top - b.top;
      if (Math.abs(a.left - b.left) > 1) return a.left - b.left;
      return a.domIndex - b.domIndex;
    });
    return leaves.map((item) => item.text).join('');
  }

  function label(element, allowContains = false) {
    if (!element) return false;
    const accessible = element.getAttribute?.('aria-label');
    if (accessible && accessibleLooksSponsored(accessible)) return true;
    if (!accessible && (element.textContent?.length ?? 0) > 192) return false;
    if (normalizedLooksSponsored(element.innerText || element.textContent, allowContains)) return true;
    const reconstructed = orderedVisibleLabel(element);
    return Boolean(reconstructed) && normalizedLooksSponsored(reconstructed, true);
  }

  function nearCardHeader(card, element, maxOffset = 300) {
    const box = element?.getBoundingClientRect?.();
    const cardBox = card?.getBoundingClientRect?.();
    if (!box || !cardBox) return true; // Fail open to metadata checks when geometry is unavailable.
    if (box.height > 120) return false;
    if (cardBox.top > 0 && box.top > 0 && box.top - cardBox.top > maxOffset) return false;
    return true;
  }

  function disclosureInMetadata(marker, card) {
    if (!marker || marker.closest?.(BODY) || !nearCardHeader(card, marker)) return false;
    if (label(marker)) return true;
    // Current Facebook often wraps the visually scrambled disclosure in a small metadata row.
    for (let metadata = marker.parentElement, depth = 0; metadata && metadata !== card && depth < 4; metadata = metadata.parentElement, depth += 1) {
      if (metadata.closest?.(BODY) || !nearCardHeader(card, metadata)) break;
      const box = metadata.getBoundingClientRect?.();
      if (box && (box.height > 120 || box.width > 720)) break;
      if (label(metadata, true)) return true;
    }
    return false;
  }

  function feedAd(card) {
    if (card.closest(BODY)) return false;
    const markers = Array.from(card.querySelectorAll('a, [role="link"], [aria-label], span, h2, h3, h4, [role="heading"]')).slice(0, 420);
    for (const marker of markers) {
      if (!disclosureInMetadata(marker, card)) continue;
      if (marker.closest(BODY)) continue;
      if (marker.hasAttribute?.('aria-label')) return true;
      if (marker.closest?.('a')?.getAttribute?.('href')?.includes('/ads/')) return true;
      if (nearCardHeader(card, marker, 280)) return true;
    }
    return false;
  }

  function railAdSection(heading) {
    if (!label(heading, true) || heading.closest(BODY)) return null;
    const rail = heading.closest('[role="complementary"], [data-pagelet="RightRail"]');
    if (!rail && heading.closest('[role="main"], [role="feed"]')) return null;
    let section = heading.parentElement;
    for (let depth = 0; section && section !== rail && depth < 8; depth += 1, section = section.parentElement) {
      if (section.matches('body, html, [role="main"], [role="feed"]')) return null;
      if (Array.from(section.querySelectorAll('a[href]')).length === 0) continue;
      const box = section.getBoundingClientRect();
      if (!rail && (box.width < 120 || box.width > 560 || box.height > 950)) return null;
      return section;
    }
    return null;
  }

  // Facebook periodically changes the attributes used on feed cards. The direct child of
  // role=feed is a much more stable structural boundary than the obfuscated class names.
  function directFeedUnit(node) {
    if (!node?.closest) return null;
    const feed = node.closest('[role="feed"]');
    if (!feed) return null;
    let unit = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
    if (!unit) return null;
    while (unit.parentElement && unit.parentElement !== feed) unit = unit.parentElement;
    return unit.parentElement === feed ? unit : null;
  }

  // Fallback for Facebook variants which omit role=feed and FeedUnit markers. We only
  // accept a reasonably sized container when the disclosure is near its top and the
  // container looks like a real post (links/media/action controls), which keeps an exact
  // "Ad" label in normal post text from hiding unrelated content.
  function geometricDisclosureCard(marker) {
    if (!marker || marker.closest?.(BODY)) return null;
    const markerBox = marker.getBoundingClientRect?.();
    let best = null;
    for (let card = marker.parentElement, depth = 0; card && depth < 16; card = card.parentElement, depth += 1) {
      if (card.matches?.('body, html, [role="feed"]')) break;
      const box = card.getBoundingClientRect?.();
      if (!box) continue;
      const width = Number(box.width) || 0;
      const height = Number(box.height) || 0;
      const offset = markerBox && Number.isFinite(markerBox.top) && Number.isFinite(box.top) ? markerBox.top - box.top : 0;
      if (width < 280 || width > 920 || height < 120 || height > 2400 || offset < -8 || offset > 260) continue;
      const hasPostContent = Boolean(card.querySelector?.('img, video, a[href], [role="button"], [data-ad-preview="message"], [data-ad-comet-preview="message"]'));
      if (!hasPostContent) continue;
      const textLength = stripInvisible(card.innerText || card.textContent || '').trim().length;
      if (textLength < 16) continue;
      best = card;
      if (card.parentElement?.matches?.('[role="main"], [data-pagelet*="Feed"]')) break;
    }
    return best;
  }

  function disclosureCard(marker) {
    if ((!label(marker, true) && !label(marker.parentElement, true)) || marker.closest(BODY)) return null;
    const feedUnit = directFeedUnit(marker);
    if (feedUnit && feedAd(feedUnit)) return feedUnit;
    for (let card = marker.parentElement, depth = 0; card && depth < 14; card = card.parentElement, depth += 1) {
      if (card.matches('[role="feed"], [role="main"], [role="complementary"], [data-pagelet="RightRail"], body, html')) break;
      if (card.querySelector('img, video, a[href], [role="button"]') && card.getBoundingClientRect().height >= 120 && feedAd(card)) return card;
    }
    const fallback = geometricDisclosureCard(marker);
    return fallback && feedAd(fallback) ? fallback : null;
  }

  function mark(element, isAd) {
    if (!isAd) { element.removeAttribute(MARK); hidden.delete(element); return 0; }
    element.setAttribute(MARK, '');
    hidden.add(element);
    if (counted.has(element)) return 0;
    counted.add(element);
    return 1;
  }

  function scan(element) {
    if (!element.isConnected) { hidden.delete(element); return 0; }
    // Remove our hiding marker before checking rendered disclosure visibility.
    element.removeAttribute(MARK);
    if (element.matches('[role="complementary"]')) {
      let count = 0;
      for (const previous of [...hidden]) if (element.contains(previous)) mark(previous, false);
      for (const heading of Array.from(element.querySelectorAll('h2, h3, [role="heading"], [aria-label]')).slice(0, 48)) {
        const section = railAdSection(heading);
        if (section) count += mark(section, true);
      }
      return count;
    }
    return mark(element, feedAd(element));
  }

  function schedule() {
    if (scheduled || !enabled) return;
    scheduled = true;
    setTimeout(() => {
      scheduled = false;
      if (!enabled) return;
      const start = performance.now();
      let count = 0;
      let visited = 0;
      for (const element of queue) {
        queue.delete(element);
        count += scan(element);
        if (++visited >= 64 || performance.now() - start >= 8) break;
      }
      for (const element of hidden) if (!element.isConnected) hidden.delete(element);
      // The background counter accepts at most 64 removals in each message.
      for (let remaining = count; remaining > 0; remaining -= 64) {
        void API.runtime.sendMessage({ type: 'activity:record', category: 'ads', source: 'cosmetic-collapse', count: Math.min(remaining, 64) }).catch(() => undefined);
      }
      if (queue.size) schedule();
    }, 50);
  }

  function messageCard(message) {
    // Some feed layouts expose no article/pagelet marker. Find the smallest
    // surrounding post with an author heading, without selecting the whole feed.
    for (let card = message.parentElement, depth = 0; card && depth < 12; card = card.parentElement, depth += 1) {
      if (card.matches('[role="feed"], [role="main"], body')) break;
      if (card.querySelector('h2, h3, h4, [role="heading"]') &&
        card.querySelectorAll('[data-ad-preview="message"], [data-ad-comet-preview="message"]').length === 1) return card;
    }
    return null;
  }

  function enqueue(node) {
    const element = node.nodeType === Node.ELEMENT_NODE ? node : node.parentElement;
    if (!element) return;
    const card = element.closest(ROOTS) || directFeedUnit(element) || disclosureCard(element);
    const rail = element.closest('[role="complementary"]');
    if (card) queue.add(card);
    if (rail) queue.add(rail);
    const messages = '[data-ad-preview="message"], [data-ad-comet-preview="message"]';
    // Revisit a markerless post on metadata hydration, edits and virtual reuse.
    for (let parent = element, depth = 0; parent && depth < 12; parent = parent.parentElement, depth += 1) {
      if (parent.matches('[role="feed"], [role="main"], body, html')) break;
      const message = parent.matches(messages) ? parent : parent.querySelector(messages);
      if (message) { const post = messageCard(message); if (post) queue.add(post); break; }
    }
    if (!rail) {
      for (const marker of Array.from(element.querySelectorAll('a, span, [aria-label], h2, h3, h4')).slice(0, 1200)) {
        if (queue.size >= 256) break;
        if (!label(marker, true) && !label(marker.parentElement, true)) continue;
        const post = disclosureCard(marker);
        if (post) queue.add(post);
        else { const section = railAdSection(marker); if (section) queue.add(section); }
      }
      for (const item of element.querySelectorAll(`${ROOTS}, [role="complementary"], ${messages}`)) {
        if (queue.size >= 256) break;
        const post = item.matches(messages) ? messageCard(item) : item;
        if (post) queue.add(post);
      }
    }
    schedule();
  }

  function stop() {
    enabled = false;
    observer?.disconnect(); observer = null;
    queue.clear();
    for (const element of hidden) element.removeAttribute(MARK);
    hidden.clear();
    style?.remove(); style = null;
  }

  async function refresh() {
    const version = ++generation;
    try {
      const stored = await API.storage.local.get(STATE_KEY);
      const state = stored[STATE_KEY];
      const response = await API.runtime.sendMessage({ type: 'recovery:page-policy' }).catch(() => null);
      if (version !== generation) return;
      const allowed = state?.allowlist?.some((entry) => host === entry || host.endsWith(`.${entry}`));
      const active = state?.protectionEnabled !== false && state?.features?.ads !== false && !allowed && !response?.compatibility?.disabledLayers?.includes('cosmetic');
      stop();
      if (!active) return;
      enabled = true;
      style = document.createElement('style');
      style.textContent = `[${MARK}] { display: none !important; }`;
      (document.head || document.documentElement).append(style);
      observer = new MutationObserver((records) => {
        for (const record of records.slice(0, 64)) {
          enqueue(record.target);
          for (const node of Array.from(record.addedNodes).slice(0, 16)) enqueue(node);
        }
      });
      observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['aria-label', 'href', 'role', 'data-pagelet', 'aria-posinset', 'aria-describedby', 'data-ad-preview', 'data-ad-comet-preview', 'class', 'style'] });
      enqueue(document.documentElement);
    } catch { if (version === generation) stop(); }
  }

  if (TESTING) {
    globalThis.__ISHIELD_FACEBOOK_INTERNALS__ = Object.freeze({
      stripInvisible,
      normalize,
      normalizedLooksSponsored,
      accessibleLooksSponsored,
      orderedVisibleLabel,
      label,
      directFeedUnit,
      geometricDisclosureCard,
    });
    return;
  }

  if (!API?.storage?.local) return;
  API.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && [STATE_KEY, 'ishield.breakage-recovery.v1', 'ishield.update.state.v1'].some((key) => Object.hasOwn(changes, key))) void refresh();
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => { void refresh(); }, { once: true });
  else void refresh();
})();
