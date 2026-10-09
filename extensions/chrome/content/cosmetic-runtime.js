'use strict';

(() => {
  const API = globalThis.browser ?? globalThis.chrome;
  const DATA = globalThis.__ISHIELD_COSMETIC_RULES__;
  const STATE_KEY = 'ishield.state.v1';
  const RECOVERY_STATE_KEY = 'ishield.breakage-recovery.v1';
  const UPDATE_STATE_KEY = 'ishield.update.state.v1';
  const COLLAPSE_CLASS = 'ishield-cosmetic-collapse-v1';
  const STYLE_ATTRIBUTE = 'data-ishield-cosmetic-style';
  const MODES = new Set(['balanced', 'strong', 'maximum']);
  const LIMITS = Object.freeze({
    maxSelectors: 4096,
    maxCssBytes: 64 * 1024,
    maxMutationRecordsPerCallback: 64,
    maxQueuedNodes: 256,
    maxFlushNodes: 128,
    maxFlushMs: 8,
    maxCollapsedElements: 768,
    maxCollapseAncestors: 4,
  });

  let activeStyle = null;
  let observer = null;
  let collapseSelector = '';
  let queueScheduled = false;
  let activityFlushScheduled = false;
  let pendingCollapsedCount = 0;
  const mutationQueue = [];
  const collapsedElements = new Set();

  function normalizeHost(value) {
    if (typeof value !== 'string') return null;
    const host = value.trim().toLowerCase().replace(/\.+$/u, '');
    if (!host || /[\s/\\]/u.test(host)) return null;
    return host;
  }

  function hostMatches(host, domain) {
    return host === domain || host.endsWith(`.${domain}`);
  }

  function hostSuffixes(host) {
    const out = [];
    let current = host;
    while (current) {
      out.push(current);
      const dot = current.indexOf('.');
      if (dot < 0) break;
      current = current.slice(dot + 1);
    }
    return out;
  }

  function normalizeState(candidate) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      return { protectionEnabled: true, mode: 'strong', allowlist: [], adsEnabled: true };
    }
    const allowlist = Array.isArray(candidate.allowlist)
      ? candidate.allowlist.map(normalizeHost).filter(Boolean).slice(0, 1000)
      : [];
    return {
      protectionEnabled: candidate.protectionEnabled !== false,
      mode: MODES.has(candidate.mode) ? candidate.mode : 'strong',
      allowlist: [...new Set(allowlist)],
      adsEnabled: candidate.features?.ads !== false,
    };
  }

  function activeTierNames(mode) {
    if (mode === 'balanced') return ['core'];
    if (mode === 'maximum') return ['core', 'strong', 'maximum'];
    return ['core', 'strong'];
  }

  function recordApplies(record, host) {
    const excludes = Array.isArray(record?.[2]) ? record[2] : [];
    return !excludes.some((excluded) => hostMatches(host, excluded));
  }

  function collectTierRecords(tier, host) {
    const records = [];
    if (!tier || typeof tier !== 'object') return records;
    if (Array.isArray(tier.generic)) records.push(...tier.generic);
    if (Array.isArray(tier.negativeOnly)) records.push(...tier.negativeOnly);
    const buckets = tier.domainBuckets ?? {};
    for (const suffix of hostSuffixes(host)) {
      const bucket = buckets[suffix];
      if (Array.isArray(bucket)) records.push(...bucket);
      if (records.length > LIMITS.maxSelectors * 2) break;
    }
    return records;
  }

  function resolveSelectors(data, host, mode) {
    const hide = new Set();
    const unhide = new Set();
    const tiers = data?.tiers ?? {};
    let considered = 0;
    for (const tierName of activeTierNames(mode)) {
      for (const record of collectTierRecords(tiers[tierName], host)) {
        considered += 1;
        if (considered > LIMITS.maxSelectors * 2) break;
        if (!Array.isArray(record) || (record[0] !== 0 && record[0] !== 1)) continue;
        const selector = record[1];
        if (typeof selector !== 'string' || selector.length === 0 || selector.length > 1024) continue;
        if (!recordApplies(record, host)) continue;
        (record[0] === 1 ? hide : unhide).add(selector);
      }
    }
    for (const selector of unhide) hide.delete(selector);
    return {
      hide: [...hide].slice(0, LIMITS.maxSelectors),
      unhide: [...unhide].slice(0, LIMITS.maxSelectors),
    };
  }

  function isAllowlisted(host, allowlist) {
    return allowlist.some((allowed) => hostMatches(host, allowed));
  }

  function selectorParses(selector, doc = document) {
    if (typeof selector !== 'string' || selector.length === 0 || selector.length > 1024) return false;
    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(selector)) return false;
    try {
      const fragment = doc.createDocumentFragment();
      fragment.querySelector(selector);
      return true;
    } catch {
      return false;
    }
  }

  function removeStyle() {
    if (activeStyle?.isConnected) activeStyle.remove();
    activeStyle = null;
  }

  function restoreCollapsed() {
    for (const element of collapsedElements) {
      if (element?.classList) element.classList.remove(COLLAPSE_CLASS);
    }
    collapsedElements.clear();
  }

  function stopObserver() {
    observer?.disconnect();
    observer = null;
    mutationQueue.length = 0;
    queueScheduled = false;
    collapseSelector = '';
  }

  function deactivate() {
    stopObserver();
    restoreCollapsed();
    removeStyle();
  }

  function scheduleActivityReport(count = 1) {
    if (!Number.isInteger(count) || count < 1 || !API?.runtime?.sendMessage) return;
    pendingCollapsedCount = Math.min(64, pendingCollapsedCount + count);
    if (activityFlushScheduled) return;
    activityFlushScheduled = true;
    const schedule = typeof globalThis.queueMicrotask === 'function'
      ? globalThis.queueMicrotask
      : (callback) => globalThis.setTimeout(callback, 0);
    schedule(() => {
      activityFlushScheduled = false;
      const pending = pendingCollapsedCount;
      pendingCollapsedCount = 0;
      if (!pending) return;
      void API.runtime.sendMessage({
        type: 'activity:record',
        category: 'ads',
        source: 'cosmetic-collapse',
        count: pending,
      }).catch(() => undefined);
    });
  }

  function installStyle(selectors, doc = document) {
    removeStyle();
    const root = doc.documentElement;
    if (!root) return { installed: 0, rejected: selectors.length };
    const style = doc.createElement('style');
    style.setAttribute(STYLE_ATTRIBUTE, 'v1');
    root.appendChild(style);
    const sheet = style.sheet;
    if (!sheet) {
      style.remove();
      return { installed: 0, rejected: selectors.length };
    }

    let installed = 0;
    let rejected = 0;
    let cssBytes = 0;
    try {
      sheet.insertRule(`.${COLLAPSE_CLASS}{display:none!important}`, sheet.cssRules.length);
    } catch {
      style.remove();
      return { installed: 0, rejected: selectors.length };
    }

    for (const selector of selectors) {
      if (installed >= LIMITS.maxSelectors) break;
      if (!selectorParses(selector, doc)) {
        rejected += 1;
        continue;
      }
      const rule = `${selector}{display:none!important}`;
      cssBytes += rule.length;
      if (cssBytes > LIMITS.maxCssBytes) break;
      try {
        sheet.insertRule(rule, sheet.cssRules.length);
        installed += 1;
      } catch {
        rejected += 1;
      }
    }
    activeStyle = style;
    return { installed, rejected };
  }

  function placeholderTextOnly(element) {
    const text = String(element?.textContent ?? '').replace(/\s+/gu, ' ').trim().toLowerCase();
    if (!text) return true;
    return /^(?:ad|ads|advertisement|advertisements|sponsored|sponsored links?|বিজ্ঞাপন|স্পনসরড|স্পন্সরড)[\s:.-]*$/iu.test(text);
  }

  function parentContainsOnlyAdSeeds(parent) {
    const children = Array.from(parent?.children ?? []);
    if (!children.length) return false;
    return children.every((child) => {
      if (collapsedElements.has(child) || child.classList?.contains(COLLAPSE_CLASS)) return true;
      try { return Boolean(collapseSelector && child.matches?.(collapseSelector)); } catch { return false; }
    });
  }

  function safeCollapseParent(seed) {
    let current = seed;
    for (let depth = 0; depth < LIMITS.maxCollapseAncestors; depth += 1) {
      const parent = current?.parentElement;
      if (!parent) return;
      const tag = parent.tagName?.toLowerCase();
      if (!tag || ['html', 'body', 'main', 'article', 'header', 'footer', 'nav', 'form'].includes(tag)) return;
      const structurallySafe = parent.childElementCount === 1 || parentContainsOnlyAdSeeds(parent);
      if (!structurallySafe || !placeholderTextOnly(parent)) return;
      if (collapsedElements.size >= LIMITS.maxCollapsedElements) return;
      const isNewCollapse = !collapsedElements.has(parent);
      parent.classList.add(COLLAPSE_CLASS);
      collapsedElements.add(parent);
      if (isNewCollapse) scheduleActivityReport(1);
      current = parent;
    }
  }

  function processCollapseRoot(root) {
    if (!collapseSelector || !root || root.nodeType !== 1) return;
    try {
      if (root.matches?.(collapseSelector)) safeCollapseParent(root);
      for (const seed of root.querySelectorAll?.(collapseSelector) ?? []) {
        safeCollapseParent(seed);
        if (collapsedElements.size >= LIMITS.maxCollapsedElements) break;
      }
    } catch {
      // Invalid/unsupported selector combinations fail open for cosmetic filtering.
    }
  }

  function scheduleQueueFlush() {
    if (queueScheduled) return;
    queueScheduled = true;
    const schedule = typeof globalThis.requestIdleCallback === 'function'
      ? (callback) => globalThis.requestIdleCallback(callback, { timeout: 50 })
      : (callback) => globalThis.setTimeout(callback, 0);
    schedule(flushMutationQueue);
  }

  function flushMutationQueue() {
    queueScheduled = false;
    const start = globalThis.performance?.now?.() ?? Date.now();
    let processed = 0;
    while (mutationQueue.length && processed < LIMITS.maxFlushNodes) {
      const node = mutationQueue.shift();
      processCollapseRoot(node);
      processed += 1;
      const now = globalThis.performance?.now?.() ?? Date.now();
      if (now - start >= LIMITS.maxFlushMs) break;
    }
    if (mutationQueue.length) scheduleQueueFlush();
  }

  function startObserver(seeds, doc = document) {
    stopObserver();
    const validSeeds = seeds.filter((selector) => selectorParses(selector, doc)).slice(0, 64);
    if (!validSeeds.length || !doc.documentElement || typeof MutationObserver !== 'function') return;
    collapseSelector = validSeeds.join(',');
    processCollapseRoot(doc.documentElement);
    observer = new MutationObserver((records) => {
      const boundedRecords = records.slice(0, LIMITS.maxMutationRecordsPerCallback);
      for (const record of boundedRecords) {
        for (const node of record.addedNodes ?? []) {
          if (node?.nodeType !== 1) continue;
          if (mutationQueue.length >= LIMITS.maxQueuedNodes) break;
          mutationQueue.push(node);
        }
        if (mutationQueue.length >= LIMITS.maxQueuedNodes) break;
      }
      if (mutationQueue.length) scheduleQueueFlush();
    });
    observer.observe(doc.documentElement, { childList: true, subtree: true });
  }

  async function readState() {
    const stored = await API.storage.local.get(STATE_KEY);
    return normalizeState(stored?.[STATE_KEY]);
  }

  async function readPagePolicy() {
    try {
      const response = await API.runtime.sendMessage({ type: 'recovery:page-policy' });
      return response?.compatibility ?? null;
    } catch { return null; }
  }

  async function applyState(candidate, pagePolicy = null) {
    const host = normalizeHost(globalThis.location?.hostname ?? '');
    const state = normalizeState(candidate);
    if (!host || !DATA || state.protectionEnabled === false || state.adsEnabled === false || isAllowlisted(host, state.allowlist) || pagePolicy?.disabledLayers?.includes?.('cosmetic')) {
      deactivate();
      return { active: false, installedSelectors: 0, rejectedSelectors: 0 };
    }

    const resolved = resolveSelectors(DATA, host, state.mode);
    const result = installStyle(resolved.hide);
    const hideSet = new Set(resolved.hide);
    const seeds = Array.isArray(DATA.collapseSeeds)
      ? DATA.collapseSeeds.filter((seed) => hideSet.has(seed))
      : [];
    startObserver(seeds);
    return { active: true, installedSelectors: result.installed, rejectedSelectors: result.rejected };
  }

  async function bootstrap() {
    if (!API?.storage?.local || !API?.storage?.onChanged || !DATA) return;
    try {
      await applyState(await readState(), await readPagePolicy());
    } catch {
      deactivate();
    }
    API.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== 'local') return;
      if (!changes?.[STATE_KEY] && !changes?.[RECOVERY_STATE_KEY] && !changes?.[UPDATE_STATE_KEY]) return;
      void (async () => applyState(changes?.[STATE_KEY]?.newValue ?? await readState(), await readPagePolicy()))().catch(deactivate);
    });
  }

  void bootstrap();
})();
