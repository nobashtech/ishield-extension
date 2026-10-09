// Count actual elements hidden by the installed cosmetic rules. This adapter is
// shared by both filtering engines; it never decides which selectors to block.
(() => {
  const API = globalThis.browser ?? globalThis.chrome;
  if (!API?.runtime || globalThis.__ishieldCosmeticActivity) return;
  const counted = globalThis.__ishieldCosmeticCounted ??= new WeakSet();
  const sources = new Map();
  const collapsed = new Set();
  const mark = 'data-ishield-empty-ad-container';
  let pending = 0, reportTimer, scanTimer, jobs = [], observer, cachedGroups;
  const registeredCss = new Set();
  const slot = /(?:^|[\s_-])(?:adslot|ad-slot|ad-wrapper|dfp-ad-unit|advertisement)(?:$|[\s_-])/iu;
  const stop = /^(?:HTML|BODY|MAIN|ARTICLE|HEADER|NAV|FOOTER|FORM)$/u;
  const style = document.createElement('style');
  style.textContent = `[${mark}]{display:none!important}`;

  function report(element) {
    if (!element?.isConnected || counted.has(element) || /^(?:HTML|BODY|HEAD|STYLE|SCRIPT)$/u.test(element.tagName)) return;
    // A matching rule can also set unrelated styles. Only hiding is counted.
    if (element.hasAttribute(mark) || getComputedStyle(element).display !== 'none') return;
    counted.add(element);
    pending++;
    if (!reportTimer) reportTimer = setTimeout(flush, 50);
    let child = element;
    for (let depth = 0; depth < 2; depth++) {
      const parent = child.parentElement;
      if (!parent || stop.test(parent.tagName) || collapsed.size >= 512) break;
      const recognized = slot.test(`${parent.id} ${parent.className}`) || parent.matches('[data-ad-slot],[data-google-query-id],[id^="div-gpt-ad"]');
      // Collapse only a recognized wrapper whose sole content is a hidden ad.
      if (!recognized || parent.children.length !== 1 || [...parent.childNodes].some(node => node.nodeType === 3 && node.textContent.trim())) break;
      parent.setAttribute(mark, '');
      collapsed.add(parent);
      child = parent;
    }
  }
  function flush() {
    reportTimer = undefined;
    while (pending) {
      const count = Math.min(pending, 64);
      pending -= count;
      void API.runtime.sendMessage({type: 'activity:record', category: 'ads', source: 'cosmetic-collapse', count}).catch(() => undefined);
    }
  }
  function groups() {
    if (cachedGroups) return cachedGroups;
    const selectors = [...new Set([...sources.values()].flat())];
    const result = [];
    for (let i = 0; i < selectors.length; i += 64) result.push(selectors.slice(i, i + 64).join(','));
    return cachedGroups = result;
  }
  function enqueue(root = document) {
    if (!sources.size || !root.querySelectorAll || !groups().length) return;
    // Coalesce bursts without retaining a growing list of detached DOM nodes.
    if (jobs.length > 128) jobs = [{root: document, groups: groups(), index: 0}];
    else jobs.push({root, groups: groups(), index: 0});
    if (!scanTimer) scanTimer = setTimeout(scan, 30);
  }
  function scan() {
    scanTimer = undefined;
    const deadline = performance.now() + 8;
    while (jobs.length && performance.now() < deadline) {
      const job = jobs[0];
      if (job.root !== document && !job.root.isConnected) { jobs.shift(); continue; }
      const selector = job.groups[job.index++];
      try {
        if (job.root.matches?.(selector)) report(job.root);
        for (const element of job.root.querySelectorAll(selector)) report(element);
      } catch { /* Invalid selectors belong to the filter parser, not this log. */ }
      if (job.index >= job.groups.length) jobs.shift();
    }
    if (jobs.length) scanTimer = setTimeout(scan, 16);
  }
  function observe() {
    if (observer) return;
    (document.head ?? document.documentElement).append(style);
    observer = new MutationObserver(records => {
      const roots = new Set();
      for (const record of records) {
        if (record.type === 'attributes') roots.add(record.target);
        else for (const node of record.addedNodes) if (node.nodeType === 1 && node !== style) roots.add(node);
      }
      for (const root of roots) enqueue(root);
    });
    observer.observe(document, {subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'id', 'style']});
  }
  function setSelectors(owner, selectors) {
    sources.set(owner, selectors);
    cachedGroups = undefined;
    if (selectors.length) { observe(); enqueue(); }
  }
  function setCss(owner, css) {
    try {
      const sheet = new CSSStyleSheet(); sheet.replaceSync(css);
      setSelectors(owner, [...sheet.cssRules].filter(rule => rule.selectorText && rule.style?.display === 'none').map(rule => rule.selectorText));
    } catch { /* Unsupported CSS is still handled by the filtering engine. */ }
  }
  function clear(owner) {
    sources.delete(owner);
    cachedGroups = undefined;
    jobs = [];
    for (const element of collapsed) element.removeAttribute(mark);
    collapsed.clear();
    if (!sources.size) { observer?.disconnect(); observer = undefined; style.remove(); }
  }
  let cssSerial = 0;
  globalThis.__ishieldCosmeticActivity = {setSelectors, setCss, clear, report, registerCss(css) {if (!registeredCss.has(css)) {registeredCss.add(css);setCss(`css-${++cssSerial}`, css);} enqueue();}};
})();
