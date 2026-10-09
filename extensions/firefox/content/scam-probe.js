'use strict';

(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const MAX_TEXT_NODES = 512;
  const MAX_TEXT_CHARS = 32768;
  const MAX_ELEMENT_NODES = 1024;
  const MAX_FORMS = 32;
  const MAX_INPUTS = 64;
  const MAX_LINKS = 128;
  const MAX_DIALOG_CANDIDATES = 64;
  const MAX_HITS = 8;
  let completed = false;

  const PHRASES = Object.freeze({
    techSupportHits: Object.freeze([
      'technical support', 'call support now', 'support agent', 'your computer has a problem',
      'do not shut down your computer', 'call microsoft support', 'call apple support', 'computer support hotline',
    ]),
    investmentHits: Object.freeze([
      'guaranteed returns', 'guaranteed profit', 'risk free investment', 'risk-free investment',
      'double your money', 'investment opportunity', 'high return investment', 'profit is guaranteed',
    ]),
    cryptoHits: Object.freeze([
      'send bitcoin', 'send crypto', 'crypto investment', 'double your bitcoin', 'wallet recovery',
      'seed phrase verification', 'connect your wallet to claim', 'guaranteed crypto returns',
    ]),
    giveawayHits: Object.freeze([
      'you have won', 'claim your prize', 'congratulations winner', 'selected as a winner',
      'claim your reward', 'free giveaway', 'prize waiting for you', 'pay a fee to claim',
    ]),
    shoppingHits: Object.freeze([
      'warehouse clearance', 'today only discount', '90% off today', 'final clearance sale',
      'unclaimed package', 'mystery box offer', 'clearance ends today', 'huge discount today only',
    ]),
    supportHits: Object.freeze([
      'contact support immediately', 'customer support number', 'account support team', 'refund support center',
      'billing support department', 'fraud support team', 'support verification required', 'call the support desk',
    ]),
    impersonationHits: Object.freeze([
      'official security department', 'bank security team', 'fraud department notice', 'government agency notice',
      'tax department notice', 'law enforcement notice', 'official support department', 'account security department',
    ]),
    downloadHits: Object.freeze([
      'download now to continue', 'required security update', 'install this update', 'download security software',
      'codec required to continue', 'browser update required', 'install the required update', 'download protection tool',
    ]),
    paymentHits: Object.freeze([
      'pay now to avoid', 'payment required immediately', 'pay a fee to claim', 'send payment now',
      'processing fee required', 'release fee required', 'verification payment required', 'pay the outstanding fee',
    ]),
    subscriptionHits: Object.freeze([
      'subscription expired', 'renew now to avoid', 'automatic renewal notice', 'membership renewal',
      'subscription will renew', 'cancel subscription call', 'renewal charge pending', 'subscription cancellation number',
    ]),
    alertHits: Object.freeze([
      'security alert', 'browser locked', 'do not close this window', 'warning your computer',
      'system warning', 'critical security warning', 'your browser has been blocked', 'immediate action required to unlock',
    ]),
    antivirusHits: Object.freeze([
      'virus detected', 'trojan detected', 'malware found', 'your device is infected',
      'antivirus expired', 'multiple viruses detected', 'spyware detected', 'infection detected on your computer',
    ]),
    urgencyHits: Object.freeze([
      'act now', 'immediately', 'urgent action required', 'within 24 hours', 'limited time',
      'do not close', 'expires today', 'final warning',
    ]),
    remoteAccessHits: Object.freeze([
      'anydesk', 'teamviewer', 'ultraviewer', 'remote access software', 'remote desktop support',
      'screen sharing app', 'remote support tool', 'give remote access',
    ]),
    irreversiblePaymentHits: Object.freeze([
      'gift card', 'bitcoin payment', 'crypto payment', 'wire transfer', 'western union',
      'moneygram', 'prepaid card payment', 'pay with cryptocurrency',
    ]),
    informationalHits: Object.freeze([
      'how to spot a scam', 'how to avoid scams', 'scam awareness', 'fraud prevention',
      'report a scam', 'examples of scams', 'security research', 'threat research',
    ]),
  });

  function send(page) {
    try {
      const maybePromise = api.runtime.sendMessage({ type: 'scam:probe', page });
      if (maybePromise?.catch) maybePromise.catch(() => undefined);
    } catch {
      // Fail open if extension context disappears during navigation.
    }
  }

  function boundedText() {
    const body = document.body;
    if (!body || typeof document.createTreeWalker !== 'function') return '';
    let total = 0;
    let nodes = 0;
    const chunks = [];
    const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node && nodes < MAX_TEXT_NODES && total < MAX_TEXT_CHARS; node = walker.nextNode()) {
      nodes += 1;
      const parent = node.parentElement;
      if (parent && /^(SCRIPT|STYLE|NOSCRIPT|TEMPLATE)$/u.test(parent.tagName)) continue;
      const raw = typeof node.nodeValue === 'string' ? node.nodeValue : '';
      if (!raw) continue;
      const remaining = MAX_TEXT_CHARS - total;
      const slice = raw.slice(0, remaining);
      total += slice.length;
      chunks.push(slice.toLowerCase());
    }
    return chunks.join(' ');
  }

  function phraseHits(text, phrases) {
    let hits = 0;
    for (const phrase of phrases) {
      if (text.includes(phrase)) hits = Math.min(MAX_HITS, hits + 1);
      if (hits >= MAX_HITS) break;
    }
    return hits;
  }

  function paymentLikeInput(input) {
    const type = String(input.getAttribute('type') || 'text').toLowerCase();
    const autocomplete = String(input.getAttribute('autocomplete') || '').toLowerCase();
    const name = String(input.getAttribute('name') || '').toLowerCase().slice(0, 64);
    return type === 'number'
      || autocomplete.startsWith('cc-')
      || autocomplete.includes('transaction-')
      || /(?:card|credit|debit|cvv|cvc|payment|billing)/u.test(name);
  }

  function structuralSignals() {
    let paymentFields = 0;
    let externalPaymentForms = 0;
    let phoneLinks = 0;
    let downloadLinks = 0;
    let dialogOverlays = 0;
    let redirectCount = 0;
    try {
      const navigation = performance.getEntriesByType('navigation')[0];
      if (Number.isFinite(navigation?.redirectCount)) redirectCount = Math.min(8, Math.max(0, Math.trunc(navigation.redirectCount)));
    } catch {
      redirectCount = 0;
    }

    const body = document.body;
    if (!body || typeof document.createTreeWalker !== 'function') {
      return { paymentFields, externalPaymentForms, phoneLinks, downloadLinks, dialogOverlays, redirectCount };
    }

    let elementNodes = 0;
    let inputsSeen = 0;
    let formsSeen = 0;
    let linksSeen = 0;
    let dialogsSeen = 0;
    const paymentForms = new WeakSet();
    const walker = document.createTreeWalker(body, NodeFilter.SHOW_ELEMENT);
    for (let element = walker.nextNode(); element && elementNodes < MAX_ELEMENT_NODES; element = walker.nextNode()) {
      elementNodes += 1;
      const tag = element.tagName;

      if (tag === 'INPUT' && inputsSeen < MAX_INPUTS) {
        inputsSeen += 1;
        if (paymentLikeInput(element)) {
          paymentFields = Math.min(16, paymentFields + 1);
          const form = element.form;
          if (form && formsSeen < MAX_FORMS && !paymentForms.has(form)) {
            paymentForms.add(form);
            formsSeen += 1;
            const rawAction = form.getAttribute('action');
            if (rawAction) {
              let action;
              try { action = new URL(rawAction, location.href); } catch { action = null; }
              if (action && (action.protocol === 'http:' || action.protocol === 'https:') && action.origin !== location.origin) {
                externalPaymentForms = Math.min(8, externalPaymentForms + 1);
              }
            }
          }
        }
      }

      if (tag === 'A' && linksSeen < MAX_LINKS) {
        linksSeen += 1;
        const rawHref = String(element.getAttribute('href') || '').slice(0, 2048);
        if (rawHref.toLowerCase().startsWith('tel:')) phoneLinks = Math.min(16, phoneLinks + 1);
        if (element.hasAttribute('download') || /\.(?:exe|msi|dmg|pkg|apk|scr)(?:[?#]|$)/iu.test(rawHref)) {
          downloadLinks = Math.min(32, downloadLinks + 1);
        }
      }

      if (dialogsSeen < MAX_DIALOG_CANDIDATES) {
        const role = String(element.getAttribute('role') || '').toLowerCase();
        const ariaModal = String(element.getAttribute('aria-modal') || '').toLowerCase();
        const isDialog = role === 'alertdialog' || role === 'dialog' || ariaModal === 'true' || (tag === 'DIALOG' && element.hasAttribute('open'));
        if (isDialog) {
          dialogsSeen += 1;
          dialogOverlays = Math.min(8, dialogOverlays + 1);
        }
      }

      if (inputsSeen >= MAX_INPUTS && formsSeen >= MAX_FORMS && linksSeen >= MAX_LINKS && dialogsSeen >= MAX_DIALOG_CANDIDATES) break;
    }

    return { paymentFields, externalPaymentForms, phoneLinks, downloadLinks, dialogOverlays, redirectCount };
  }

  function boundedSignals() {
    const text = boundedText();
    const page = structuralSignals();
    for (const [field, phrases] of Object.entries(PHRASES)) page[field] = phraseHits(text, phrases);
    return page;
  }

  // Immediate URL/reputation/domain-only pass. No page-derived text signal is sent here.
  send({
    techSupportHits: 0, investmentHits: 0, cryptoHits: 0, giveawayHits: 0, shoppingHits: 0,
    supportHits: 0, impersonationHits: 0, downloadHits: 0, paymentHits: 0, subscriptionHits: 0,
    alertHits: 0, antivirusHits: 0, urgencyHits: 0, remoteAccessHits: 0, irreversiblePaymentHits: 0, informationalHits: 0,
    paymentFields: 0, externalPaymentForms: 0, phoneLinks: 0, downloadLinks: 0, dialogOverlays: 0, redirectCount: 0,
  });

  function complete() {
    if (completed) return;
    completed = true;
    send(boundedSignals());
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', complete, { once: true });
  else complete();
})();
