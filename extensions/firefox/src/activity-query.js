'use strict';
const TYPES = new Set(['all', 'ads', 'trackers', 'scams', 'threats', 'phishing', 'malware', 'privacy', 'strictPolicy']);
export function activityPage(events, {page = 0, size = 6, category = 'all', search = ''} = {}) {
  const selected = TYPES.has(category) ? category : 'all';
  const term = typeof search === 'string' ? search.trim().toLowerCase().slice(0, 100) : '';
  const limit = Number.isInteger(size) ? Math.max(1, Math.min(64, size)) : 6;
  const filtered = events.filter(event => (selected === 'all' || event.category === selected || (selected === 'threats' && ['phishing', 'malware'].includes(event.category))) && `${event.category} ${event.source}`.replaceAll('-', ' ').toLowerCase().includes(term));
  const pages = Math.max(1, Math.ceil(filtered.length / limit));
  const index = Math.max(0, Math.min(pages - 1, Number.isInteger(page) ? page : 0));
  return {items: filtered.slice(index * limit, (index + 1) * limit), pagination: {page: index, pages, total: filtered.length, size: limit}};
}
