// Share Chrome's matched-rule query budget between popup and background refreshes.
export const MATCH_QUERY_KEY = 'ishield.activity.last-query.v1';
export const MATCH_QUERY_INTERVAL_MS = 31_000;
export function createMatchQuery(dnr, storage, now = Date.now) {
  let tail = Promise.resolve(); let last = null;
  return filter => {
    const result = tail.then(async () => {
      const saved = storage ? (await storage.get(MATCH_QUERY_KEY))[MATCH_QUERY_KEY] : last;
      const time = now();
      if (Number.isFinite(saved) && time - saved < MATCH_QUERY_INTERVAL_MS) throw new Error('MatchQueryDeferred');
      last = time;
      if (storage) await storage.set({[MATCH_QUERY_KEY]:time});
      return dnr.getMatchedRules(filter);
    });
    tail = result.catch(() => undefined); return result;
  };
}
