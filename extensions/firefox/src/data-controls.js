export function websiteExclusions(state, recovery, now = Date.now()) {
  const rows = new Map();
  for (const host of state.allowlist ?? []) rows.set(host,{host,allowed:true,recovery:false});
  for (const site of recovery.sites ?? []) {
    if (!(site.expiresAtMs > now) || !site.source) continue;
    const row=rows.get(site.host)??{host:site.host,allowed:false,recovery:false};
    row.recovery=true;row.source=site.source;rows.set(site.host,row);
  }
  return [...rows.values()].sort((a,b)=>a.host.localeCompare(b.host));
}
export async function clearLocalExtensionData(api) {
  await api.alarms.clearAll();
  await api.storage.local.clear();
  await api.storage.session?.clear();
}
