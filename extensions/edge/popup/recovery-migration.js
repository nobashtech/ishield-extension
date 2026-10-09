// Restore the Facebook filtering explicitly requested after the removed recovery action.
const MARKER = 'ishield.popup.facebook-recovery-restored.v1';
const RECOVERY_KEY = 'ishield.breakage-recovery.v1';
export async function restoreLegacyFacebookRecovery(storage, send) {
  const saved = await storage.get([MARKER, RECOVERY_KEY]);
  if (saved[MARKER] === true) return [];
  const sites = saved[RECOVERY_KEY]?.sites ?? [];
  const hosts = [...new Set(sites.filter(site => site.source === 'manual' && typeof site.host === 'string' && (site.host === 'facebook.com' || site.host.endsWith('.facebook.com'))).map(site => site.host))];
  for (const host of hosts) await send({type:'recovery:clear', host});
  await storage.set({[MARKER]:true});
  return hosts;
}
