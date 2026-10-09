// AdGuard TSUrlFilter owns rule parsing, domain/path matching and exceptions.
// iShield supplies bundled lists and the protection-layer/site policy.
import { Engine, Request, RequestType } from '@adguard/tsurlfilter';
export function cosmeticResult(engine, url) {
  const request = new Request(url, url, RequestType.Document);
  const options = engine.matchRequest(request).getCosmeticOption();
  return engine.getCosmeticResult(request, options);
}
export async function createEngine(filters) {
  return Engine.createAsync({ filters: filters.map(({id, content}, index) => ({id:index+1, content})) });
}
export function contentPayload(engine, url) {
  const result = cosmeticResult(engine, url);
  const nativeSelectors = [...result.elementHiding.generic, ...result.elementHiding.specific].map(rule => rule.getContent());
  const extendedSelectors = [...result.elementHiding.genericExtCss, ...result.elementHiding.specificExtCss].map(rule => rule.getContent());
  const css = [...result.CSS.generic, ...result.CSS.specific].map(rule => rule.getContent());
  const extendedCss = [...result.CSS.genericExtCss, ...result.CSS.specificExtCss].map(rule => rule.getContent());
  return {nativeSelectors, css, extendedRules:[...extendedSelectors.map(selector=>`${selector} { display: none !important; }`), ...extendedCss]};
}
