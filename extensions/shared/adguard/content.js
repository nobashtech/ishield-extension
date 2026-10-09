// Bundled AdGuard ExtendedCss handles procedural selectors and DOM changes.
import {ExtendedCss} from '@adguard/extended-css';
const API=globalThis.browser??globalThis.chrome;
if(API?.runtime && !globalThis.__ishieldAdguardContent) {
 globalThis.__ishieldAdguardContent=true;
 let generation=0, sheet=null, extended=null;
 function clear() { globalThis.__ishieldCosmeticActivity?.clear('adguard'); globalThis.__ishieldCosmeticActivity?.clear('adguard-css'); sheet?.remove(); sheet=null;extended?.dispose();extended=null; }
 async function refresh() {
  const version=++generation;
  try {
   const payload=await API.runtime.sendMessage({type:'content:adguard'});
   if(version!==generation) return;
   clear();
   if(!payload?.active) return;
   const selectors=payload.nativeSelectors??[];
   const css=[...selectors.map(selector=>`${selector} {display:none!important;}`),...(payload.css??[])].join('\n');
   if(css) {sheet=document.createElement('style');sheet.dataset.ishieldAdguard='';sheet.textContent=css;(document.head??document.documentElement).append(sheet);}
   globalThis.__ishieldCosmeticActivity?.setSelectors('adguard',selectors);
   globalThis.__ishieldCosmeticActivity?.setCss('adguard-css',(payload.css??[]).join('\n'));
   if(payload.extendedRules?.length) {extended=new ExtendedCss({cssRules:payload.extendedRules,beforeStyleApplied:affected=>{setTimeout(()=>globalThis.__ishieldCosmeticActivity?.report(affected.node),0);return affected;}});extended.apply();}
  } catch {if(version===generation) clear();}
 }
 API.storage.onChanged.addListener((changes,area)=>{if(area==='local'&&['ishield.state.v1','ishield.breakage-recovery.v1','ishield.update.state.v1'].some(key=>Object.hasOwn(changes,key)))void refresh();});
 void refresh();
}
