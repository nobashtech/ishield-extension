'use strict';
import {createEngine, contentPayload} from './vendor/adguard-engine.js';
const enabledLayers=state=>state?.protectionEnabled===false?[]:['ads','privacy'].filter(layer=>state?.features?.[layer]!==false && state?.lists?.[layer==='ads'?'base':'tracking']!==false);
const matchesHost=(host,entries=[])=>entries.some(entry=>host===entry||host.endsWith(`.${entry}`));
export function createAdguardContentManager(loadText) {
  let configured=null;
  let current=null;
  let revision=0;
  async function configure(state) {
    const layers=enabledLayers(state);
    const key=layers.join(',');
    if(key===configured) return current;
    configured=key;const version=++revision;
    const task=layers.length ? Promise.all(layers.map(async id=>({id,content:await loadText(`rules/adguard/${id}.txt`)}))).then(createEngine) : Promise.resolve(null);
    current=task;
    try {return await task;} catch(error) {if(version===revision) {configured=null;current=null;}throw error;}
  }
  async function serve(message,sender,state,recoveryDisabled=false) {
    if(message?.type!=='content:adguard') throw TypeError('unsupported content request');
    if(!Number.isInteger(sender?.tab?.id)||!Number.isInteger(sender?.frameId)||!/^https?:\/\//u.test(sender.url??'')) throw TypeError('page content sender required');
    const topHost=new URL(sender.tab.url||sender.url).hostname;
    const host=new URL(sender.url).hostname;
    if(!state.protectionEnabled || recoveryDisabled || matchesHost(topHost,state.allowlist)||matchesHost(host,state.allowlist)) return {active:false};
    const engine=await configure(state);
    if(!engine) return {active:false};
    return {active:true,...contentPayload(engine,sender.url)};
  }
  return {configure,serve};
}
export function adguardRegistrations(state, excludeMatches=[]) {
  if(!state || state.protectionEnabled===false) return [];
  const base={allFrames:true,persistAcrossSessions:true,matches:['http://*/*','https://*/*'],runAt:'document_start',...(excludeMatches.length?{excludeMatches:[...new Set(excludeMatches)]}:{})};
  const layers=enabledLayers(state);
  if(!layers.length) return [];
  const name=layers.length===2?'all':layers[0];
  const mainScripts=name==='privacy'
    ? ['content/adguard-privacy-main.js']
    : [`content/adguard-${name}-filter-data.js`,`content/adguard-${name}-main.js`];
  return [
    {...base,id:'ishield_pc_adguard_content',js:['content/cosmetic-activity.js','content/adguard-content.js']},
    {...base,id:'ishield_pc_adguard_main',world:'MAIN',js:mainScripts},
  ];
}
