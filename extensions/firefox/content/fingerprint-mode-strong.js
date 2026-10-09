'use strict';
(() => {
  const MODE = 'strong';
  const MARK = Symbol.for('ishield.fingerprint.v1');
  if (globalThis[MARK]) return;
  try { Object.defineProperty(globalThis, MARK, { value: MODE, configurable: false, enumerable: false, writable: false }); } catch { globalThis[MARK] = MODE; }

  const CAPS = Object.freeze({
    balanced: Object.freeze({ hardware: true, webgl: false, canvas: false, audio: false, uaHighEntropy: false }),
    strong: Object.freeze({ hardware: true, webgl: true, canvas: false, audio: false, uaHighEntropy: false }),
    maximum: Object.freeze({ hardware: true, webgl: true, canvas: true, audio: true, uaHighEntropy: true }),
  });
  const caps = CAPS[MODE] || CAPS.strong;
  const MAX_CANVAS_PIXELS = 262144;
  const AUDIO_NOISE_EPSILON = 0.0000001;
  const seedBytes = new Uint32Array(4);
  try { globalThis.crypto?.getRandomValues(seedBytes); } catch { seedBytes.set([0x49736869,0x656c6450,0x72697661,0x63793239]); }
  const documentSeed = (seedBytes[0] ^ seedBytes[1] ^ seedBytes[2] ^ seedBytes[3]) >>> 0;
  const hashIndex = (index) => { let x = (documentSeed ^ Math.imul((index >>> 0) + 1, 2654435761)) >>> 0; x ^= x << 13; x ^= x >>> 17; x ^= x << 5; return x >>> 0; };
  const tiny = (index) => ((hashIndex(index) & 1) ? 1 : -1);

  function safeGetter(proto, name, transform) {
    try {
      if (!proto) return;
      const desc = Object.getOwnPropertyDescriptor(proto, name);
      if (!desc?.get || desc.configurable === false) return;
      Object.defineProperty(proto, name, { ...desc, get: function(){ return transform(desc.get.call(this)); } });
    } catch { /* fail closed to native behavior */ }
  }

  if (caps.hardware && globalThis.Navigator?.prototype) {
    safeGetter(Navigator.prototype, 'hardwareConcurrency', (value) => {
      const n = Number(value); if (!Number.isFinite(n) || n < 1) return value;
      if (n >= 8) return 8; if (n >= 4) return 4; if (n >= 2) return 2; return 1;
    });
    safeGetter(Navigator.prototype, 'deviceMemory', (value) => {
      const n = Number(value); if (!Number.isFinite(n) || n <= 0) return value;
      if (n >= 8) return 8; if (n >= 4) return 4; if (n >= 2) return 2; return 1;
    });
  }

  function patchWebGL(proto) {
    try {
      if (!proto?.getParameter) return;
      const original = proto.getParameter;
      Object.defineProperty(proto, 'getParameter', { configurable: true, writable: true, value: function(parameter) {
        if (parameter === 37445) return 'WebKit';
        if (parameter === 37446) return 'WebKit WebGL';
        return Reflect.apply(original, this, arguments);
      }});
    } catch { /* native behavior wins */ }
  }
  if (caps.webgl) { patchWebGL(globalThis.WebGLRenderingContext?.prototype); patchWebGL(globalThis.WebGL2RenderingContext?.prototype); }

  function eligibleCanvas(canvas) {
    const w=Number(canvas?.width)||0, h=Number(canvas?.height)||0;
    return w > 0 && h > 0 && w * h <= MAX_CANVAS_PIXELS;
  }
  function perturbImageData(imageData) {
    const data=imageData?.data; if(!data || data.length < 4) return imageData;
    const stride=Math.max(4, Math.floor(data.length / 256 / 4) * 4);
    for(let i=0;i<data.length;i+=stride){ const channel=(i + (hashIndex(i)%3)); if(channel < data.length && (channel & 3) !== 3) data[channel]=Math.max(0,Math.min(255,data[channel]+tiny(channel))); }
    return imageData;
  }
  if (caps.canvas && globalThis.CanvasRenderingContext2D?.prototype && globalThis.HTMLCanvasElement?.prototype) {
    try {
      const ctxProto=CanvasRenderingContext2D.prototype;
      const originalGet=ctxProto.getImageData;
      if(typeof originalGet==='function') Object.defineProperty(ctxProto,'getImageData',{configurable:true,writable:true,value:function(){const result=Reflect.apply(originalGet,this,arguments);return eligibleCanvas(this?.canvas)?perturbImageData(result):result;}});
      const canvasProto=HTMLCanvasElement.prototype;
      const originalToDataURL=canvasProto.toDataURL, originalToBlob=canvasProto.toBlob;
      const originalDraw=ctxProto.drawImage, originalPut=ctxProto.putImageData;
      function noisyClone(canvas){
        if(!eligibleCanvas(canvas) || !globalThis.document?.createElement || typeof originalGet!=='function' || typeof originalDraw!=='function' || typeof originalPut!=='function') return null;
        try{const clone=document.createElement('canvas');clone.width=canvas.width;clone.height=canvas.height;const c=clone.getContext('2d');if(!c)return null;Reflect.apply(originalDraw,c,[canvas,0,0]);const img=Reflect.apply(originalGet,c,[0,0,clone.width,clone.height]);perturbImageData(img);Reflect.apply(originalPut,c,[img,0,0]);return clone;}catch{return null;}
      }
      if(typeof originalToDataURL==='function') Object.defineProperty(canvasProto,'toDataURL',{configurable:true,writable:true,value:function(){const clone=noisyClone(this);return Reflect.apply(originalToDataURL,clone??this,arguments);}});
      if(typeof originalToBlob==='function') Object.defineProperty(canvasProto,'toBlob',{configurable:true,writable:true,value:function(){const clone=noisyClone(this);return Reflect.apply(originalToBlob,clone??this,arguments);}});
    } catch { /* native canvas remains */ }
  }

  if (caps.audio && globalThis.OfflineAudioContext?.prototype?.startRendering) {
    try {
      const original=OfflineAudioContext.prototype.startRendering;
      Object.defineProperty(OfflineAudioContext.prototype,'startRendering',{configurable:true,writable:true,value:function(){const value=Reflect.apply(original,this,arguments);if(!value?.then)return value;return value.then((buffer)=>{try{const channels=Math.min(Number(buffer?.numberOfChannels)||0,8);for(let ch=0;ch<channels;ch+=1){const data=buffer.getChannelData(ch);const step=Math.max(128,Math.floor(data.length/256));for(let i=0;i<data.length;i+=step)data[i]+=tiny(i+ch*131)*AUDIO_NOISE_EPSILON;}}catch{}return buffer;});}});
    } catch { /* native audio remains */ }
  }

  if (caps.uaHighEntropy && globalThis.NavigatorUAData?.prototype?.getHighEntropyValues) {
    try {
      const proto=NavigatorUAData.prototype, original=proto.getHighEntropyValues;
      Object.defineProperty(proto,'getHighEntropyValues',{configurable:true,writable:true,value:function(){const value=Reflect.apply(original,this,arguments);return Promise.resolve(value).then((result)=>{if(!result||typeof result!=='object')return result;const out={...result};for(const key of ['architecture','bitness','model','platformVersion','uaFullVersion']) if(key in out) out[key]='';if(Array.isArray(out.fullVersionList))out.fullVersionList=out.fullVersionList.map((item)=>({brand:item.brand,version:String(item.version??'').split('.')[0]}));return out;});}});
    } catch { /* native UA data remains */ }
  }
})();
