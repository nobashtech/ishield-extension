// Rebuild the generated AdGuard browser bundles used by the Firefox package.
// All executable code is bundled at build time from npm dependencies pinned by package-lock.json.
import fs from 'node:fs';
import path from 'node:path';
import { build } from 'esbuild';
import { CosmeticRule, setConfiguration } from '@adguard/tsurlfilter';

const root = process.cwd();
const dir = path.join(root, 'extensions', 'firefox');
setConfiguration({ engine: 'extension', version: '1.0.0.1' });
const preamble = '/*! AdGuard TSUrlFilter / Scriptlets / ExtendedCss, GPL-3.0. Corresponding source and notices ship with iShield. */';
const output = async (entry, out, format = 'iife') => build({
  entryPoints: [entry], outfile: out, bundle: true, format, platform: 'browser',
  target: ['firefox140'], minify: false, legalComments: 'inline', banner: { js: preamble },
});

const splitLargeMainBundle = (name) => {
  if (name === 'privacy') return;
  const file = path.join(dir, `content/adguard-${name}-main.js`);
  const source = fs.readFileSync(file, 'utf8');
  const token = 'content: `';
  const start = source.indexOf(token);
  const endToken = '` }] });';
  const end = source.indexOf(endToken, start + token.length);
  if (start < 0 || end < 0) throw new Error(`Unable to split ${file}`);
  const dataStart = start + 'content: '.length;
  const literal = source.slice(dataStart, end + 1);
  const key = name === 'ads' ? '__ISHIELD_AG_ADS_FILTER_DATA__' : '__ISHIELD_AG_ALL_FILTER_DATA__';
  fs.writeFileSync(
    path.join(dir, `content/adguard-${name}-filter-data.js`),
    `/*! iShield packaged AdGuard ${name} scriptlet filter data. No remote code. */\nconst ${key} = ${literal};\n`,
  );
  fs.writeFileSync(file, `${source.slice(0, dataStart)}${key}${source.slice(end + 1)}`);
};

fs.mkdirSync(path.join(dir, 'src/vendor'), { recursive: true });
fs.mkdirSync(path.join(dir, 'rules/adguard'), { recursive: true });
await output('extensions/shared/adguard/engine.js', path.join(dir, 'src/vendor/adguard-engine.js'), 'esm');
fs.copyFileSync('extensions/shared/adguard/cosmetic-activity.js', path.join(dir, 'content/cosmetic-activity.js'));
await output('extensions/shared/adguard/content.js', path.join(dir, 'content/adguard-content.js'));
for (const layer of ['ads', 'privacy']) {
  fs.copyFileSync(`extensions/shared/adguard/filters/${layer}.txt`, path.join(dir, `rules/adguard/${layer}.txt`));
}
for (const layers of [['ads'], ['privacy'], ['ads', 'privacy']]) {
  const name = layers.length === 2 ? 'all' : layers[0];
  const text = layers.map(layer => fs.readFileSync(`extensions/shared/adguard/filters/${layer}.txt`, 'utf8')).join('\n');
  const scriptRules = [];
  const functions = new Map();
  const actions = new Map();
  for (const line of text.split('\n')) {
    // Store builds may intercept/neutralize page requests, but imported filters must not
    // originate their own network requests. These guards preserve that privacy boundary.
    if (/google-ima3-dai/u.test(line)
        || (/fandango\.com#%#/u.test(line) && /advertStreamingSessionStart/u.test(line))
        || (/tenasia\.hankyung\.com#%#/u.test(line) && /hkstatic\.hankyung\.com\/css\/rel\/tenasia\/w\/common\.css/u.test(line))
        || (/#%#/u.test(line) && (/\bfetch\s*\(/u.test(line) || /\bsendBeacon\s*\(/u.test(line)))) {
      throw new Error(`Network-initiating imported filter is not allowed in iShield store builds: ${line.slice(0, 180)}`);
    }
    if (line.startsWith('@@')) { scriptRules.push(line); continue; }
    if (!line.includes('#%#') && !line.includes('#@%#')) continue;
    const rule = new CosmeticRule(line);
    scriptRules.push(line);
    if (rule.isAllowlist()) continue;
    const key = rule.getContent();
    const data = rule.getScriptletData();
    if (data) {
      functions.set(data.params.name, data.func.toString());
      actions.set(key, { name: data.params.name, args: data.params.args, params: data.params });
    } else {
      const code = rule.getScript();
      if (code) {
        const rawName = `raw-${functions.size}`;
        functions.set(rawName, `()=>{${code}\n}`);
        actions.set(key, { name: rawName, args: [], params: {} });
      }
    }
  }
  const source = `import {Engine,Request,RequestType} from '@adguard/tsurlfilter';\nconst engine=Engine.createSync({filters:[{id:1,content:${JSON.stringify(scriptRules.join('\n'))}}]});\nconst functions=new Map([${[...functions].map(([key, code]) => `[${JSON.stringify(key)},${code}]`).join(',\n')}]);\nconst actions=new Map(${JSON.stringify([...actions])});\nconst request=new Request(location.href,location.href,RequestType.Document);\nconst result=engine.getCosmeticResult(request,engine.matchRequest(request).getCosmeticOption());\nfor(const rule of result.getScriptRules()){try{const action=actions.get(rule.getContent());if(action)functions.get(action.name)?.({...action.params,domainName:location.hostname},action.args);}catch{}}\n`;
  await build({
    stdin: { contents: source, resolveDir: root, sourcefile: `adguard-${name}-main.js` },
    outfile: path.join(dir, `content/adguard-${name}-main.js`), bundle: true, format: 'iife',
    platform: 'browser', target: ['firefox140'], minify: false, legalComments: 'inline', banner: { js: preamble },
  });
  splitLargeMainBundle(name);
}
const meta = JSON.parse(fs.readFileSync('extensions/shared/adguard/filters/ATTRIBUTION.json', 'utf8'));
fs.writeFileSync(path.join(dir, 'src/adguard-catalog.js'), `// Generated from the pinned imported filter metadata.\nexport const CONTENT_FILTER_COUNTS = Object.freeze(${JSON.stringify(Object.fromEntries(meta.lists.map(list => [list.id, list.ruleCount])))});\n`);
fs.copyFileSync('extensions/shared/adguard/filters/ATTRIBUTION.json', path.join(dir, 'rules/adguard/ATTRIBUTION.json'));
fs.copyFileSync('extensions/shared/adguard/content-manager.js', path.join(dir, 'src/adguard-content-manager.js'));
console.log('AdGuard Firefox bundles rebuilt');
