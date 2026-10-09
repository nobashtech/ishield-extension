#!/usr/bin/env python3
from pathlib import Path
import json, re, sys, hashlib

ROOT = Path(__file__).resolve().parents[1]
EXT = ROOT / 'extensions' / 'firefox'
MANIFEST = EXT / 'manifest.json'
errors=[]; notes=[]

def fail(msg): errors.append(msg)
def ok(msg): notes.append(msg)

def load_json(path):
    try: return json.loads(path.read_text(encoding='utf-8'))
    except Exception as e:
        fail(f'Invalid JSON: {path.relative_to(ROOT)}: {e}')
        return None

m=load_json(MANIFEST) or {}
if m.get('manifest_version') != 3: fail('manifest_version must be 3')
else: ok('Manifest V3')
gecko=((m.get('browser_specific_settings') or {}).get('gecko') or {})
if not gecko.get('id'): fail('browser_specific_settings.gecko.id missing')
else: ok(f"Gecko ID: {gecko['id']}")
try:
    minv=float(str(gecko.get('strict_min_version','0')).split('.')[0])
    if minv < 140: fail('strict_min_version must be >= 140')
    else: ok(f"strict_min_version: {gecko.get('strict_min_version')}")
except Exception: fail('invalid strict_min_version')
dcp=(gecko.get('data_collection_permissions') or {}).get('required')
if dcp != ['none']: fail(f'data_collection_permissions.required must be ["none"], got {dcp!r}')
else: ok('data_collection_permissions.required = ["none"]')
if m.get('incognito') != 'not_allowed': fail('incognito must be not_allowed')
else: ok('Private browsing disabled')

# Static DNR resources and quotas.
rr=((m.get('declarative_net_request') or {}).get('rule_resources') or [])
if len(rr)>50: fail(f'{len(rr)} static rulesets > Firefox maximum 50')
else: ok(f'Static rulesets: {len(rr)}/50')
enabled=[r for r in rr if r.get('enabled')]
if len(enabled)>10: fail(f'{len(enabled)} enabled static rulesets > Firefox maximum 10')
else: ok(f'Enabled static rulesets: {len(enabled)}/10')

total_rules=enabled_rules=total_regex=max_regex=0
per=[]
for r in rr:
    p=EXT / r.get('path','')
    if not p.is_file():
        fail(f'Missing static ruleset: {r.get("path")}'); continue
    data=load_json(p)
    if not isinstance(data,list):
        fail(f'Ruleset must be a JSON array: {r.get("path")}'); continue
    rc=len(data)
    rg=sum(1 for x in data if isinstance(x,dict) and isinstance((x.get('condition') or {}).get('regexFilter'),str))
    total_rules+=rc; total_regex+=rg; max_regex=max(max_regex,rg)
    if r.get('enabled'): enabled_rules+=rc
    per.append((r.get('id'),rc,rg,bool(r.get('enabled'))))
ok(f'Static DNR rules: {total_rules:,}; enabled by default: {enabled_rules:,}; regex: {total_regex:,}; max regex in one ruleset: {max_regex:,}')

# Dynamic-rule budgets from source constants.
files={
    'allow': EXT/'src/constants.js',
    'strict_policy': EXT/'src/strict-policy.js',
    'strict_manager': EXT/'src/strict-manager.js',
    'update': EXT/'src/update-runtime.js',
}
def const(path,name):
    txt=path.read_text(encoding='utf-8')
    mt=re.search(rf'\b{name}\s*=\s*([0-9_]+)',txt)
    if not mt: fail(f'Cannot resolve {name} in {path.relative_to(ROOT)}'); return 0
    return int(mt.group(1).replace('_',''))
allow=const(files['allow'],'ALLOWLIST_RULE_CAP')
strictp=const(files['strict_policy'],'STRICT_POLICY_CAP')
strictc=const(files['strict_manager'],'STRICT_CATEGORY_RULE_CAP')
update=const(files['update'],'UPDATE_DYNAMIC_RULE_CAP')
dynamic=allow+strictp+strictc+update
if dynamic>5000: fail(f'Managed dynamic rule budget {dynamic} exceeds Firefox 5,000')
else: ok(f'Managed dynamic-rule budget: {dynamic:,}/5,000 (allowlist {allow:,} + strict {strictp:,}+{strictc:,} + signed updates {update:,})')

# Web accessible resources: no wildcard and every path exists.
for block in m.get('web_accessible_resources') or []:
    for res in block.get('resources') or []:
        if '*' in res: fail(f'Wildcard web-accessible resource: {res}')
        if not (EXT/res).is_file(): fail(f'Missing web-accessible resource: {res}')
ok(f"Web-accessible resources: {sum(len(x.get('resources') or []) for x in (m.get('web_accessible_resources') or []))} exact files")

# Validate all JSON in extension.
json_count=0
for p in EXT.rglob('*.json'):
    json_count+=1; load_json(p)
ok(f'JSON parsed: {json_count} files')

# AMO addons-linter rejects individual JavaScript files larger than 5 MiB.
large_js=[(x.stat().st_size,x) for x in EXT.rglob('*.js') if x.stat().st_size>5*1024*1024]
if large_js:
    fail('JavaScript file exceeds AMO 5 MiB parse limit: '+', '.join(f'{p.relative_to(EXT)} ({size:,} bytes)' for size,p in large_js))
else:
    ok('All JavaScript files are within AMO 5 MiB parse limit')

# No private keys / common secrets in first-party text files.
secret_patterns=[
    re.compile(r'BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY'),
    re.compile(r'\bclient_secret\b\s*[:=]\s*["\'][^"\']+',re.I),
    re.compile(r'\b(?:api[_-]?key|access[_-]?token)\b\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}',re.I),
]
secret_hits=[]
for p in EXT.rglob('*'):
    if not p.is_file() or p.suffix.lower() in {'.png','.gif','.mp3','.mp4','.woff','.woff2','.ico','.jpg','.jpeg','.webp'}: continue
    try: txt=p.read_text(encoding='utf-8')
    except Exception: continue
    for pat in secret_patterns:
        if pat.search(txt): secret_hits.append(str(p.relative_to(EXT))); break
if secret_hits: fail('Possible secret/private-key material: '+', '.join(secret_hits[:10]))
else: ok('Secret/private-key scan: clear')

# Packaging hygiene.
for bad in ['.DS_Store','.env']:
    hits=[p for p in EXT.rglob(bad)]
    if hits: fail(f'Forbidden package artifact {bad}: {len(hits)}')
for p in EXT.rglob('*.pem'): fail(f'PEM file must not ship: {p.relative_to(EXT)}')
for p in EXT.rglob('*.map'): fail(f'Source map must not ship in store package: {p.relative_to(EXT)}')

size=sum(p.stat().st_size for p in EXT.rglob('*') if p.is_file())
if size>200*1024*1024: fail(f'Extension tree size {size:,} exceeds 200 MiB')
else: ok(f'Extension tree size: {size/1024/1024:.2f} MiB')

print('Firefox AMO preflight')
for n in notes: print('PASS',n)
for e in errors: print('FAIL',e)
if errors: sys.exit(1)
