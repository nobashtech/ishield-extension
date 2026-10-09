#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import json, re, sys

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []

def fail(msg: str) -> None:
    errors.append(msg)

required = [
    'README.md','SECURITY.md','CONTRIBUTING.md','CHANGELOG.md','THIRD-PARTY-NOTICES.md',
    'docs/NETWORK-BOUNDARY.md','docs/BRAVE-COMPATIBILITY.md','docs/GITHUB-RELEASE.md',
    '.github/workflows/ci.yml','.gitattributes','.gitignore','package.json','package-lock.json'
]
for rel in required:
    if not (ROOT/rel).is_file(): fail(f'missing required public-release file: {rel}')

junk_patterns = ('*.tmp','*.bak','*~','.DS_Store','*.pem','*.key','*.p12','*.pfx')
for pattern in junk_patterns:
    for p in ROOT.rglob(pattern):
        if 'node_modules' not in p.parts and 'dist' not in p.parts:
            fail(f'forbidden release file: {p.relative_to(ROOT)}')

for name in ('chrome','edge','opera','firefox'):
    manifest_path = ROOT/'extensions'/name/'manifest.json'
    try:
        manifest=json.loads(manifest_path.read_text())
    except Exception as e:
        fail(f'{name}: invalid manifest: {e}')
        continue
    if manifest.get('manifest_version') != 3: fail(f'{name}: Manifest V3 required')
    if manifest.get('version') != '1.0.0.1': fail(f'{name}: unexpected release version')
    if manifest.get('incognito') != 'not_allowed': fail(f'{name}: private browsing must be disabled')

# Keep GitHub-hosted source within GitHub's normal per-file limit.
for p in ROOT.rglob('*'):
    if not p.is_file() or 'node_modules' in p.parts or 'dist' in p.parts: continue
    if p.stat().st_size >= 100 * 1024 * 1024:
        fail(f'file reaches GitHub 100 MiB danger zone: {p.relative_to(ROOT)}')

# Very high-signal private credential markers. Public keys and local session tokens are allowed.
secret_res = [
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----'),
    re.compile(rb'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(rb'\bgh[pousr]_[A-Za-z0-9_]{20,}\b'),
    re.compile(rb'\bsk_live_[A-Za-z0-9]{16,}\b'),
]
text_exts={'.js','.mjs','.py','.json','.md','.html','.yml','.yaml','.txt','.css'}
for p in ROOT.rglob('*'):
    if not p.is_file() or p.suffix.lower() not in text_exts: continue
    if 'node_modules' in p.parts or 'dist' in p.parts: continue
    data=p.read_bytes()
    if any(rx.search(data) for rx in secret_res): fail(f'possible private credential in {p.relative_to(ROOT)}')

if errors:
    print(f'iShield public-release preflight FAILED ({len(errors)})')
    for e in errors: print(f'- {e}')
    sys.exit(1)
print('iShield public-release preflight PASS')
print('- public repository docs present')
print('- no temp/private-key artifacts')
print('- manifests are MV3 release version 1.0.0.1')
print('- no file exceeds GitHub normal 100 MiB limit')
print('- high-signal credential scan clear')
