#!/usr/bin/env python3
from pathlib import Path
import hashlib, zipfile
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'dist'/'iShield-Firefox-1.0.0.1-source.zip'
OUT.parent.mkdir(exist_ok=True)
include_roots=['extensions','scripts','tests','licenses','store/firefox']
root_files=['README.md','LICENSE-MIT','LICENSE-APACHE','THIRD-PARTY-NOTICES.md','package.json','package-lock.json','.gitignore']
files=[]
for name in root_files:
    p=ROOT/name
    if p.is_file(): files.append(p)
for name in include_roots:
    base=ROOT/name
    if base.exists():
        for p in base.rglob('*'):
            if not p.is_file(): continue
            rel=p.relative_to(ROOT)
            if any(part in {'node_modules','dist','.git','__pycache__'} for part in rel.parts): continue
            if p.name=='.DS_Store' or p.suffix=='.pyc': continue
            files.append(p)
with zipfile.ZipFile(OUT,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
    for p in sorted(set(files), key=lambda x:x.relative_to(ROOT).as_posix()):
        rel=p.relative_to(ROOT).as_posix()
        info=zipfile.ZipInfo(rel,date_time=(2026,10,5,0,0,0))
        info.compress_type=zipfile.ZIP_DEFLATED; info.external_attr=0o644<<16
        z.writestr(info,p.read_bytes())
sha=hashlib.sha256(OUT.read_bytes()).hexdigest()
print(f'Built {OUT} ({OUT.stat().st_size:,} bytes, {len(set(files))} files)')
print(f'SHA-256 {sha}')
