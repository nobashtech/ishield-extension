#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, shutil, zipfile

root=Path(__file__).resolve().parents[1]
dist=root/'dist'
dist.mkdir(exist_ok=True)
for old in dist.glob('ishield-*-clean-dev.zip'): old.unlink()
for browser in ('chrome','edge','opera','firefox'):
    src=root/'extensions'/browser
    out=dist/f'ishield-{browser}-clean-dev.zip'
    files=[p for p in src.rglob('*') if p.is_file() and p.name!='README.md' and '.DS_Store' not in p.parts]
    with zipfile.ZipFile(out,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for p in sorted(files):
            rel=p.relative_to(src).as_posix()
            info=zipfile.ZipInfo(rel,date_time=(2026,10,5,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o644<<16
            z.writestr(info,p.read_bytes())
        for name in ('LICENSE-MIT','LICENSE-APACHE','THIRD-PARTY-NOTICES.md','licenses/GPL-3.0.txt'):
            p=root/name
            info=zipfile.ZipInfo(name,date_time=(2026,10,5,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED
            info.external_attr=0o644<<16
            z.writestr(info,p.read_bytes())
    print(f'Built {out.relative_to(root)} ({out.stat().st_size:,} bytes)')

checks={}
for p in sorted(dist.glob('ishield-*-clean-dev.zip')):
    checks[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
(dist/'SHA256SUMS.json').write_text(json.dumps(checks,indent=2)+'\n')
print('Wrote dist/SHA256SUMS.json')
