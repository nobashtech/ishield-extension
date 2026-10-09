#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, zipfile
root = Path(__file__).resolve().parents[1]
src = root / 'extensions' / 'firefox'
dist = root / 'dist'
dist.mkdir(exist_ok=True)
out = dist / 'iShield-Firefox-1.0.0.1-amo.zip'
files = [p for p in src.rglob('*') if p.is_file() and p.name != 'README.md' and '.DS_Store' not in p.parts]
with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for p in sorted(files):
        rel = p.relative_to(src).as_posix()
        info = zipfile.ZipInfo(rel, date_time=(2026, 10, 5, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        z.writestr(info, p.read_bytes())
    for name in ('LICENSE-MIT', 'LICENSE-APACHE', 'THIRD-PARTY-NOTICES.md', 'licenses/GPL-3.0.txt'):
        p = root / name
        info = zipfile.ZipInfo(name, date_time=(2026, 10, 5, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        z.writestr(info, p.read_bytes())
sha = hashlib.sha256(out.read_bytes()).hexdigest()
(dist / 'FIREFOX-SHA256.json').write_text(json.dumps({out.name: sha}, indent=2) + '\n')
print(f'Built {out.relative_to(root)} ({out.stat().st_size:,} bytes)')
print(f'SHA-256 {sha}')
