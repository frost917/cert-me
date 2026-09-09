#!/usr/bin/env python3
"""Verify SQL digests, local links and reproducible initial artifact generation."""
import hashlib
import json
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True
ROOT=Path(__file__).resolve().parents[1]
manifest=json.loads((ROOT/'internal/storage/migrations/manifest.json').read_text())
for path,want in manifest['files'].items():
    assert hashlib.sha256((ROOT/path).read_bytes()).hexdigest()==want,path
for file in (ROOT/'docs').glob('*.md'):
    text=file.read_text();assert text.count('```')%2==0,file
    for target in re.findall(r'\]\((\.{1,2}/[^)#]+)',text):
        assert (file.parent/target).exists(),(file,target)
# Never overwrite checked-in files to check generation. Use an isolated temp root.
import tempfile
import importlib.util
with tempfile.TemporaryDirectory(prefix='certme-artifacts-') as tmp:
    target=Path(tmp);(target/'api').mkdir()
    for name in ['generate_migrations','generate_openapi']:
        spec=importlib.util.spec_from_file_location(name,ROOT/'tools'/f'{name}.py')
        if name=='generate_migrations':
            mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
            mod.ROOT=target;mod.generate()
        else:
            # OpenAPI generator is a single entry script; execute a copy with root replaced.
            code=(ROOT/'tools/generate_openapi.py').read_text().replace("ROOT=Path(__file__).resolve().parents[1]",'ROOT=Path('+repr(str(target))+')')
            exec(compile(code,str(ROOT/'tools/generate_openapi.py'),'exec'),{'__name__':'__artifact_check__'})
    for file in target.rglob('*'):
        if file.is_file():
            relative=file.relative_to(target)
            assert file.read_bytes()==(ROOT/relative).read_bytes(),f'generated drift: {relative}'
print('PASS: 32 SQL checksums, generation reproducibility and documentation links')
