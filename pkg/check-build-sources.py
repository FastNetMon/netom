#!/usr/bin/env python3
"""Keep build/release inputs independent of upstream hosting infrastructure."""

from pathlib import Path
import re
import tomllib

ROOT = Path(__file__).resolve().parent.parent
FORK_PREFIX = 'https://github.com/FastNetMon/'


def check_manifest(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'git' and not item.startswith(FORK_PREFIX):
                raise SystemExit(f'Git dependency must use a FastNetMon fork: {item}')
            check_manifest(item)
    elif isinstance(value, list):
        for item in value:
            check_manifest(item)


with (ROOT / 'Cargo.toml').open('rb') as source:
    check_manifest(tomllib.load(source))
with (ROOT / 'Cargo.lock').open('rb') as source:
    for package in tomllib.load(source)['package']:
        location = package.get('source', '')
        if location.startswith('git+') and not location.startswith('git+' + FORK_PREFIX):
            raise SystemExit(f'Locked Git dependency must use a FastNetMon fork: {location}')

# Match network locations and GitHub Action references, not author names or
# license notices. Also reject images in the upstream Docker Hub namespace.
upstream = re.compile(r'''https?://[^\s"'<>]*nlnetlabs[^\s"'<>]*|\bnlnetlabs/''', re.I)
paths = [ROOT / 'Dockerfile', ROOT / 'build.rs']
for directory in ('.github/workflows', 'pkg', 'scripts', '.cargo'):
    paths.extend(path for path in (ROOT / directory).rglob('*')
                 if path.is_file() and '__pycache__' not in path.parts)
for path in paths:
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if upstream.search(line):
            raise SystemExit(f'Upstream build/release reference in {path.relative_to(ROOT)}:{number}')

print('Build sources OK: Git dependencies use FastNetMon forks; no upstream endpoints or actions.')
