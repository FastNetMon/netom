#!/usr/bin/env python3
"""Emit the release matrices from one platform inventory (also usable locally)."""
import json
import os
from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def metadata(package_format='all'):
    with (ROOT / 'pkg/targets.toml').open('rb') as source:
        targets = tomllib.load(source)
    with (ROOT / 'Cargo.toml').open('rb') as source:
        version = tomllib.load(source)['workspace']['package']['version']
    if os.environ.get('GITHUB_REF_TYPE') == 'tag':
        if os.environ['GITHUB_REF_NAME'] != f'v{version}':
            raise ValueError(f'Release tag must match Cargo.toml: v{version}')
    if package_format not in ('all', *targets['packages']):
        raise ValueError(f'Unknown package format: {package_format}')
    builds, tests = [], []
    for family, config in targets['packages'].items():
        if package_format not in ('all', family):
            continue
        for architecture in targets['architectures']:
            common = dict(architecture, format=family)
            builds.append(dict(common, image=config['build_image']))
            tests.extend(dict(common, image=image) for image in config['test_images'])
    return {
        'version': version,
        'rust_version': targets['rust_version'],
        'cargo_deb_version': targets['cargo_deb_version'],
        'build_matrix': {'include': builds},
        'test_matrix': {'include': tests},
        'architectures': {'include': targets['architectures']},
        'apt_suites': targets['packages']['deb']['apt_suites'],
    }


if __name__ == '__main__':
    result = metadata(os.environ.get('PACKAGE_FORMAT', 'all'))
    if output := os.environ.get('GITHUB_OUTPUT'):
        with open(output, 'a') as destination:
            for key, value in result.items():
                print(f'{key}={value if isinstance(value, str) else json.dumps(value)}', file=destination)
    else:
        print(json.dumps(result, indent=2))
