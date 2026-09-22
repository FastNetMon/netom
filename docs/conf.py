"""Build the Netom manual from the Markdown maintained in this repository."""

from pathlib import Path
import tomllib

ROOT = Path(__file__).resolve().parent.parent
with (ROOT / 'Cargo.toml').open('rb') as manifest:
    release = tomllib.load(manifest)['workspace']['package']['version']

project = 'Netom'
author = 'FastNetMon Inc'
copyright = '2026, FastNetMon Inc and the Netom contributors'
version = release
language = 'en'
extensions = ['myst_parser', 'sphinx.ext.githubpages']
source_suffix = {'.md': 'markdown'}
root_doc = 'index'
exclude_patterns = ['_build', 'planning/**']
myst_heading_anchors = 6

html_theme = 'furo'
html_title = 'Netom documentation'
html_baseurl = 'https://fastnetmon.github.io/netom/'
html_theme_options = {
    'source_repository': 'https://github.com/FastNetMon/netom/',
    'source_branch': 'main',
    'source_directory': 'docs/',
}
html_show_sourcelink = False
