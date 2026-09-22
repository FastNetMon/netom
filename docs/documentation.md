# Maintaining the documentation

The manual at <https://fastnetmon.github.io/netom/> is built from the Markdown
files in `docs/`. Sphinx generates the HTML, MyST parses Markdown, and Furo
provides navigation, search, and light/dark themes. All site assets are served
by GitHub Pages. Building the manual does not compile Netom or fetch content
from an upstream documentation service.

## Build locally

Use Python 3.13 or newer. From the repository root:

```sh
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r docs/requirements.txt
.venv-docs/bin/python -m sphinx -n -W --keep-going -b html docs docs/_build/html
.venv-docs/bin/python -m http.server --bind 127.0.0.1 --directory docs/_build/html 8000
```

Open <http://127.0.0.1:8000/>. Warnings fail the build, including unresolved
internal documentation links. Generated HTML stays out of Git.

## Add or update a guide

Edit the existing Markdown file so GitHub and the website share one source.
Add new guides to a `toctree` in `docs/index.md`. Use relative `.md` links
between guides and ordinary heading anchors. Links to local configuration
files or SQL schemas become downloadable assets in the generated site.

`docs/planning/` contains development notes and is excluded from the manual.
Reference RFC text files are also not documentation sources. Link to GitHub
explicitly when a reader needs a file outside the published manual.

The site follows `main`; it does not maintain separate manuals for each
release. The build reads the application version from `Cargo.toml` without
running Cargo. Documentation dependencies are pinned in `docs/requirements.txt`.

## Publish

The **Documentation** GitHub Actions workflow validates documentation changes
on pull requests. On `main`, it uploads the generated HTML and deploys it
to GitHub Pages. It can also be run manually from `main`.

The build has read-only repository permissions. A separate deployment job
uses GitHub's `github-pages` environment with `pages: write` and
`id-token: write`; no personal token or deployment branch is needed. Pull
requests do not receive deployment permissions.

For a new repository, set **Settings → Pages → Build and deployment → Source**
to **GitHub Actions** before the first deployment. Forks must also update
`html_baseurl`, the source repository links in `docs/conf.py`, and the
deployment job's repository condition in `.github/workflows/docs.yml`.
