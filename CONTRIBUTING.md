# Contributing

Thanks for helping make PyGuard better. This repo uses **tight docs hygiene** and **fast feedback**.

## Dev setup

```bash
# Clone + env
git clone https://github.com/YOUR_USERNAME/PyGuard.git
cd PyGuard
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Docs tooling
npm i -g markdownlint-cli
pip install vale
```

## Lint & test

```bash
# Code
make test
make lint
make format

# Docs
markdownlint "**/*.md"
vale docs/
npx linkinator README.md docs/**/*.md
```

## Commit style

Conventional commits: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`

Keep PRs narrowly scoped. Include before/after evidence (logs, screenshots).

## PR checklist

- [ ] Quickstart works on a clean machine
- [ ] Updated README/config tables as needed
- [ ] Added/updated tests (aim for >70% coverage)
- [ ] Security implications noted (secrets/permissions)
- [ ] Links valid, badges green
- [ ] Docs lint-clean (markdownlint, vale)

## Releasing

- Tag with SemVer (`vX.Y.Z`)
- Publish artifacts + SBOM (SPDX)
- Sign release (Sigstore/cosign)
- Attach provenance/SLSA

Full guide: [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)
