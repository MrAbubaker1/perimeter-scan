# Publishing perimeter-scan

Status: package is built + validated (`dist/perimeter_scan-0.1.0{.tar.gz,-py3-none-any.whl}`,
both pass `twine check`, 24 tests green). Two destinations: **GitHub** (the funnel /
top-of-funnel) and **PyPI** (so `pip install perimeter-scan` works).

Run everything from `/home/captain/Projects/perimeter-scan` in YOUR terminal (these steps
need interactive auth, so I can't run them headless).

---

## 1. GitHub  →  github.com/MrAbubaker1/perimeter-scan

### Option A — GitHub CLI (cleanest; handles auth + push in one go)
```bash
sudo pacman -S github-cli         # Arch; one-time install
gh auth login                     # choose GitHub.com → HTTPS → login via browser
gh repo create MrAbubaker1/perimeter-scan --public --source=. --remote=origin --push \
  --description "Passive external attack-surface scanner — find exposed subdomains, expiring certs, missing security headers, and dangling DNS before attackers do."
```
That creates the public repo and pushes `main` in one command.

### Option B — no gh (create on web, push with git)
1. Go to **github.com/new** → name `perimeter-scan` → **Public** → **do NOT** add README/license (repo already has them) → Create.
2. ```bash
   git remote add origin git@github.com:MrAbubaker1/perimeter-scan.git
   git push -u origin main
   ```
   (SSH push will prompt for your key passphrase. If your GitHub account has no SSH key,
   use the HTTPS URL `https://github.com/MrAbubaker1/perimeter-scan.git` and a Personal
   Access Token as the password.)

### After pushing — make the repo look credible (matters for the funnel)
- Add topics: `security`, `attack-surface`, `subdomain`, `recon`, `appsec`.
- Set the repo's website to **https://perimeter-hq.com**.
- (Optional) tag the release: `git tag v0.1.0 && git push --tags`.

---

## 2. PyPI  →  pip install perimeter-scan

### One-time setup
1. Create account at **pypi.org** (verify email).
2. Account → **API tokens** → **Add API token** → scope "Entire account" (fine for first
   upload) → copy the `pypi-...` token.

### Upload
```bash
.venv/bin/python -m twine upload dist/*
# username:  __token__
# password:  paste the pypi-... token (input is hidden)
```
Verify: `pip install perimeter-scan` in a fresh venv → `perimeter-scan example.com` runs.

> **Tip:** test against TestPyPI first if you want a dry run:
> `.venv/bin/python -m twine upload --repository testpypi dist/*`

### Re-publishing later
Bump `version` in `pyproject.toml`, then `rm -rf dist && python -m build && twine upload dist/*`
(PyPI rejects re-uploading an existing version).

---

## 3. Wire the SaaS to PyPI (optional cleanup, after PyPI is live)
The live Perimeter SaaS currently installs `perimeter-scan` from a vendored wheel in
`../perimeter/vendor/`. Once it's on PyPI you can drop the vendor hack: the Docker build's
`pip install ".[prod]"` will resolve it from PyPI normally. Not urgent — the vendored wheel
works fine.
