# perimeter-scan

**Passive external attack-surface scanner.** Find your exposed subdomains, expiring
certs, missing security headers, and dangling DNS that could be hijacked — before an
attacker (or a prospect's security team) does.

One command, no agent, no signup:

```console
$ perimeter-scan example.com
```

It's **passive**: it reads public Certificate Transparency logs and DNS, and makes
standard web requests to the hosts it finds. No exploitation, no port scanning, no
authenticated probing. **Only scan domains you own or are authorized to assess.**

## What it checks

| Check | How |
|-------|-----|
| **Subdomains** | enumerated from public Certificate Transparency logs (crt.sh) |
| **TLS hygiene** | expired, expiring-soon, and self-signed certificates |
| **Security headers** | missing HSTS / CSP / anti-clickjacking / MIME-sniffing headers |
| **Subdomain takeover** | dangling CNAMEs pointing at unclaimed third-party services |

## Install

```console
$ pipx install perimeter-scan      # recommended (isolated)
# or
$ pip install perimeter-scan
```

Requires Python 3.11+.

## Usage

```console
$ perimeter-scan example.com                  # human-readable report
$ perimeter-scan example.com --json           # machine-readable JSON
$ perimeter-scan example.com --min-severity high   # only high+ findings
$ perimeter-scan example.com --max-subdomains 100  # scan more hosts
$ perimeter-scan example.com --fail-on high   # exit 1 if any high+ finding (for CI)
```

### In CI — fail the build on a new exposure

```yaml
# .github/workflows/attack-surface.yml
- run: pipx install perimeter-scan
- run: perimeter-scan yourcompany.com --fail-on high --json
```

### As a library

```python
import asyncio
from perimeter_scan import passive_scan, ScanConfig

result = asyncio.run(passive_scan("example.com", config=ScanConfig(max_subdomains=50)))
print(result.risk_score, result.counts_by_severity())
for f in result.findings:
    print(f.severity.value, f.asset, f.title)
```

## A one-time scan is a snapshot. Your attack surface changes every deploy.

`perimeter-scan` is the open-source scanner behind **[Perimeter](https://perimeter.example)**.
The CLI tells you what's exposed *right now*. Perimeter runs it continuously, remembers
what it saw last time, and **alerts you the moment something new appears** — a fresh
subdomain, a cert about to lapse, a dangling record someone could hijack — so you find
it before anyone else does.

→ **[Monitor your domain continuously](https://perimeter.example)**

## License

MIT. Contributions welcome.
