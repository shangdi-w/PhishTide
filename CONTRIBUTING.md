# Contributing / Read-only repository

This repository is public for **reading and downloading only**. The owner does not accept pull requests or pushes from visitors. Please do not open PRs with content changes.

- **Deployment questions:** follow [docs/en/ONE-CLICK.md](docs/en/ONE-CLICK.md) or [docs/zh-CN/ONE-CLICK.md](docs/zh-CN/ONE-CLICK.md), or scan the contact QR in the README.
- **Security issues:** use GitHub's private security advisory (Security → Advisories); see [SECURITY.md](SECURITY.md).

## Development reference

The source is published for transparency and self-hosting. If you want to modify it for your own deployment, clone or download the repository and work in your own copy; do not push to this repository.

Requirements: Go 1.27+, and Chrome/Chromium for clone/screenshot/e2e features.

```bash
git clone https://github.com/shangdi-w/PhishTide.git
cd PhishTide
go build ./...
go vet ./...
go test ./...
```

Tests are offline and deterministic. MySQL tests are skipped unless `PHISH_TEST_MYSQL_DSN` is set.

## Code layout

```
cmd/phishsim/            entry point
internal/core/           config, crypto, logbuf, tlsutil, store
internal/services/       analyze, bounce, detect, dnscheck, geoip, hygiene, pdftext, report
internal/features/       clone, email, llm
internal/web/            HTTP, admin API, agent, embedded console
deploy/                  deployment templates and the one-click installer
docs/                    English and Chinese manuals
```

## License

No license file is included. The source is published for viewing and downloading; all rights are reserved by the author. Do not redistribute or relicense without permission.
