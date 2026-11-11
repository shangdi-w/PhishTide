# Security Policy

## Authorized use

PhishTide is a phishing simulation platform intended for **authorized security awareness training and internal phishing drills**. Use it only against people and systems you own or have explicit written permission to test. Misuse may be illegal; the authors provide no warranty and accept no liability.

## Supported versions

The `main` branch is the supported version. Security fixes are applied there.

## Reporting a vulnerability

Please use GitHub's **private security advisory** feature (Security → Advisories → Report a vulnerability) instead of a public issue. Include:

- affected version/commit,
- reproduction steps or a proof of concept,
- impact and any suggested mitigation.

Do not include real credentials, personal data or third-party target data in the report.

## Scope

In scope: authentication/authorization bypass, CSRF, SSRF, injection, path traversal, stored XSS in the console, secret exposure, unsafe defaults, and data-at-rest issues.

Out of scope: the inherent behavior of a phishing simulator (sending simulated phishing emails, capturing credentials from consenting participants, cloned pages), and issues that require a compromised admin account unless they cross a privilege boundary.

## Hardening

See [docs/en/SECURITY.md](docs/en/SECURITY.md) and [docs/zh-CN/SECURITY.md](docs/zh-CN/SECURITY.md) for the threat model, residual risks and a deployment hardening checklist.
