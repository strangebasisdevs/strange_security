# Security policy

## Supported versions

Security fixes are made for the latest release of strange_security. Consumers
pin a release by commit SHA, so a fix reaches them when Dependabot proposes the
new pin and they merge it.

## Reporting a vulnerability

Report vulnerabilities privately through this repository's Security tab:
**Security -> Report a vulnerability**. Do not open a public issue, pull
request or discussion for a suspected vulnerability.

## Scope

In scope:

- the reusable workflows in `.github/workflows/` (`semgrep.yml`, `trivy.yml`,
  `gitleaks.yml`, `trivy-image.yml`, `trivy-images.yml`), for example a way to
  make a scan pass without scanning the code, to run attacker-controlled code in
  the caller's job, to leak the token, or to widen the permissions a caller
  grants;
- the scanner images built from `scanner-images/`, for example a mutable or
  unpinned base image, or a tool version that is not the one pinned;
- the scripts in `scripts/` that the workflows run, including the suppression
  checker and the image exception and allowlist gates.

Out of scope: findings that the scanners themselves report about a consumer
repository (report those to that repository), and vulnerabilities in Semgrep,
Trivy, Gitleaks or GitHub Actions themselves (report those upstream).

## What to include

The workflow or script, the commit or release, the steps that reproduce it, and
the impact you expect.

## What to expect

Reports are acknowledged promptly and handled on a best-effort basis. You will be
told whether the report is accepted and when a fix is released.
