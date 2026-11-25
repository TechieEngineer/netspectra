# Packaging verification

Executed locally in the packaging environment:

- `go test -race ./internal/scanner -count=1 -v`: PASS (scope, enumeration, cancellation).
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c ... ./internal/scanner`: PASS (scanner test binary compilation, not execution).
- Go formatting and YAML/JSON syntax checks: PASS.

Not executed successfully: full backend compilation/tests, frontend dependency install/build, full vulnerability scans, Docker, GitHub Actions, browser tests, independent security review, actual firewall/honeypot integration. Go module registry DNS requests were refused and dependency lockfiles could not be generated; Docker was not installed. Follow the release checklist before publishing stable v1.0.0. The source contains proposed security changes that have not been integration-tested.

## Local Windows Acceptance — November 25, 2026

- Go backend compilation: PASS
- Go unit and integration tests: PASS
- Go static analysis: PASS
- React production build: PASS
- npm vulnerability audit: PASS — zero reported vulnerabilities
- Go reachable-code vulnerability audit: PASS — zero reported vulnerabilities
- Embedded dashboard startup: PASS
- Unauthenticated API access rejection: PASS
- Authenticated API access: PASS
- API key revocation: PASS
- Automated security lifecycle test: PASS
- Docker image compilation: PASS
- Docker executable version verification: PASS
- Docker non-root user verification: PASS

## Outstanding Verification

- Review of 18 remaining module-level vulnerability findings
- Linux CI and race detector verification
- Independent security review
- Cross-platform runtime testing
- External firewall and honeypot integration testing
- Supply-chain security review

Release designation: v1.0.0-rc.1.

Automated verification does not constitute an independent security certification.
