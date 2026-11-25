# Packaging verification

Executed locally in the packaging environment:

- `go test -race ./internal/scanner -count=1 -v`: PASS (scope, enumeration, cancellation).
- `GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c ... ./internal/scanner`: PASS (scanner test binary compilation, not execution).
- Go formatting and YAML/JSON syntax checks: PASS.

Not executed successfully: full backend compilation/tests, frontend dependency install/build, full vulnerability scans, Docker, GitHub Actions, browser tests, independent security review, actual firewall/honeypot integration. Go module registry DNS requests were refused and dependency lockfiles could not be generated; Docker was not installed. Follow the release checklist before publishing stable v1.0.0. The source contains proposed security changes that have not been integration-tested.
