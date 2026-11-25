# v1.0.0 release acceptance

**Status: v1.0.0-rc.1. No completed external security audit.** Record actual results, date, commit SHA, environment, and reviewer for every gate. Never mark a gate passed without evidence.

| Phase | Required evidence | Status at packaging |
| --- | --- | --- |
| 1 Backend | Lockfiles committed; go vet; full tests; race tests; schema/retention/recovery tests | Pending dependencies |
| 2 Scanner | Scope, target count, cancellation tests; loopback end-to-end result; persistence; no public scope | Unit tests passed locally; E2E pending |
| 3 Dashboard | React build; browser setup/login/logout; live progress; history; filters; topology; no CSP errors; settings and revocation | Pending |
| 4 Security | govulncheck; npm audit; review auth, resource bounds, database permissions, webhooks, threat model and workflow supply chain; independent review and remediation | Pending |
| 5 Deployment | Native Windows run; Linux Docker smoke test; CI green; cross-builds; release checksum verification; static Pages | Pending |
| 6 Integration | Read-only inventory and metrics consumed by a separate local client; webhook delivery with a test endpoint; contract tests against firewall/honeypot | Contracts available; actual integration pending other repositories |

## Manual acceptance on a local machine

1. Run `scripts/bootstrap.ps1` and `scripts/verify.ps1` from PowerShell. Fix reported findings before continuing; do not bypass or suppress failed checks. Review changes to dependencies and commit lockfiles.
2. Start the built executable, navigate to http://127.0.0.1:8080, create a unique administrator password. Use browser developer tools to check for JavaScript errors, CSP blocks and successful WebSocket upgrade. Verify logout closes access and refreshing does not restore a revoked session.
3. Run a scan only against `127.0.0.1/32` with explicit permission confirmation. Verify progress, port 8080, persisted history, and filtering. Restart gracefully and confirm history survives. Test rejection of unauthorized requests and invalid CIDRs with the existing automated tests.
4. Create and revoke a test API key in Settings. Confirm a local GET inventory request returns 200 before revocation and 401 afterwards. Never commit the key or database. Confirm the metrics endpoint rejects anonymous calls and accepts a valid key.
5. On native Linux, run `docker compose up --build -d`, verify local setup and dashboard, then `docker compose down`. Confirm container UID 10001, no added capabilities, and private data volume. Verify artifacts on each supported operating system, not just cross-compilation.
6. Have a separate reviewer inspect the threat model and source. Record findings and resolutions. Configure branch protection, dependency alerts, secret scanning where available, and private vulnerability reporting. Review/pin third-party Actions and container base images by verified immutable revisions before claiming reproducible supply-chain security.
7. Exercise the integration contracts in `INTEGRATION.md`. Actual firewall and honeypot sources are not in this archive. Do not claim integration until it is tested against those projects.
8. Push an RC tag. CI must pass before a draft GitHub Release is created. Verify binary hashes and inspect the draft. Publish a stable `v1.0.0` tag and its draft release only after all acceptance gates are satisfied.

## Evidence record (complete after verification)

- Commit SHA:
- Date and environment:
- CI run URL:
- Security reviewer and report reference:
- Unresolved findings:
- Browser / native / Docker test evidence:
- Integration evidence:
- Release approver:
