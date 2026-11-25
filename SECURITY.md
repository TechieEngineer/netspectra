# Security policy and threat model

NetSpectra v1.0.0-rc.1 is not independently audited. Report vulnerabilities privately through repository Security Advisories. Do not include credentials, webhook URLs or real network inventory in public issues.

## Deployment boundaries

- Local trusted operating-system account; loopback by default. Do not expose NetSpectra directly to the Internet. Use only networks you own or have explicit permission to assess. Private addresses alone do not imply authorization.
- Browser: mandatory password, bcrypt, encrypted HttpOnly/SameSite cookies, server-side expiry/revocation, origin and Host checks, CSP. HTTP loopback is not encrypted in transit; non-loopback requires TLS. First-run setup trusts local machine access.
- API keys: random, hashed, revocable, limited to inventory and bounded scan access. They are not read-only. Use a separate key per trusted integration and revoke after use.
- SQLite: protect data directory, backups and WAL files with OS permissions/ACLs. Database is not encrypted at rest. A path-based single-process lock directory prevents accidental concurrent opens of the same path; it does not protect against a malicious local user or hard-link aliases. After an abnormal termination, confirm no NetSpectra process or container is using the database before removing the empty `<database>.lock` directory. Never delete an active lock. Back up the database only when the service is stopped. Retention is not a disk quota.
- Webhooks: URLs are trusted operator configuration. HTTPS, no redirects. No DNS/IP egress filtering; generic URLs can target private services. Restrict egress at deployment if needed, and never accept untrusted webhook URLs. Notifications contain only aggregate scan status/count and identifier, not host inventory.
- Resource bounds: one scan per process, fixed worker and pacing limits, bounded request bodies, limited WebSocket connections, 32 API keys and 100 retained scans. These are not comprehensive denial-of-service protections.
- Supply chain: review lockfiles, dependency audit results, third-party action versions and container base images. CI checks are not an independent penetration test. No signed binaries, reproducible-build guarantee, or container vulnerability scan is claimed.

See RELEASE-CHECKLIST.md for the stable release requirements.
