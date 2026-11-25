# Local integration contracts

NetSpectra exposes a versioned REST API. The firewall and honeypot projects are independent services; no automatic firewall mutation or external network scanning is part of this integration. The recommended first integration is read-only inventory aggregation using a revocable key kept server-side. The existing API keys also authorize bounded scans, so do not give them to untrusted consumers; finer scopes remain a future enhancement.

- `GET /api/v1/hosts` returns a JSON array of `{ip,mac,vendor,ports:[{number,service}]}`. Select an observation with `?scan_id=...`.
- `GET /api/v1/scans` returns up to 100 recent scan records, including `id,cidr,status,started,finished,done,total`.
- `GET /metrics` returns authenticated Prometheus exposition text with retained scan and observation gauges and a running gauge. Retained counts may decrease.
- Webhooks are opt-in completion notifications; generic JSON includes `id,status,hosts` (host count only). Discord and Slack receive a summary. Configure HTTPS URLs as trusted operator environment values, not user input. Notifications are best effort.

Keep the browser dashboard separate from integrations and never embed API credentials in a public GitHub Pages site. Do not copy actual inventory or database files into the portfolio.

Local read-only contract check in PowerShell after generating a temporary key:

```powershell
$secret = Read-Host 'Temporary integration key' -AsSecureString
$token = [System.Net.NetworkCredential]::new('', $secret).Password
try {
  $headers = @{ Authorization = "Bearer $token" }
  Invoke-RestMethod -Uri 'http://127.0.0.1:8080/api/v1/hosts' -Headers $headers
  Invoke-RestMethod -Uri 'http://127.0.0.1:8080/api/v1/scans' -Headers $headers
  (Invoke-WebRequest -Uri 'http://127.0.0.1:8080/metrics' -Headers $headers).StatusCode
} finally { Remove-Variable token,secret,headers -ErrorAction SilentlyContinue }
```

Revoke the temporary key in the dashboard. An actual integration test must be run when the other repositories are available.
