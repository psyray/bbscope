# Yogosha

## Authentication

Yogosha uses OIDC (Keycloak) with email + password + TOTP. bbscope performs
the full Authorization Code + PKCE browser flow automatically: it logs in via
Keycloak, submits the TOTP code, and exchanges the authorization code for a
bearer token.

### Config file

```yaml
yogosha:
  email: "you@example.com"
  password: "your_password"
  otpsecret: "YOUR_TOTP_SECRET"
```

### CLI flags

```bash
bbscope poll yog --email you@example.com --password pass --otp-secret SECRET
```

Or with a bearer token (skip the login flow):

```bash
bbscope poll yog --token "your_bearer_token"
```

### Environment variables (web server)

```
YOG_EMAIL=you@example.com
YOG_PASSWORD=your_password
YOG_OTP=YOUR_TOTP_SECRET
```

## What it fetches

- All visible programs via the Yogosha API (`api-cyber.yogosha.com`)
- Public + open-audience programs by default
- Invited (private) programs with `--private-only`
- In-scope URLs (including Google Play / Apple App Store links) and
  out-of-scope URLs, with automatic category classification

## Program metadata captured

Yogosha programs are fetched with `embed=content,audiences` which provides
rich metadata stored in the `program_metadata` table:

| Field | Source | Notes |
|-------|--------|-------|
| Title, Tagline, Company | `name`, `asset.title`, `organization.name` | |
| Program type | `type` | `bugbounty`, `pentest`, or `vdp` |
| Is public / bounty / VDP / disabled | `audiences[].accessMode`, reward amounts, `state`, `archivedAt` | VDP = all rewards zero + `hack_for_values` tag |
| Currency, min/max bounty | `organization.currency`, `lowReward`/`criticalReward` amounts | |
| Reward grid | `lowReward`/`mediumReward`/`highReward`/`criticalReward` | Single grid (dimension `default`), 4 severity levels, min=max |
| Rules | `content.mission` | Markdown — full rules of engagement |
| Qualifying vulnerabilities | Parsed from `content.mission` | Markdown bullet list after "Qualifying vulnerabilities" heading |
| Non-qualifying vulnerabilities | Parsed from `content.outOfScope` | Markdown bullet list after "outside the scope" heading |
| Out-of-scope summary | `content.outOfScope` | Full markdown text |
| VPN required, VPN IPs | `vpnRequired`, `monitoring.type`, `vpnIpAdresses` | |
| Request header | Parsed from `content.terms` | `X-Bug-Bounty` header detected |
| Automated tooling limit | Parsed from `content.terms` | `max. N per sec` extracted |
| Test accounts | `testAccountsEnabled`, `testAccounts.instructions` | |
| Scopes count, tags | `scope.#` (array length), `tags` | |

## Platform name

Used in database records and API responses: **`yog`**