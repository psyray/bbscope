# BugBounty.ch

## Authentication

BugBounty.ch uses Azure AD B2C with email + password + TOTP. bbscope performs
the full login flow automatically: it logs in via Azure B2C, submits the TOTP
code, and exchanges the resulting session for a bearer token.

### Config file

```yaml
bugbountych:
  email: "you@example.com"
  password: "your_password"
  otpsecret: "YOUR_TOTP_SECRET"
```

### CLI flags

```bash
bbscope poll bbch --email you@example.com --password pass --otp-secret SECRET
```

Or with a bearer token (skip the login flow):

```bash
bbscope poll bbch --token "your_bearer_token"
```

### Environment variables (web server)

```
BBCH_EMAIL=you@example.com
BBCH_PASSWORD=your_password
BBCH_OTP=YOUR_TOTP_SECRET
```

## What it fetches

- All active (state=1) public engagements via the BugBounty.ch researcher API
  (`api-hacker.bugbounty.ch`)
- Invited (private) engagements with `--private-only`
- One in-scope entry per scope group (the researcher API does not expose the
  underlying asset URLs, so the group name is recorded as the target with
  category `url`)
- Out-of-scope IPv4 addresses mined from the engagement's outOfScope Quill
  Delta text

## Program metadata captured

BugBounty.ch engagements are fetched with rich metadata stored in the
`program_metadata` table:

| Field | Source | Notes |
|-------|--------|-------|
| Title, Tagline, Company | Engagement fields | |
| Program type | `type` | Bounty program when `type=0` and `maxReward>0` |
| Is bounty / VDP / disabled | `type`, `maxReward`, `state` | VDP derived from zero reward + non-bounty type |
| Reward grid | Per-scope-group bounty rows | Severity × tier matrix per scope group |
| Rules, out-of-scope text | Engagement rich-text fields | Quill Delta parsed to plain text |
| Out-of-scope IPs | Parsed from `outOfScope` Quill Delta | IPv4 regex extraction |

## Platform name

Used in database records and API responses: **`bbch`**