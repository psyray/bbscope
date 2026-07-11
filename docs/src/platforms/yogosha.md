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

## Platform name

Used in database records and API responses: **`yog`**