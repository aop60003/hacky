---
name: http_headers
description: HTTP security header analysis and misconfiguration detection
---

# HTTP Security Headers

## Attack Surface

- Missing or misconfigured security headers enabling client-side attacks
- Overly permissive CORS allowing cross-origin data theft
- Absent CSP allowing XSS and data injection
- Information leakage via Server, X-Powered-By, X-AspNet-Version headers
- Cookie attributes missing security flags
- Clickjacking via missing X-Frame-Options or CSP frame-ancestors

## Detection Techniques

- Inspect response headers for presence/absence of security headers
- Test CORS: send `Origin: https://evil.com` and check `Access-Control-Allow-Origin`
- Evaluate CSP policy for `unsafe-inline`, `unsafe-eval`, wildcard sources
- Check cookie flags: `Secure`, `HttpOnly`, `SameSite`
- Test X-Frame-Options by embedding target in an iframe
- Look for server version disclosure in error pages (404, 500)
- Verify HSTS header with adequate `max-age` and `includeSubDomains`

## Common Payloads

### CORS Misconfiguration Testing
```
Origin: https://evil.com
Origin: https://target.com.evil.com
Origin: null
```

### CSP Bypass Indicators
```
Content-Security-Policy: default-src 'self' 'unsafe-inline'
Content-Security-Policy: script-src * 'unsafe-eval'
Content-Security-Policy: script-src cdn.jsdelivr.net  (JSONP/Angular gadgets)
```

### Expected Secure Headers
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

### Headers to Remove
```
Server: Apache/2.4.51
X-Powered-By: PHP/8.1.0
X-AspNet-Version: 4.0.30319
```

## Remediation

- Deploy all recommended security headers via web server or middleware
- Configure CSP with strict nonce-based or hash-based script policy
- Set CORS `Access-Control-Allow-Origin` to specific trusted origins, never `*` with credentials
- Enable HSTS with `max-age` of at least one year and submit to preload list
- Set cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict`)
- Remove version-disclosing headers (Server, X-Powered-By)
- Use `X-Frame-Options: DENY` or `CSP frame-ancestors 'none'` to prevent clickjacking
- Set `Referrer-Policy: strict-origin-when-cross-origin` to limit referrer leakage

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [SecurityHeaders.com](https://securityheaders.com/)
- [MDN HTTP Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
