---
name: http_smuggling
description: HTTP request smuggling via CL.TE, TE.CL, and H2 desync for cache poisoning and auth bypass
---

# HTTP Request Smuggling

## Attack Surface
- Reverse proxy/CDN chains with differing HTTP parsing (HAProxy + nginx, ALB + Apache)
- HTTP/1.1 where front-end and back-end disagree on Content-Length vs Transfer-Encoding
- HTTP/2 to HTTP/1.1 downgrade proxies that improperly translate headers

## Detection Techniques
- Send CL.TE probe: both Content-Length and Transfer-Encoding, measure timing
- Smuggle a request triggering a distinct response on the next legitimate request
- Test TE obfuscation variants to identify which server processes which header

## Common Payloads

```http
# CL.TE: front-end CL, back-end TE
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
# TE.CL: front-end TE, back-end CL  (CL: 3, TE: chunked, chunk "8\r\nSMUGGLED\r\n0")
# TE.TE obfuscation: "Transfer-Encoding : chunked" / "Transfer-Encoding: xchunked"
# H2.CL downgrade: :method POST, :path /, content-length: 0, body: GET /admin HTTP/1.1
# CL.TE credential capture: smuggle POST /log with large Content-Length to absorb next request
```

## Bypass Techniques
- Obfuscate TE with whitespace, capitalization, or duplicate headers
- Line folding (tab after CRLF) to hide TE from the front-end
- H2 binary framing: inject CRLF visible only after H2-to-H1 downgrade

## Exploit Chaining
- Smuggling + cache poisoning: associate attacker content with victim's cached URL
- Smuggling + credential theft: capture cookies via smuggled POST to logging endpoint
- Smuggling + access control bypass: reach internal-only endpoints past the front-end

## Remediation
- Use HTTP/2 end-to-end; avoid H2-to-H1 downgrade at the proxy layer
- Reject ambiguous requests with both Content-Length and Transfer-Encoding
- Disable connection reuse between front-end and back-end servers
