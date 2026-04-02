---
name: idor
description: Insecure Direct Object Reference detection techniques
---

# Insecure Direct Object Reference (IDOR)

## Attack Surface

- REST API endpoints with numeric or sequential IDs (`/api/users/123`)
- File download endpoints (`/download?file_id=456`)
- Account management: profile view/edit, settings, billing
- API keys, tokens, or documents referenced by predictable identifiers
- GraphQL queries with user-controlled ID arguments
- Bulk export/import operations referencing object collections

## Detection Techniques

- Create two test accounts; access Account A's resources using Account B's session
- Increment/decrement numeric IDs in API calls and observe responses
- Replace UUIDs with those from other users (captured via other endpoints)
- Test both GET and state-changing methods (PUT, DELETE, PATCH)
- Check for authorization on nested resources (`/org/1/users/2` - change org ID)
- Compare response sizes: a 200 with different content length may indicate data leak
- Test encoded/hashed IDs for predictable patterns (Base64-decoded sequential values)

## Common Payloads

### Sequential ID Enumeration
```
GET /api/users/1001  (own user)
GET /api/users/1002  (other user)
GET /api/users/1000  (admin or early user)
```

### Parameter Manipulation
```
GET /api/orders/ORD-0001  -> GET /api/orders/ORD-0002
POST /api/profile  {"user_id": 1002, "email": "attacker@evil.com"}
DELETE /api/documents/doc-abc  (other user's document)
```

### HTTP Method Switching
```
GET /api/users/1002  -> 403 Forbidden
PUT /api/users/1002  -> 200 OK (broken authorization on write)
```

### Encoded ID Testing
```
/api/resource/MTAwMg==  (Base64 of "1002")
/api/resource/a1b2c3    (check if hash is predictable)
```

## Remediation

- Enforce server-side authorization checks on every request, not just authentication
- Map object access through the authenticated user's session (e.g., `current_user.orders` not `Order.find(params[:id])`)
- Use non-sequential, non-guessable identifiers (UUIDv4)
- Implement object-level access control policies and test them
- Log and alert on anomalous cross-account access patterns
- Avoid exposing internal IDs in URLs; use indirect reference maps where practical

## References

- [OWASP IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [OWASP API Security Top 10 - BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
