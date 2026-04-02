---
name: graphql
description: GraphQL API security assessment techniques
---

# GraphQL Security

## Attack Surface

- Introspection queries exposing full schema (types, mutations, fields)
- Deeply nested queries causing denial of service (query complexity attacks)
- Batch queries enabling brute force (multiple operations in one request)
- Authorization bypass on individual fields or nested resolvers
- Injection in query arguments passed to backend data sources
- Mutation abuse: mass assignment via unexpected input fields
- Subscription endpoints leaking real-time data

## Detection Techniques

- Test introspection: send `{ __schema { types { name } } }` query
- Identify endpoint: common paths `/graphql`, `/graphiql`, `/v1/graphql`, `/api/graphql`
- Check for GraphiQL/Playground UI exposed in production
- Test query depth limits with deeply nested queries
- Attempt field-level authorization bypass across different user roles
- Test batch queries: send array of operations `[{query: ...}, {query: ...}]`
- Probe for verbose error messages revealing schema details

## Common Payloads

### Introspection
```graphql
{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name } } } } }
```

```graphql
{ __type(name: "User") { fields { name type { name kind ofType { name } } } } }
```

### Denial of Service (Nested Query)
```graphql
{ user(id: 1) { friends { friends { friends { friends { friends { name } } } } } } }
```

### Batch Brute Force
```json
[
  {"query": "mutation { login(user:\"admin\", pass:\"pass1\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass2\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass3\") { token } }"}
]
```

### SQL Injection via Arguments
```graphql
{ user(name: "admin' OR '1'='1") { id email } }
```

### Field Suggestion Abuse
```graphql
{ user { __typename passwrd } }
```
(Error message may suggest `password` field)

## Remediation

- Disable introspection in production environments
- Implement query depth limiting (max 5-7 levels)
- Enforce query complexity/cost analysis and reject expensive queries
- Apply field-level authorization in resolvers, not just at query level
- Disable batch queries or apply per-batch rate limits
- Validate and sanitize all input arguments before passing to data sources
- Use persisted/allowlisted queries in production
- Mask or suppress detailed error messages

## References

- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [HackTricks GraphQL](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql)
- [GraphQL Security Best Practices](https://www.apollographql.com/docs/apollo-server/security/overview)
