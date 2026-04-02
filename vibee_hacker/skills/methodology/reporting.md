---
name: reporting
description: Vulnerability reporting standards with CVSS scoring, evidence, and remediation guidance
---

# Vulnerability Reporting

## CVSS v3.1 Scoring Guide

### Attack Vector (AV)
```
Network (N)  = 0.85  Exploitable over the network (most web vulns)
Adjacent (A) = 0.62  Requires adjacent network (same LAN/wifi)
Local (L)    = 0.55  Requires local access (file upload, local app)
Physical (P) = 0.20  Requires physical device access
```

### Attack Complexity (AC)
```
Low (L)  = 0.77  No special conditions needed (direct exploitation)
High (H) = 0.44  Requires specific config, race condition, or MitM
```

### Privileges Required (PR)
```
None (N) = 0.85  No authentication needed
Low (L)  = 0.62  Requires basic user account
High (H) = 0.27  Requires admin or privileged account
```

### User Interaction (UI)
```
None (N)     = 0.85  No victim action required
Required (R) = 0.62  Victim must click link, open file, etc.
```

### Impact (Confidentiality / Integrity / Availability)
```
None (N) = 0.00  No impact to this dimension
Low (L)  = 0.22  Limited data exposure / partial modification / degraded service
High (H) = 0.56  Full data exposure / complete modification / total denial
```

### Common Vulnerability Scores
```
Unauthenticated RCE:           AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = 10.0
SQLi with data extraction:     AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1
SSRF to cloud metadata:        AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N = 8.6
Stored XSS (admin target):     AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N = 9.0
IDOR with PII exposure:        AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N = 6.5
Reflected XSS:                 AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1
CSRF (state change):           AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N = 6.5
Info disclosure (version):     AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N = 5.3
```

## Severity Classification

```
Critical (9.0-10.0): Immediate action. Full system compromise, mass data breach,
                     unauthenticated RCE. Fix within 24 hours.

High (7.0-8.9):     Urgent. Significant data exposure, authenticated RCE,
                     privilege escalation. Fix within 1 week.

Medium (4.0-6.9):   Important. Limited data exposure, requires user interaction
                     or authentication. Fix within 1 month.

Low (0.1-3.9):      Advisory. Minor information disclosure, theoretical impact.
                     Fix in next release cycle.

Informational:       Best practice recommendations. No direct exploitability.
                     Address during regular maintenance.
```

## Evidence Standards

### Required for Every Finding
```
1. Vulnerability title: clear, specific (e.g., "Stored XSS in Comment Field")
2. Affected endpoint: full URL with method (POST /api/comments)
3. Reproduction steps: numbered, exact steps any tester can follow
4. HTTP request/response: full raw request with headers and body
5. Impact statement: what an attacker can achieve in business terms
6. CVSS score with vector string and justification
```

### PoC Requirements by Severity
```
Critical/High:
  - Full working exploit with sanitized credentials
  - Step-by-step reproduction with screenshots at each step
  - Video walkthrough if the attack chain is complex
  - Evidence of actual impact (data accessed, command output)

Medium:
  - HTTP request/response pairs showing the vulnerability
  - Screenshot of the vulnerable behavior
  - Proof that the issue is exploitable, not theoretical

Low/Informational:
  - HTTP response showing the finding (headers, error messages)
  - Explanation of potential risk if conditions change
```

## Report Structure

```
1. Executive Summary
   - Total findings by severity
   - Top 3 most critical risks in business language
   - Overall security posture assessment

2. Methodology
   - Scope and rules of engagement
   - Tools and techniques used
   - Testing timeline

3. Findings (per vulnerability)
   - Title, severity, CVSS score
   - Description
   - Affected endpoints
   - Steps to reproduce
   - Evidence (requests, responses, screenshots)
   - Business impact
   - Remediation recommendation
   - References (CWE, OWASP)

4. Remediation Priority Matrix
   - Quick wins: low effort + high impact fixes first
   - Group related findings for efficient remediation
   - Suggest defense-in-depth layers
```

## Remediation Priority

```
Priority 1 (immediate): Actively exploitable, no auth required, critical data at risk
Priority 2 (this week): Exploitable with low barrier, sensitive data exposure
Priority 3 (this month): Requires conditions or auth, limited direct impact
Priority 4 (next quarter): Best practice improvements, hardening measures

When multiple findings exist, prioritize:
1. Unauthenticated > Authenticated vulnerabilities
2. Remote > Local exploitation
3. Data breach risk > Availability impact
4. Easy to exploit > Complex exploitation
5. Chained critical paths > Isolated findings
```
