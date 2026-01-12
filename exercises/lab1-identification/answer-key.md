# Lab 1: Vulnerability Identification - Answer Key

## File 1: auth-controller.ts

| # | OWASP | CWE | Severity | Line | Vulnerability | Attack Scenario |
|---|-------|-----|----------|------|---------------|-----------------|
| 1 | A02 | CWE-256 | Critical | 21-23 | Plain text password storage | Attacker gains DB access, reads all passwords |
| 2 | A07 | CWE-307 | High | 34-35 | No rate limiting | Brute force login attempts |
| 3 | A02 | CWE-328 | High | 40 | Weak token generation (base64) | Token easily decoded to extract role |
| 4 | A09 | CWE-532 | Critical | 43 | Password logged in plain text | Log files expose credentials |
| 5 | A07 | CWE-614 | Medium | 46 | Cookie missing secure flags | Session hijacking via XSS |
| 6 | A02 | CWE-200 | High | 48-51 | Password returned in response | Credentials exposed to client |
| 7 | A07 | CWE-204 | Medium | 55-57 | User enumeration via error | Attackers discover valid usernames |
| 8 | A01 | CWE-639 | Critical | 62-66 | IDOR - no authorization check | Any user can access any user's data |
| 9 | A01 | CWE-915 | High | 73-78 | Mass assignment vulnerability | Attacker can set role to admin |
| 10 | A07 | CWE-620 | High | 84-95 | Password reset without verification | Account takeover without proof of identity |

---

## File 2: user-repository.ts

| # | OWASP | CWE | Severity | Line | Vulnerability | Attack Scenario |
|---|-------|-----|----------|------|---------------|-----------------|
| 1 | A03 | CWE-89 | Critical | 18-21 | SQL injection via email | `' OR '1'='1' --` extracts all users |
| 2 | A03 | CWE-89 | Critical | 25-28 | SQL injection in search + ORDER BY | Attacker exfiltrates data via UNION |
| 3 | A03 | CWE-943 | High | 32-35 | NoSQL injection | `{"$gt": ""}` bypasses filters |
| 4 | A03 | CWE-78 | Critical | 39-42 | Command injection | `; rm -rf /` deletes server files |
| 5 | A01 | CWE-22 | High | 46-48 | Path traversal | `../../../etc/passwd` reads system files |

---

## File 3: payment-handler.ts

| # | OWASP | CWE | Severity | Line | Vulnerability | Attack Scenario |
|---|-------|-----|----------|------|---------------|-----------------|
| 1 | A09 | CWE-532 | Critical | 28 | Credit card logged | PCI violation, card theft from logs |
| 2 | A04 | CWE-20 | High | 30-32 | No amount validation | Negative amounts create credits |
| 3 | A02 | CWE-311 | Critical | 36 | Full card number stored | Data breach exposes card numbers |
| 4 | A02 | CWE-330 | Medium | 35 | Weak transaction ID (Math.random) | Predictable IDs allow enumeration |
| 5 | A01 | CWE-862 | High | 46-57 | No authorization on refund | Any user can refund any transaction |
| 6 | A01 | CWE-639 | High | 62-67 | IDOR on payment history | View other users' payment data |
| 7 | A08 | CWE-347 | High | 71-76 | Webhook without signature | Attacker forges payment events |

---

## File 4: resource-controller.ts

| # | OWASP | CWE | Severity | Line | Vulnerability | Attack Scenario |
|---|-------|-----|----------|------|---------------|-----------------|
| 1 | A01 | CWE-862 | High | 17-20 | No access control | Any user accesses any resource |
| 2 | A01 | CWE-269 | High | 24-28 | Privilege escalation | Users grant themselves permissions |
| 3 | A10 | CWE-918 | Critical | 32-45 | SSRF via URL fetch | Access AWS metadata, internal services |
| 4 | A01 | CWE-601 | Medium | 49-52 | Open redirect | Phishing via trusted domain |
| 5 | A05 | CWE-942 | High | 56-60 | CORS misconfiguration | Credential theft via cross-origin |

---

## Summary Statistics

| Category | Count | Percentage |
|----------|-------|------------|
| A01: Broken Access Control | 9 | 33% |
| A02: Cryptographic Failures | 5 | 19% |
| A03: Injection | 5 | 19% |
| A07: Authentication Failures | 4 | 15% |
| A09: Logging Failures | 2 | 7% |
| A10: SSRF | 1 | 4% |
| A08: Integrity Failures | 1 | 4% |
| **Total** | **27** | 100% |

---

## Top 5 Most Critical Issues

1. **SQL Injection (user-repository.ts:18)** - Critical
   - Direct database compromise
   - Data exfiltration possible
   - Fix: Parameterized queries

2. **Plain Text Password Storage (auth-controller.ts:21)** - Critical
   - All user passwords exposed if DB leaked
   - Fix: bcrypt with cost 12+

3. **Credit Card Logging (payment-handler.ts:28)** - Critical
   - PCI-DSS violation
   - Card theft from log files
   - Fix: Never log card data

4. **SSRF (resource-controller.ts:32)** - Critical
   - Access to internal services
   - AWS credential theft via metadata
   - Fix: URL allowlist

5. **Password in Logs (auth-controller.ts:43)** - Critical
   - Credentials exposed in log storage
   - Fix: Never log passwords

---

## Recommended Fix Priority

1. **Immediate (Day 1):**
   - Remove password/card logging
   - Add parameterized queries
   - Implement bcrypt hashing

2. **Short Term (Week 1):**
   - Add authorization checks
   - Implement SSRF protection
   - Fix CORS configuration

3. **Medium Term (Sprint):**
   - Add rate limiting
   - Implement webhook signatures
   - Secure token generation
