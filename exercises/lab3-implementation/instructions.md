# Lab 3: Implementing Secure Patterns with GitHub Copilot

**Duration:** 35 minutes
**Objective:** Fix vulnerabilities identified in Labs 1 & 2 using secure coding patterns.

---

## How This Lab Works

In this lab, you will **modify the vulnerable code in `src/vulnerable/`** to fix security issues. Use GitHub Copilot to help you understand and implement secure patterns.

### Workflow:
1. **Open a vulnerable file** from `src/vulnerable/`
2. **Use Copilot** to generate secure fixes
3. **Apply fixes** directly to the vulnerable file
4. **Run tests** to validate your changes: `npm test`
5. **Compare** your implementation with the reference in `src/secure/` (after completing each task)

> **Note:** The `src/secure/` directory contains reference implementations showing one way to fix the vulnerabilities. Your solution may differ - that's okay! The tests validate secure patterns, not exact code matches.

---

## Important: Copilot-Only Workflow

All code changes must be made using GitHub Copilot:
- Use Copilot Chat for refactoring guidance
- Use inline Copilot suggestions for code completion
- Use `#file` references to include context
- **Do NOT manually type code**

---

## Reference Implementations

Secure reference code is available in `src/secure/` for comparison **after** you complete each task:
- `src/secure/auth/auth-controller.ts`
- `src/secure/api/payment-handler.ts`
- `src/secure/api/resource-controller.ts`
- `src/secure/data/user-repository.ts`
- `src/secure/session/token-manager.ts`

Use these to validate your approach and learn alternative patterns.

---

## Task 1: Secure Authentication (10 min)

**File:** `src/vulnerable/auth/auth-controller.ts`

**Copilot Chat Prompt:**
```
#file:src/vulnerable/auth/auth-controller.ts

Refactor this authentication controller to fix these issues:
1. Add password hashing using bcrypt (cost factor 12)
2. Implement account lockout after 5 failed attempts for 30 minutes
3. Generate secure session tokens using crypto.randomBytes(32)
4. Remove passwords from logs and responses
5. Use generic error messages to prevent user enumeration
6. Add httpOnly, Secure, and SameSite flags to cookies

Reference the secure implementation in:
#file:src/secure/auth/auth-controller.ts

Generate the complete refactored code.
```

**Apply the changes using Copilot's "Apply in Editor" or inline suggestions.**

### Verify Task 1

Ask Copilot to verify:
```
Review my changes to auth-controller.ts.
Confirm these security issues are fixed:
- Password hashing
- Account lockout
- Secure cookies
- No sensitive data in logs/responses
```

---

## Task 2: Secure Payment Processing (10 min)

**File:** `src/vulnerable/api/payment-handler.ts`

**Copilot Chat Prompt:**
```
#file:src/vulnerable/api/payment-handler.ts

Fix these security issues in the payment handler:

1. INPUT VALIDATION:
   - Amount: positive number, max $1,000,000, 2 decimal places
   - Currency: whitelist (USD, EUR, GBP only)
   - Card token: validate format, never accept raw card numbers

2. AUTHORIZATION:
   - Verify user owns the transaction before refund
   - Add role check for admin-only operations

3. LOGGING:
   - Remove all credit card data from logs
   - Log security events without sensitive data

4. WEBHOOK SECURITY:
   - Add HMAC signature verification
   - Validate timestamp to prevent replay attacks

Reference: #file:src/secure/api/payment-handler.ts

Generate the secure implementation.
```

### Verify Task 2

```
Check my payment-handler.ts changes:
- Is credit card data removed from all logs?
- Are amounts properly validated?
- Is webhook signature verification implemented?
```

---

## Task 3: Fix SQL Injection (8 min)

**File:** `src/vulnerable/data/user-repository.ts`

**Copilot Chat Prompt:**
```
#file:src/vulnerable/data/user-repository.ts

Convert all SQL queries to use parameterized statements:

1. findByEmail - use parameterized query
2. searchUsers - use parameterized LIKE with validated ORDER BY
3. findByQuery - whitelist allowed fields
4. exportUsers - remove command injection (use programmatic export)
5. getUserAvatar - add path traversal protection

Show the vulnerable pattern and the secure replacement for each.

Reference: #file:src/secure/data/user-repository.ts
```

### Verify Task 3

```
#file:src/vulnerable/data/user-repository.ts

Are there any remaining injection vulnerabilities in this file?
Check for SQL injection, command injection, and path traversal.
```

---

## Task 4: Fix SSRF and Access Control (7 min)

**File:** `src/vulnerable/api/resource-controller.ts`

**Copilot Chat Prompt:**
```
#file:src/vulnerable/api/resource-controller.ts

Fix these critical vulnerabilities:

1. SSRF PREVENTION:
   - Add URL allowlist for external fetches
   - Block internal IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)
   - Only allow HTTPS
   - Disable redirect following

2. AUTHORIZATION:
   - Add authentication check to all endpoints
   - Verify resource ownership before access
   - Log authorization failures

3. OPEN REDIRECT:
   - Validate redirect URLs against allowlist
   - Only allow relative URLs or trusted domains

4. CORS:
   - Replace wildcard with specific allowed origins
   - Remove credentials from wildcard CORS

Reference: #file:src/secure/api/resource-controller.ts
```

---

## Final Verification

### Run Build

Ask Copilot:
```
#runInTerminal npm run build
```

### Security Review

**Copilot Chat Prompt:**
```
@workspace Review all files in src/vulnerable/ that I modified.
For each file, confirm:
1. Original vulnerabilities are fixed
2. No new vulnerabilities introduced
3. Code follows OWASP secure coding guidelines

List any remaining issues.
```

---

## Success Criteria

Your fixes should address:

| Category | Requirements | Verified |
|----------|--------------|----------|
| Authentication | bcrypt, lockout, secure tokens | ☐ |
| Input Validation | Amount, currency, card validation | ☐ |
| Authorization | Ownership checks, role verification | ☐ |
| Injection | Parameterized queries, no concatenation | ☐ |
| SSRF | URL allowlist, block internal IPs | ☐ |
| Logging | No sensitive data in logs | ☐ |
| Webhooks | Signature verification | ☐ |

---

## Compare with Solutions

After completing the lab, compare your implementations with:
- `src/secure/auth/auth-controller.ts`
- `src/secure/api/payment-handler.ts`
- `src/secure/data/user-repository.ts`
- `src/secure/api/resource-controller.ts`

---

## Bonus Challenge

If time permits, fix the JWT vulnerabilities:

```
#file:src/vulnerable/session/token-manager.ts

Fix the JWT security issues:
1. Reject 'none' algorithm
2. Use cryptographically secure secret
3. Add token expiration
4. Implement refresh token rotation

Reference: #file:src/secure/session/token-manager.ts
```
