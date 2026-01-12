# Lab Action Guide

Follow these lean steps using GitHub Copilot for all work. Each lab builds on the previous—complete them in order.

## Quick Reference

| Lab | Duration | Primary Actions | Core Artifacts / Commands |
| --- | --- | --- | --- |
| Setup | 5 min | `#runInTerminal npm install`, `#runInTerminal npm run build` | `package.json`, `tsconfig.json` |
| 1 | 30 min | Analyze `src/vulnerable/**`, document findings | `exercises/lab1-identification/answer-key.md` |
| 2 | 25 min | STRIDE analysis, architecture diagram | `threat-models/my-threat-model.md` |
| 3 | 35 min | Refactor vulnerable code, run tests | `src/vulnerable/**`, `#runInTerminal npm test` |
| Verify | 5 min | `#runInTerminal npm run build`, `#runInTerminal npm test` | Final validation |

## Setup – Environment Preparation

- Copilot Chat: `#runInTerminal npm install`
- Copilot Chat: `#runInTerminal npm run build`
- Verify no build errors before proceeding
- Open `README.md` to review lab structure

## Lab 1 – Vulnerability Identification (30 min)

### Phase 1: Reconnaissance (10 min)
- Copilot Chat: `@workspace List all files in src/vulnerable/ and identify which OWASP Top 10 categories each file likely contains`
- Review the file list and create mental map of attack surface
- Start with `#file:src/vulnerable/auth/auth-controller.ts`

### Phase 2: Deep Analysis (15 min)
- For each vulnerable file, use this prompt pattern:
```
#file:src/vulnerable/auth/auth-controller.ts

Analyze this file for OWASP Top 10 vulnerabilities.
For each issue found:
1. OWASP category (A01-A10)
2. Severity (Critical/High/Medium/Low)
3. Line number(s)
4. Attack scenario
5. Recommended fix
```
- Repeat for: `auth-controller.ts`, `payment-handler.ts`, `user-repository.ts`, `resource-controller.ts`, `token-manager.ts`
- Reference `#file:docs/owasp-reference/top-10-summary.md` for category definitions

### Phase 3: Documentation (5 min)
- Copilot Chat: Generate a vulnerability summary table
- Compare findings against `#file:exercises/lab1-identification/answer-key.md`
- Target: Identify at least 15 of 27 documented vulnerabilities

## Lab 2 – Threat Modeling (25 min)

### Phase 1: Architecture (5 min)
- Copilot Chat:
```
Generate a Mermaid diagram for a payment system with:
- Auth Controller (login, registration)
- Payment Handler (payments, refunds, webhooks)
- Resource Controller (files, external resources)
- Session Manager, Token Manager, User Repository

Include trust boundaries between:
1. Internet and API gateway
2. API gateway and application services
3. Application services and database

Use Mermaid flowchart syntax with subgraphs for trust boundaries.
```

### Phase 2: STRIDE Analysis (15 min)
- Copilot Chat: Perform STRIDE analysis using this sequence:
```
For the auth/payment system, perform STRIDE analysis.

SPOOFING: How can attackers impersonate users or the system?
TAMPERING: What data can be modified maliciously?
REPUDIATION: What actions can users deny performing?
INFORMATION DISCLOSURE: What sensitive data could be exposed?
DENIAL OF SERVICE: What resources can be exhausted?
ELEVATION OF PRIVILEGE: How can users gain unauthorized access?

For each threat: describe attack, impact (H/M/L), and mitigation.
```
- Reference `#file:threat-models/templates/stride-template.md` for format

### Phase 3: Prioritization (5 min)
- Copilot Chat: `Rank the top 5 most critical threats by business impact and implementation complexity`
- Save threat model to `threat-models/my-threat-model.md`
- Compare against `#file:threat-models/examples/auth-payment-system-threat-model.md`

## Lab 3 – Secure Implementation (35 min)

### Task 1: Secure Authentication (10 min)
- Copilot Chat:
```
#file:src/vulnerable/auth/auth-controller.ts

Refactor this authentication controller to fix:
1. Add password hashing using bcrypt (cost factor 12)
2. Implement account lockout after 5 failed attempts for 30 minutes
3. Generate secure session tokens using crypto.randomBytes(32)
4. Remove passwords from logs and responses
5. Use generic error messages to prevent user enumeration
6. Add httpOnly, Secure, and SameSite flags to cookies

Reference: #file:src/secure/auth/auth-controller.ts
```
- Apply changes using Copilot's "Apply in Editor"
- Verify with: `#runInTerminal npm run build`

### Task 2: Secure Payment Processing (10 min)
- Copilot Chat:
```
#file:src/vulnerable/api/payment-handler.ts

Fix these security issues:
1. INPUT VALIDATION: Amount (positive, max $1M, 2 decimals), Currency (whitelist USD/EUR/GBP)
2. AUTHORIZATION: Verify transaction ownership before refund
3. LOGGING: Remove all credit card data from logs
4. WEBHOOK: Add HMAC signature verification with timestamp validation

Reference: #file:src/secure/api/payment-handler.ts
```

### Task 3: Fix SQL Injection (8 min)
- Copilot Chat:
```
#file:src/vulnerable/data/user-repository.ts

Convert all SQL queries to parameterized statements:
1. findByEmail - parameterized query
2. searchUsers - parameterized LIKE with validated ORDER BY
3. findByQuery - whitelist allowed fields
4. exportUsers - remove command injection
5. getUserAvatar - add path traversal protection

Reference: #file:src/secure/data/user-repository.ts
```

### Task 4: Fix SSRF and Access Control (7 min)
- Copilot Chat:
```
#file:src/vulnerable/api/resource-controller.ts

Fix critical vulnerabilities:
1. SSRF: Add URL allowlist, block internal IPs, HTTPS only, disable redirects
2. AUTHORIZATION: Add auth check, verify resource ownership
3. OPEN REDIRECT: Validate redirect URLs against allowlist
4. CORS: Replace wildcard with specific allowed origins

Reference: #file:src/secure/api/resource-controller.ts
```

## Final Verification

- Copilot Chat: `#runInTerminal npm run build`
- Copilot Chat: `#runInTerminal npm test`
- Copilot Chat:
```
@workspace Review all files in src/vulnerable/ that were modified.
For each file confirm:
1. Original vulnerabilities are fixed
2. No new vulnerabilities introduced
3. Code follows OWASP secure coding guidelines
```

## Success Checklist

| Category | Requirements | Verified |
|----------|--------------|----------|
| Lab 1 | Identified ≥15 vulnerabilities with OWASP categories | ☐ |
| Lab 2 | Created STRIDE threat model with ≥12 threats | ☐ |
| Authentication | bcrypt, lockout, secure tokens implemented | ☐ |
| Input Validation | Amount, currency, card validation added | ☐ |
| Authorization | Ownership checks, role verification added | ☐ |
| Injection | Parameterized queries, no concatenation | ☐ |
| SSRF | URL allowlist, internal IP blocking | ☐ |
| Logging | No sensitive data in logs | ☐ |
| Build | `npm run build` passes | ☐ |
| Tests | `npm test` passes (23 tests) | ☐ |

## Copilot Prompt Patterns

### Security Analysis
```
Analyze this file for OWASP Top 10 vulnerabilities.
For each issue: OWASP category, severity, line number, attack scenario, fix.
```

### Threat Modeling
```
Perform STRIDE analysis for this system.
Identify threats for each category with impact and mitigation.
```

### Secure Refactoring
```
Refactor this code to follow secure coding practices.
Add: input validation, authorization, secure logging, parameterized queries.
```

### Code Review
```
Review this code against the security checklist.
Flag any violations with severity and recommended fix.
```

## Key Resources

| Resource | Location |
|----------|----------|
| OWASP Top 10 Reference | `docs/owasp-reference/top-10-summary.md` |
| Security Checklist | `docs/checklists/security-review-checklist.md` |
| STRIDE Template | `threat-models/templates/stride-template.md` |
| Completed Threat Model | `threat-models/examples/auth-payment-system-threat-model.md` |
| Lab 1 Answer Key | `exercises/lab1-identification/answer-key.md` |
| Secure Implementations | `src/secure/` |

## Reminder

- **All work via Copilot**: Use `#runInTerminal` for commands, `#file:` for context, `@workspace` for project-wide queries
- **No manual typing**: Let Copilot generate all code and terminal commands
- **Verify suggestions**: Security is everyone's responsibility—review Copilot output before applying
