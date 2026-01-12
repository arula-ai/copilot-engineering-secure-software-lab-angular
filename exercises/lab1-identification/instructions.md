# Lab 1: Vulnerability Identification with GitHub Copilot

**Duration:** 30 minutes
**Objective:** Use GitHub Copilot to identify security vulnerabilities in intentionally vulnerable code.

---

## Prerequisites

- GitHub Copilot extension installed and active
- Lab repository open in VS Code
- Reference: `docs/owasp-reference/top-10-summary.md`

---

## Important: Copilot-Only Workflow

All lab work must be completed using GitHub Copilot. Use these methods:

1. **Copilot Chat** (`Ctrl+Shift+I` / `Cmd+Shift+I`)
2. **Inline suggestions** (type comments starting with `//`)
3. **Terminal commands** via Copilot: `#runInTerminal npm audit`

**Do NOT manually type code or terminal commands.**

---

## Files to Analyze (Priority Order)

| # | File | Time | Expected Issues |
|---|------|------|-----------------|
| 1 | `src/vulnerable/auth/auth-controller.ts` | 8 min | 8-10 |
| 2 | `src/vulnerable/api/payment-handler.ts` | 7 min | 6-8 |
| 3 | `src/vulnerable/data/user-repository.ts` | 7 min | 4-5 |
| 4 | `src/vulnerable/api/resource-controller.ts` | 8 min | 5-6 |

---

## Step-by-Step Instructions

### Step 1: Open Copilot Chat (2 min)

Open Copilot Chat panel. Use the prompt:

```
@workspace I'm analyzing this codebase for OWASP Top 10 vulnerabilities.
The vulnerable code is in src/vulnerable/.
List all the files I should analyze.
```

### Step 2: Analyze auth-controller.ts (8 min)

Open `src/vulnerable/auth/auth-controller.ts`

**Copilot Chat Prompt:**
```
Analyze this file for security vulnerabilities. For each issue found:
1. OWASP category (A01-A10)
2. CWE number
3. Severity (Critical/High/Medium/Low)
4. Line number(s)
5. Attack scenario (one sentence)
6. Fix recommendation

Focus on: authentication, access control, cryptography, and logging.
```

**Document your findings** in the response template below.

### Step 3: Analyze payment-handler.ts (7 min)

Open `src/vulnerable/api/payment-handler.ts`

**Copilot Chat Prompt:**
```
Review this payment handler for security issues:
- Input validation vulnerabilities
- Authorization flaws
- PCI compliance violations
- Data integrity issues

For each issue: OWASP category, severity, line, attack, fix.
```

### Step 4: Analyze user-repository.ts (7 min)

Open `src/vulnerable/data/user-repository.ts`

**Copilot Chat Prompt:**
```
Identify injection vulnerabilities in this file:
- SQL injection
- Command injection
- Path traversal
- NoSQL injection

Show the vulnerable code pattern and the secure alternative.
```

### Step 5: Analyze resource-controller.ts (6 min)

Open `src/vulnerable/api/resource-controller.ts`

**Copilot Chat Prompt:**
```
Check this controller for:
- SSRF (Server-Side Request Forgery)
- Open redirect
- CORS misconfiguration
- Missing authorization

Explain how each vulnerability could be exploited.
```

---

## Response Template

### File: auth-controller.ts

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

**Most Critical Issue:**


**Attack Scenario:**


---

### File: payment-handler.ts

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |
| 2 | | | | |

---

### File: user-repository.ts

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |
| 2 | | | | |

---

### File: resource-controller.ts

| # | OWASP | Severity | Line | Description |
|---|-------|----------|------|-------------|
| 1 | | | | |
| 2 | | | | |

---

## Summary Questions

Use Copilot to answer:

```
Based on the vulnerabilities found in src/vulnerable/,
what are the top 5 most critical security issues that
should be fixed first? Explain why each is critical.
```

---

## Bonus: Run Security Audit (if time permits)

Ask Copilot to run a dependency audit:

```
#runInTerminal npm audit
```

Then ask Copilot:
```
Explain the npm audit results and which vulnerabilities
are most concerning.
```

---

## Validation

Compare your findings with `exercises/lab1-identification/answer-key.md`

**Target:** Find at least 15 vulnerabilities across all files.
