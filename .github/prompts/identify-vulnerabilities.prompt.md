---
description: Analyze Angular components for security vulnerabilities (Lab 1)
---

# Vulnerability Identification Prompt

Analyze the provided Angular code for security vulnerabilities.

## Analysis Focus

1. **XSS Vulnerabilities**
   - `bypassSecurityTrust*()` usage with user input
   - `[innerHTML]` bindings with unsanitized data
   - Direct `nativeElement.innerHTML` assignments
   - URL parameter reflection without encoding

2. **Authentication Issues**
   - Tokens stored in localStorage/sessionStorage
   - Credentials logged to console
   - Client-side role/permission checks
   - Missing session validation

3. **CSRF/XSRF**
   - Missing `withXsrfConfiguration()`
   - GET requests for state-changing operations
   - Missing SameSite cookie configuration

4. **Data Exposure**
   - Sensitive data in console.log
   - API keys in environment files
   - PII stored in browser storage

5. **Open Redirects**
   - Unvalidated redirect URLs
   - Missing protocol validation
   - External URL navigation without checks

## Output Format

For each vulnerability found, provide:

| # | OWASP | Severity | Location | Description |
|---|-------|----------|----------|-------------|
| 1 | A03 | Critical | file.ts:42 | XSS via bypassSecurityTrustHtml with user input |

### Detailed Finding

**Vulnerability:** [Name]
**OWASP Category:** [A01-A10]
**CWE:** [CWE-XXX]
**Severity:** Critical/High/Medium/Low
**Location:** `path/to/file.ts:line`

**Vulnerable Code:**
```typescript
// Code snippet
```

**Attack Scenario:**
[How an attacker would exploit this]

**Proof of Concept:**
```
[Attack payload or URL]
```

**Remediation:**
[How to fix with secure code example]

---

## Usage

```
/identify-vulnerabilities [file or directory path]
```

Example:
```
/identify-vulnerabilities src/app/vulnerable/components/xss-bypass/
/identify-vulnerabilities src/app/vulnerable/services/auth.service.ts
```
