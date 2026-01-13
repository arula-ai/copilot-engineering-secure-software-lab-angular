---
description: Perform comprehensive security code review
---

# Security Code Review Prompt

Perform a comprehensive security code review of Angular code following OWASP guidelines.

## Review Checklist

### Input Validation
- [ ] All user inputs validated
- [ ] URL parameters sanitized
- [ ] Query params encoded
- [ ] File uploads validated
- [ ] JSON parsing handled safely

### Output Encoding
- [ ] No `bypassSecurityTrust*()` with user data
- [ ] No `innerHTML` with unsanitized content
- [ ] No direct DOM manipulation with user data
- [ ] URLs validated before navigation

### Authentication
- [ ] No tokens in localStorage/sessionStorage
- [ ] Credentials not logged
- [ ] Session validated server-side
- [ ] Proper logout implementation

### Authorization
- [ ] No client-side only role checks
- [ ] Sensitive actions require server validation
- [ ] Route guards verify permissions

### Data Protection
- [ ] Sensitive data masked in UI
- [ ] No PII in console logs
- [ ] No secrets in frontend code
- [ ] Proper error handling (no stack traces)

### HTTP Security
- [ ] XSRF configuration present
- [ ] withCredentials for auth requests
- [ ] Proper HTTP methods used
- [ ] HTTPS enforced

## Output Format

```markdown
# Security Code Review: [File/Component]

## Summary
- **Risk Level:** Critical/High/Medium/Low
- **Findings:** X issues found
- **Recommendation:** [Brief summary]

## Findings

### [SEVERITY] Finding 1: [Title]

**Category:** Input Validation / Output Encoding / Auth / etc.
**Location:** `file.ts:line`
**CWE:** CWE-XXX

**Issue:**
[Description of the problem]

**Code:**
```typescript
// Problematic code
```

**Impact:**
[What could happen if exploited]

**Remediation:**
```typescript
// Fixed code
```

**Priority:** P1/P2/P3/P4

---

[Repeat for each finding]

## Statistics

| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |

## Positive Findings
- [Security controls that are properly implemented]
```

## Review Scope Options

### Quick Review
Focus on critical vulnerabilities only:
- XSS patterns
- Token storage
- Credential exposure

### Standard Review
Include medium-severity issues:
- CSRF configuration
- Input validation
- Error handling

### Comprehensive Review
Full security assessment:
- All vulnerability categories
- Code quality issues
- Security best practices

## Usage

```
/security-code-review [file path] [scope: quick|standard|comprehensive]
```

Examples:
```
/security-code-review src/app/vulnerable/services/auth.service.ts comprehensive
/security-code-review src/app/vulnerable/components/ standard
/security-code-review src/app/ quick
```
