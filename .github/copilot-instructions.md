# Angular Security Lab - Copilot Instructions

This is an **Angular 19 Security Training Lab** demonstrating OWASP Top 10 frontend vulnerabilities and their mitigations.

## Project Context

### Purpose
Educational lab for learning frontend security through hands-on exercises:
- **Lab 1**: Vulnerability identification
- **Lab 2**: STRIDE threat modeling
- **Lab 3**: Secure implementation

### Structure
```
src/app/
├── vulnerable/          # Intentionally insecure code (DO NOT USE IN PRODUCTION)
│   ├── components/      # XSS, CSRF, redirect vulnerabilities
│   └── services/        # Insecure auth patterns
├── secure/              # Reference secure implementations
│   ├── components/      # Secure counterparts
│   ├── services/        # HttpOnly cookie auth
│   └── utils/           # Security utilities + tests
└── shared/              # Common components
```

### Technology Stack
- Angular 19 (standalone components)
- TypeScript 5.6
- Jest for testing
- json-server for mock API

---

## Security Analysis Guidelines

When analyzing code in this project, apply these security principles:

### XSS Prevention

**Dangerous Patterns (Flag as Critical):**
```typescript
// NEVER use with user input
this.sanitizer.bypassSecurityTrustHtml(userInput)
this.sanitizer.bypassSecurityTrustUrl(userInput)
element.nativeElement.innerHTML = userInput
```

**Safe Alternatives:**
```typescript
// Use Angular's built-in sanitization
<div>{{ userContent }}</div>

// Use allowlist-based sanitizer
const clean = sanitizeHtml(userInput, allowedTags);
```

### Authentication Security

**Dangerous Patterns (Flag as High):**
```typescript
// NEVER store tokens in browser storage
localStorage.setItem('token', jwt)
sessionStorage.setItem('auth_token', token)

// NEVER log credentials
console.log('Login:', { password })
```

**Safe Patterns:**
```typescript
// Use HttpOnly cookies (server-side)
http.post(url, data, { withCredentials: true })

// Memory-only state
private user = signal<User | null>(null);
```

### CSRF Protection

**Configuration Required:**
```typescript
// app.config.ts
provideHttpClient(
  withXsrfConfiguration({
    cookieName: 'XSRF-TOKEN',
    headerName: 'X-XSRF-TOKEN'
  })
)
```

### URL Validation

**Dangerous Patterns:**
```typescript
// NEVER redirect without validation
window.location.href = urlParam
router.navigate([untrustedUrl])
```

**Safe Patterns:**
```typescript
// Validate against allowlist
const ALLOWED = ['/', '/dashboard', '/profile'];
if (ALLOWED.includes(path)) {
  router.navigate([path]);
}
```

---

## Vulnerability Reference

| # | Vulnerability | OWASP | Location |
|---|--------------|-------|----------|
| 1 | XSS via bypassSecurityTrustHtml | A03 | xss-bypass.component.ts |
| 2 | Stored XSS via innerHTML | A03 | xss-innerhtml.component.ts |
| 3 | Reflected XSS via URL | A03 | xss-innerhtml.component.ts |
| 4 | XSS via URL bypass | A03 | xss-interpolation.component.ts |
| 5 | JWT in localStorage | A02 | auth.service.ts |
| 6 | Credential logging | A02 | auth.service.ts |
| 7 | Client-side role checks | A07 | auth.service.ts |
| 8 | Missing CSRF protection | A01 | csrf-demo.component.ts |
| 9 | Open redirect | A01 | redirect-handler.component.ts |
| 10 | Secrets in environment | A02 | environment.ts |
| 11 | Sensitive data logging | A02 | data-exposure.component.ts |

---

## Lab Exercise Prompts

### Lab 1: Vulnerability Identification
```
Analyze [component path] for security vulnerabilities.
Focus on:
- bypassSecurityTrust* usage
- innerHTML bindings
- localStorage token storage
- console.log with credentials
- Unvalidated redirects

For each issue: OWASP category, severity, line numbers, attack scenario.
```

### Lab 2: Threat Modeling
```
Create a STRIDE threat model for [component].
Include:
- Data flow diagram with trust boundaries
- STRIDE analysis table
- DREAD risk scores
- Attack tree for primary threat
- Mitigation recommendations
```

### Lab 3: Secure Implementation
```
Fix the vulnerability in [component] by:
- Implementing HTML sanitization with allowlist
- Using HttpOnly cookies instead of localStorage
- Adding URL validation with allowlist
- Configuring XSRF protection
- Implementing data masking

Show before/after code with security explanation.
```

---

## Commands

```bash
# Run development server
ng serve

# Run tests
npm test

# Run specific security tests
npm test -- --testPathPattern="html-sanitizer"
npm test -- --testPathPattern="url-validator"
npm test -- --testPathPattern="auth.service"

# Build
npm run build
```

---

## Response Guidelines

When providing security advice:

1. **Always cite OWASP/CWE references** for vulnerabilities
2. **Provide specific line numbers** when identifying issues
3. **Include attack scenarios** showing how vulnerabilities can be exploited
4. **Show secure code examples** that follow Angular best practices
5. **Explain why** the fix is secure, not just what to change

When working with vulnerable code:
- Treat files in `vulnerable/` as educational examples
- Never suggest using vulnerable patterns in production
- Always point to secure alternatives in `secure/`

When writing tests:
- Include attack payloads as test cases
- Verify that sanitization blocks malicious input
- Test edge cases (encoding, null bytes, etc.)
