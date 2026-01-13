# Lab 3: Secure Angular Implementation

**Duration:** 45-60 minutes
**Objective:** Fix vulnerabilities using AI assistance and secure coding patterns.

---

## Prerequisites

- Completed Labs 1 and 2
- GitHub Copilot or Claude Code installed
- Tests baseline: `npm test`

---

## How This Lab Works

1. **Review** vulnerable component in `/vulnerable/*`
2. **Study** secure counterpart in `/secure/*`
3. **Use AI** to understand the security patterns
4. **Run tests** to verify patterns: `npm test`

---

## Task 1: Secure HTML Handling (15 min)

### Goal
Implement safe HTML rendering without `bypassSecurityTrustHtml()`

### Files
- Vulnerable: `src/app/vulnerable/components/xss-bypass/`
- Secure: `src/app/secure/components/xss-bypass/`

### AI Prompt
```
Create a function that sanitizes HTML input using an allowlist:
- Allow only: b, i, u, strong, em, p, br, ul, ol, li, a, span
- Remove all event handlers (onclick, onerror, onload, etc.)
- Validate href attributes: only allow http:, https:, mailto:
- Remove script, iframe, object, embed tags completely

Return sanitized HTML string that Angular can safely bind.
```

### Test Payloads
```html
<script>alert('XSS')</script>
<img src=x onerror="alert('XSS')">
<a href="javascript:alert('XSS')">click</a>
<svg onload="alert('XSS')">
```

### Verify
```bash
npm test -- --testPathPattern="html-sanitizer"
```

---

## Task 2: Secure Authentication (15 min)

### Goal
Implement authentication without localStorage token storage

### Files
- Vulnerable: `src/app/vulnerable/services/auth.service.ts`
- Secure: `src/app/secure/services/auth.service.ts`

### AI Prompt
```
Refactor this Angular auth service to:
1. Never store tokens in localStorage or sessionStorage
2. Use HttpClient with withCredentials: true for cookie-based auth
3. Keep user state in memory only (Angular signals)
4. Never log passwords or tokens to console
5. Implement server-side logout (POST /api/auth/logout)
6. Validate session on app load (GET /api/auth/session)
```

### Key Security Patterns
```typescript
// SECURE: HttpOnly cookie-based auth
this.http.post('/api/auth/login', credentials, {
  withCredentials: true  // Include cookies
});

// SECURE: User state in memory only
private currentUserSignal = signal<User | null>(null);

// SECURE: No credential logging
// console.log() should never contain passwords
```

### Verify
```bash
npm test -- --testPathPattern="auth.service"
```

---

## Task 3: URL Validation (10 min)

### Goal
Prevent open redirect vulnerabilities

### Files
- Vulnerable: `src/app/vulnerable/components/redirect-handler/`
- Secure: `src/app/secure/components/redirect-handler/`

### AI Prompt
```
Create a validateRedirectUrl function that:
1. Only allows internal paths from an allowlist: /, /dashboard, /profile, /settings
2. Blocks javascript:, data:, vbscript: URLs
3. Blocks protocol-relative URLs (//)
4. Handles URL-encoded and double-encoded attacks
5. Returns safe default path (/) if validation fails
6. Decodes URLs before validation to catch encoded attacks
```

### Test Payloads
```
https://evil.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>
//evil.com
%2F%2Fevil.com
%252F%252Fevil.com
```

### Verify
```bash
npm test -- --testPathPattern="url-validator"
```

---

## Task 4: CSRF Protection (10 min)

### Goal
Configure Angular XSRF handling

### Files
- Secure: `src/app/secure/components/csrf-demo/`
- Config: `src/app/app.config.ts`

### AI Prompt
```
Show how to configure Angular's HttpClient for CSRF protection:
1. Use withXsrfConfiguration() in app.config.ts
2. Set cookie name: XSRF-TOKEN
3. Set header name: X-XSRF-TOKEN
4. Ensure all state-changing operations use POST/PUT/DELETE

Also show server-side cookie settings needed.
```

### Key Configuration
```typescript
// app.config.ts
export const appConfig: ApplicationConfig = {
  providers: [
    provideHttpClient(
      withXsrfConfiguration({
        cookieName: 'XSRF-TOKEN',
        headerName: 'X-XSRF-TOKEN'
      })
    )
  ]
};
```

### Verify
```bash
npm test -- --testPathPattern="csrf-protection"
```

---

## Task 5: Data Protection (10 min)

### Goal
Protect sensitive data from exposure

### Files
- Vulnerable: `src/app/vulnerable/components/data-exposure/`
- Secure: `src/app/secure/components/data-exposure/`

### AI Prompt
```
Create utility functions for sensitive data handling:

1. maskCreditCard(card: string): string
   - Return: ****-****-****-1234 (show last 4 only)

2. maskSSN(ssn: string): string
   - Return: ***-**-6789 (show last 4 only)

3. maskEmail(email: string): string
   - Return: j***e@example.com (first/last char of local part)

4. safeLog(data: object): void
   - Automatically redact fields: password, ssn, creditCard, token
   - Log only safe fields
```

### Key Patterns
```typescript
// SECURE: Mask sensitive data
function maskCreditCard(card: string): string {
  const digits = card.replace(/\D/g, '');
  return `****-****-****-${digits.slice(-4)}`;
}

// SECURE: Never log sensitive data
console.log('Payment:', { cardLast4: '1234', amount: 100 });
// NOT: console.log('Payment:', { card: '4111111111111111' });
```

### Verify
```bash
npm test -- --testPathPattern="data-protection"
```

---

## Final Verification

### Run All Tests
```bash
npm test
```

### Expected Results
All security tests should pass:
- `html-sanitizer.spec.ts`
- `url-validator.spec.ts`
- `csrf-protection.spec.ts`
- `data-protection.spec.ts`
- `auth.service.spec.ts`

---

## AI Prompting Tips

### Be Specific About Security
```
❌ "Make this secure"
✅ "Validate URLs to prevent open redirect. Block javascript: and data: protocols. Only allow paths from allowlist: [/dashboard, /profile]"
```

### Include Attack Context
```
❌ "Sanitize HTML"
✅ "Sanitize user HTML for comments. Allow b/i/a tags. Remove all event handlers and javascript: URLs to prevent XSS."
```

### Request Verification
```
✅ "...and explain what XSS attacks this prevents"
✅ "...and show test cases for common attack payloads"
```

---

## Security Review Checklist

After implementing fixes, verify:

- [ ] No sensitive data in console.log
- [ ] No tokens in localStorage/sessionStorage
- [ ] URL parameters validated before use
- [ ] HTML sanitized with allowlist
- [ ] XSRF configured for state-changing requests
- [ ] HttpOnly cookies for session tokens
- [ ] No secrets in environment.ts
- [ ] Tests cover attack scenarios

---

## Bonus Challenges

### 1. Content Security Policy
```
Configure CSP headers to prevent inline scripts:
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
```

### 2. Subresource Integrity
```
Add integrity attributes to external scripts/styles
```

### 3. Security Headers
```
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

---

## Conclusion

This lab demonstrated secure Angular patterns:

1. **HTML Sanitization**: Allowlist approach, no bypassSecurityTrust
2. **Token Storage**: HttpOnly cookies, not localStorage
3. **URL Validation**: Allowlist paths, block dangerous protocols
4. **CSRF Protection**: Angular XSRF module, SameSite cookies
5. **Data Protection**: Mask sensitive data, safe logging

AI assistance is powerful but requires human verification of security patterns.
